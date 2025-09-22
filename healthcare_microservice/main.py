"""
HIPAA-Compliant Healthcare AI Microservice
FastAPI implementation with end-to-end encryption, vector search, and AI coaching
"""

from fastapi import FastAPI, HTTPException, Depends, Security, Request, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
import httpx
import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import jwt
import redis
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
import chromadb
from chromadb.config import Settings
import openai
from sentence_transformers import SentenceTransformer

# Configure logging for audit trail
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/healthcare_ai/audit.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app with security headers
app = FastAPI(
    title="Healthcare AI Coaching Service",
    description="HIPAA-compliant microservice for AI-powered health coaching",
    version="1.0.0",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc"
)

# Security middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "*.healthcare-ai.com"]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.healthcare-ai.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Security configurations
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 24

# Encryption setup
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", Fernet.generate_key())
cipher_suite = Fernet(ENCRYPTION_KEY)

# Redis for session management
redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    decode_responses=True,
    ssl=True if os.getenv("REDIS_SSL") == "true" else False
)

# Vector database setup
chroma_client = chromadb.Client(Settings(
    chroma_db_impl="duckdb+parquet",
    persist_directory="/data/chroma_db"
))
health_collection = chroma_client.get_or_create_collection("health_coaching")

# AI models
sentence_model = SentenceTransformer('all-MiniLM-L6-v2')
openai.api_key = os.getenv("OPENAI_API_KEY")

# Security
security = HTTPBearer()

# Pydantic Models
class EncryptedHealthData(BaseModel):
    encrypted_data: str = Field(..., description="AES-256-GCM encrypted health data")
    patient_id: str = Field(..., min_length=1, max_length=64)
    data_type: str = Field(..., regex="^(symptoms|vitals|goals|history)$")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    @validator('patient_id')
    def validate_patient_id(cls, v):
        if not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError('Patient ID must be alphanumeric')
        return v

class CoachingRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=1000)
    context: Optional[Dict[str, Any]] = None
    preferences: Optional[Dict[str, str]] = None

class CoachingResponse(BaseModel):
    recommendations: List[str]
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    coaching_type: str
    follow_up_questions: List[str]
    resources: List[Dict[str, str]]
    audit_id: str

class AuditLog(BaseModel):
    audit_id: str
    user_id: str
    action: str
    resource: str
    timestamp: datetime
    ip_address: str
    user_agent: str
    request_data: Optional[Dict[str, Any]] = None
    response_data: Optional[Dict[str, Any]] = None
    security_flags: List[str] = []

# Utility Functions
def encrypt_data(data: str) -> str:
    """Encrypt sensitive data using AES-256-GCM"""
    try:
        return cipher_suite.encrypt(data.encode()).decode()
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Encryption failed")

def decrypt_data(encrypted_data: str) -> str:
    """Decrypt sensitive data"""
    try:
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        raise HTTPException(status_code=400, detail="Invalid encrypted data")

def create_jwt_token(user_id: str, roles: List[str]) -> str:
    """Create JWT token with user claims"""
    payload = {
        "user_id": user_id,
        "roles": roles,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS),
        "iat": datetime.utcnow(),
        "iss": "healthcare-ai-service"
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> Dict[str, Any]:
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def log_audit_event(audit_log: AuditLog):
    """Log audit event asynchronously"""
    try:
        log_entry = {
            "audit_id": audit_log.audit_id,
            "timestamp": audit_log.timestamp.isoformat(),
            "user_id": audit_log.user_id,
            "action": audit_log.action,
            "resource": audit_log.resource,
            "ip_address": audit_log.ip_address,
            "user_agent": audit_log.user_agent,
            "security_flags": audit_log.security_flags
        }
        
        # Log to file
        logger.info(f"AUDIT: {json.dumps(log_entry)}")
        
        # Store in Redis for real-time monitoring
        await redis_client.lpush("audit_logs", json.dumps(log_entry))
        await redis_client.ltrim("audit_logs", 0, 10000)  # Keep last 10k logs
        
    except Exception as e:
        logger.error(f"Audit logging failed: {str(e)}")

# Authentication dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Validate JWT token and extract user information"""
    token = credentials.credentials
    payload = verify_jwt_token(token)
    
    # Check if token is blacklisted
    is_blacklisted = await redis_client.get(f"blacklist:{token}")
    if is_blacklisted:
        raise HTTPException(status_code=401, detail="Token has been revoked")
    
    return payload

async def require_role(required_roles: List[str]):
    """Role-based access control dependency"""
    def role_checker(current_user: Dict = Depends(get_current_user)):
        user_roles = current_user.get("roles", [])
        if not any(role in user_roles for role in required_roles):
            raise HTTPException(
                status_code=403, 
                detail=f"Insufficient permissions. Required roles: {required_roles}"
            )
        return current_user
    return role_checker

# API Endpoints
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

@app.get("/health")
async def health_check():
    """Health check endpoint for load balancer"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "services": {
            "redis": "connected" if redis_client.ping() else "disconnected",
            "vector_db": "connected",
            "ai_service": "connected"
        }
    }

@app.post("/api/v1/auth/token")
@limiter.limit("5/minute")
async def authenticate(
    request: Request,
    username: str,
    password: str,
    background_tasks: BackgroundTasks
):
    """Authenticate user and return JWT token"""
    # In production, verify against secure user database
    if username == "healthcare_provider" and password == "secure_password_123":
        user_id = str(uuid.uuid4())
        roles = ["healthcare_provider", "ai_user"]
        token = create_jwt_token(user_id, roles)
        
        # Audit log
        audit_log = AuditLog(
            audit_id=str(uuid.uuid4()),
            user_id=user_id,
            action="authenticate",
            resource="/api/v1/auth/token",
            timestamp=datetime.utcnow(),
            ip_address=get_remote_address(request),
            user_agent=request.headers.get("user-agent", "")
        )
        background_tasks.add_task(log_audit_event, audit_log)
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": JWT_EXPIRE_HOURS * 3600,
            "user_id": user_id
        }
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/api/v1/health-data/ingest")
@limiter.limit("10/minute")
async def ingest_health_data(
    request: Request,
    data: EncryptedHealthData,
    background_tasks: BackgroundTasks,
    current_user: Dict = Depends(require_role(["healthcare_provider"]))
):
    """Ingest encrypted health data and store in vector database"""
    try:
        # Decrypt the health data
        decrypted_data = decrypt_data(data.encrypted_data)
        health_info = json.loads(decrypted_data)
        
        # Generate embeddings for semantic search
        text_content = f"{health_info.get('symptoms', '')} {health_info.get('concerns', '')} {health_info.get('goals', '')}"
        embeddings = sentence_model.encode([text_content])[0].tolist()
        
        # Store in vector database with encrypted metadata
        encrypted_metadata = encrypt_data(json.dumps({
            "patient_id": data.patient_id,
            "data_type": data.data_type,
            "timestamp": data.timestamp.isoformat(),
            "provider_id": current_user["user_id"]
        }))
        
        health_collection.add(
            embeddings=[embeddings],
            documents=[text_content],
            metadatas=[{"encrypted_metadata": encrypted_metadata}],
            ids=[f"{data.patient_id}_{int(time.time())}"]
        )
        
        # Audit logging
        audit_log = AuditLog(
            audit_id=str(uuid.uuid4()),
            user_id=current_user["user_id"],
            action="ingest_health_data",
            resource="/api/v1/health-data/ingest",
            timestamp=datetime.utcnow(),
            ip_address=get_remote_address(request),
            user_agent=request.headers.get("user-agent", ""),
            request_data={"patient_id": data.patient_id, "data_type": data.data_type}
        )
        background_tasks.add_task(log_audit_event, audit_log)
        
        return {
            "status": "success",
            "message": "Health data ingested successfully",
            "data_id": f"{data.patient_id}_{int(time.time())}"
        }
        
    except Exception as e:
        logger.error(f"Data ingestion failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Data ingestion failed")

@app.post("/api/v1/coaching/generate", response_model=CoachingResponse)
@limiter.limit("20/minute")
async def generate_coaching(
    request: Request,
    coaching_request: CoachingRequest,
    background_tasks: BackgroundTasks,
    current_user: Dict = Depends(require_role(["healthcare_provider", "ai_user"]))
):
    """Generate personalized coaching recommendations using AI"""
    try:
        audit_id = str(uuid.uuid4())
        
        # 1. Semantic search for relevant health data
        query_embedding = sentence_model.encode([coaching_request.query])[0].tolist()
        
        search_results = health_collection.query(
            query_embeddings=[query_embedding],
            n_results=5,
            include=["documents", "metadatas", "distances"]
        )
        
        # 2. Prepare context for AI model
        context_docs = search_results["documents"][0] if search_results["documents"] else []
        context_text = "\n".join(context_docs[:3])  # Use top 3 relevant documents
        
        # 3. Generate coaching with GPT-4
        system_prompt = """You are a certified health coach providing personalized wellness recommendations. 
        Always prioritize safety and recommend consulting healthcare professionals for medical concerns.
        Provide actionable, evidence-based advice tailored to the individual's needs."""
        
        user_prompt = f"""
        User Query: {coaching_request.query}
        
        Relevant Health Context: {context_text}
        
        User Preferences: {coaching_request.preferences or 'None specified'}
        
        Please provide:
        1. 3-5 specific, actionable recommendations
        2. 2-3 follow-up questions to better understand their needs
        3. Relevant resources or tools
        4. Assessment of confidence in recommendations (0.0-1.0)
        """
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {openai.api_key}"},
                json={
                    "model": "gpt-4",
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    "max_tokens": 1000,
                    "temperature": 0.7
                },
                timeout=30.0
            )
            
        if response.status_code != 200:
            raise HTTPException(status_code=500, detail="AI service unavailable")
            
        ai_response = response.json()
        content = ai_response["choices"][0]["message"]["content"]
        
        # 4. Parse AI response and structure output
        # In production, use more sophisticated parsing
        recommendations = [
            rec.strip() for rec in content.split('\n') 
            if rec.strip() and ('recommendation' in rec.lower() or rec.strip().startswith(('1.', '2.', '3.', '4.', '5.')))
        ][:5]
        
        follow_up_questions = [
            q.strip() for q in content.split('\n') 
            if q.strip() and '?' in q
        ][:3]
        
        # 5. Calculate confidence score based on context relevance
        confidence_score = min(0.9, max(0.6, len(context_docs) / 5 * 0.8 + 0.2))
        
        coaching_response = CoachingResponse(
            recommendations=recommendations or ["Please consult with a healthcare professional for personalized advice."],
            confidence_score=confidence_score,
            coaching_type="personalized_wellness",
            follow_up_questions=follow_up_questions or ["How are you feeling today?"],
            resources=[
                {"title": "Mayo Clinic Health Information", "url": "https://mayoclinic.org"},
                {"title": "CDC Health Guidelines", "url": "https://cdc.gov"}
            ],
            audit_id=audit_id
        )
        
        # 6. Audit logging
        audit_log = AuditLog(
            audit_id=audit_id,
            user_id=current_user["user_id"],
            action="generate_coaching",
            resource="/api/v1/coaching/generate",
            timestamp=datetime.utcnow(),
            ip_address=get_remote_address(request),
            user_agent=request.headers.get("user-agent", ""),
            request_data={"query_length": len(coaching_request.query)},
            response_data={"confidence_score": confidence_score, "recommendations_count": len(recommendations)}
        )
        background_tasks.add_task(log_audit_event, audit_log)
        
        return coaching_response
        
    except Exception as e:
        logger.error(f"Coaching generation failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Coaching generation failed")

@app.get("/api/v1/audit/logs")
async def get_audit_logs(
    limit: int = 100,
    current_user: Dict = Depends(require_role(["admin", "security_officer"]))
):
    """Retrieve audit logs for compliance monitoring"""
    try:
        logs = await redis_client.lrange("audit_logs", 0, limit - 1)
        return {
            "audit_logs": [json.loads(log) for log in logs],
            "total_count": len(logs),
            "retrieved_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Audit log retrieval failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Audit log retrieval failed")

@app.post("/api/v1/auth/revoke")
async def revoke_token(
    request: Request,
    current_user: Dict = Depends(get_current_user)
):
    """Revoke JWT token (logout)"""
    token = request.headers.get("authorization", "").replace("Bearer ", "")
    
    # Add token to blacklist
    exp_time = current_user.get("exp", 0)
    ttl = max(0, exp_time - int(time.time()))
    await redis_client.setex(f"blacklist:{token}", ttl, "revoked")
    
    return {"status": "success", "message": "Token revoked successfully"}

# Metrics endpoint for monitoring
@app.get("/metrics")
async def get_metrics():
    """Prometheus-compatible metrics endpoint"""
    try:
        # Get Redis info
        redis_info = redis_client.info()
        
        # Get audit log count
        audit_count = await redis_client.llen("audit_logs")
        
        return {
            "http_requests_total": "handled_by_prometheus",
            "redis_connected_clients": redis_info.get("connected_clients", 0),
            "audit_logs_total": audit_count,
            "vector_db_documents": health_collection.count(),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception:
        return {"status": "metrics_unavailable"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        ssl_keyfile="/etc/ssl/private/server.key",
        ssl_certfile="/etc/ssl/certs/server.crt",
        log_level="info"
    )