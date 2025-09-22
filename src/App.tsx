import React, { useState } from 'react';
import { Shield, Database, Brain, Users, Server, Lock, Activity, GitBranch } from 'lucide-react';

function App() {
  const [selectedChallenge, setSelectedChallenge] = useState(1);

  const challenges = [
    { id: 1, title: "Secure Multi-Agent Architecture", icon: Shield },
    { id: 4, title: "FastAPI Implementation", icon: Server, color: "indigo" }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      {/* Header */}
      <div className="bg-white shadow-lg border-b">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center space-x-3">
            <div className="bg-blue-600 p-2 rounded-lg">
              <Activity className="w-6 h-6 text-white" />
            </div>
            <h1 className="text-2xl font-bold text-gray-900">HIPAA-Compliant Healthcare AI System</h1>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Challenge Navigation */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
          {challenges.map((challenge) => {
            const Icon = challenge.icon;
            return (
              <button
                key={challenge.id}
                onClick={() => setSelectedChallenge(challenge.id)}
                className={`p-4 rounded-xl border-2 transition-all duration-200 ${
                  selectedChallenge === challenge.id
                    ? 'border-blue-500 bg-blue-50 shadow-lg'
                    : 'border-gray-200 bg-white hover:border-blue-300 hover:shadow-md'
                }`}
              >
                <div className="flex flex-col items-center space-y-2">
                  <Icon className={`w-6 h-6 ${
                    selectedChallenge === challenge.id ? 'text-blue-600' : 'text-gray-600'
                  }`} />
                  <span className={`text-sm font-medium text-center ${
                    selectedChallenge === challenge.id ? 'text-blue-900' : 'text-gray-700'
                  }`}>
                    {challenge.title}
                  </span>
                </div>
              </button>
            );
          })}
        </div>

        {/* Challenge Content */}
        <div className="bg-white rounded-xl shadow-lg p-8">
          {selectedChallenge === 1 && <Challenge1 />}
          {selectedChallenge === 4 && <Challenge4 />}
        </div>
      </div>
    </div>
  );
}

function Challenge1() {
  return (
    <div className="space-y-6">
      <div className="flex items-center space-x-3 mb-6">
        <Shield className="w-8 h-8 text-blue-600" />
        <h2 className="text-3xl font-bold text-gray-900">Secure Multi-Agent Architecture</h2>
      </div>

      {/* Architecture Overview */}
      <div className="bg-gray-50 p-6 rounded-lg">
        <h3 className="text-xl font-semibold mb-4 flex items-center">
          <Database className="w-5 h-5 mr-2 text-blue-600" />
          HIPAA-Compliant System Architecture
        </h3>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div className="bg-white p-4 rounded-lg border-l-4 border-blue-500">
              <h4 className="font-semibold text-gray-900">API Gateway Layer</h4>
              <p className="text-sm text-gray-600 mt-2">
                • Rate limiting and DDoS protection<br/>
                • JWT validation and refresh token management<br/>
                • Request/response encryption validation<br/>
                • Audit log initialization
              </p>
            </div>
            <div className="bg-white p-4 rounded-lg border-l-4 border-green-500">
              <h4 className="font-semibold text-gray-900">Authentication Service</h4>
              <p className="text-sm text-gray-600 mt-2">
                • OAuth 2.0 + PKCE implementation<br/>
                • Multi-factor authentication<br/>
                • Session management with Redis<br/>
                • Role-based access control (RBAC)
              </p>
            </div>
          </div>
          <div className="space-y-4">
            <div className="bg-white p-4 rounded-lg border-l-4 border-purple-500">
              <h4 className="font-semibold text-gray-900">Data Processing Layer</h4>
              <p className="text-sm text-gray-600 mt-2">
                • AES-256-GCM encryption for PHI data<br/>
                • PII tokenization using Vault<br/>
                • Vector embeddings with encrypted metadata<br/>
                • Secure data pipeline orchestration
              </p>
            </div>
            <div className="bg-white p-4 rounded-lg border-l-4 border-red-500">
              <h4 className="font-semibold text-gray-900">Audit & Compliance</h4>
              <p className="text-sm text-gray-600 mt-2">
                • Immutable audit trail with blockchain<br/>
                • Real-time anomaly detection<br/>
                • Compliance reporting dashboard<br/>
                • Automated BAA management
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Security Implementation */}
      <div className="bg-blue-50 p-6 rounded-lg">
        <h3 className="text-xl font-semibold mb-4 flex items-center">
          <Lock className="w-5 h-5 mr-2 text-blue-600" />
          Security Implementation Details
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-white p-4 rounded-lg">
            <h4 className="font-semibold text-blue-900 mb-2">End-to-End Encryption</h4>
            <ul className="text-sm text-gray-700 space-y-1">
              <li>• TLS 1.3 for transport security</li>
              <li>• AES-256-GCM for data at rest</li>
              <li>• Key rotation every 90 days</li>
              <li>• HSM for key management</li>
            </ul>
          </div>
          <div className="bg-white p-4 rounded-lg">
            <h4 className="font-semibold text-blue-900 mb-2">JWT Security</h4>
            <ul className="text-sm text-gray-700 space-y-1">
              <li>• RS256 algorithm with key rotation</li>
              <li>• 15-minute access token expiry</li>
              <li>• Secure refresh token storage</li>
              <li>• Token blacklisting capability</li>
            </ul>
          </div>
          <div className="bg-white p-4 rounded-lg">
            <h4 className="font-semibold text-blue-900 mb-2">Vector Storage</h4>
            <ul className="text-sm text-gray-700 space-y-1">
              <li>• Encrypted embeddings at rest</li>
              <li>• Metadata tokenization</li>
              <li>• Access pattern obfuscation</li>
              <li>• Differential privacy protection</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}

          <p className="text-gray-600 mt-2">Production-ready healthcare AI microservice</p>
        </div>
      </div>

      {/* Implementation Overview */}
      <div className="bg-gradient-to-r from-indigo-50 to-blue-50 p-8 rounded-2xl border border-indigo-200">
        <h3 className="text-2xl font-bold mb-6 text-indigo-900">Complete FastAPI Microservice</h3>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <div className="bg-white p-6 rounded-xl shadow-md">
            <h4 className="font-bold text-gray-900 mb-4 flex items-center">
              <Code className="w-5 h-5 mr-2 text-indigo-600" />
              Core Features Implemented
            </h4>
            <ul className="text-sm text-gray-700 space-y-2">
              <li>• <strong>Encrypted Health Data:</strong> AES-256-GCM encryption for PHI</li>
              <li>• <strong>JWT Authentication:</strong> RS256 with role-based access control</li>
              <li>• <strong>Vector Search:</strong> ChromaDB integration for semantic similarity</li>
              <li>• <strong>AI Integration:</strong> GPT-4 powered coaching generation</li>
              <li>• <strong>Audit Logging:</strong> Comprehensive compliance tracking</li>
              <li>• <strong>Rate Limiting:</strong> Protection against abuse</li>
              <li>• <strong>Security Headers:</strong> OWASP recommended protections</li>
              <li>• <strong>Health Checks:</strong> Monitoring and observability</li>
            </ul>
          </div>
          <div className="bg-white p-6 rounded-xl shadow-md">
            <h4 className="font-bold text-gray-900 mb-4 flex items-center">
              <CheckCircle className="w-5 h-5 mr-2 text-green-600" />
              Production Ready Features
            </h4>
            <ul className="text-sm text-gray-700 space-y-2">
              <li>• <strong>Docker Containerization:</strong> Multi-stage builds</li>
              <li>• <strong>Kubernetes Deployment:</strong> Scalable orchestration</li>
              <li>• <strong>Comprehensive Testing:</strong> Unit and integration tests</li>
              <li>• <strong>Security Scanning:</strong> Vulnerability assessments</li>
              <li>• <strong>Monitoring:</strong> Prometheus metrics integration</li>
              <li>• <strong>Error Handling:</strong> Graceful failure management</li>
              <li>• <strong>Documentation:</strong> OpenAPI/Swagger specs</li>
              <li>• <strong>HIPAA Compliance:</strong> Healthcare data protection</li>
            </ul>
          </div>
        </div>
      </div>

      {/* API Endpoints */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div className="bg-white p-6 rounded-xl shadow-md border">
          <h4 className="text-xl font-bold text-gray-900 mb-4">API Endpoints</h4>
          <div className="space-y-3">
            <div className="bg-green-50 p-3 rounded-lg border-l-4 border-green-500">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm font-semibold">POST /api/v1/auth/token</span>
                <span className="bg-green-100 text-green-800 px-2 py-1 rounded text-xs">AUTH</span>
              </div>
              <p className="text-xs text-gray-600 mt-1">Authenticate and receive JWT token</p>
            </div>
            <div className="bg-blue-50 p-3 rounded-lg border-l-4 border-blue-500">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm font-semibold">POST /api/v1/health-data/ingest</span>
                <span className="bg-blue-100 text-blue-800 px-2 py-1 rounded text-xs">SECURE</span>
              </div>
              <p className="text-xs text-gray-600 mt-1">Ingest encrypted health data to vector store</p>
            </div>
            <div className="bg-purple-50 p-3 rounded-lg border-l-4 border-purple-500">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm font-semibold">POST /api/v1/coaching/generate</span>
                <span className="bg-purple-100 text-purple-800 px-2 py-1 rounded text-xs">AI</span>
              </div>
              <p className="text-xs text-gray-600 mt-1">Generate personalized coaching with GPT-4</p>
            </div>
            <div className="bg-yellow-50 p-3 rounded-lg border-l-4 border-yellow-500">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm font-semibold">GET /api/v1/audit/logs</span>
                <span className="bg-yellow-100 text-yellow-800 px-2 py-1 rounded text-xs">AUDIT</span>
              </div>
              <p className="text-xs text-gray-600 mt-1">Retrieve compliance audit logs</p>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-xl shadow-md border">
          <h4 className="text-xl font-bold text-gray-900 mb-4">Security Implementation</h4>
          <div className="space-y-4">
            <div>
              <h5 className="font-semibold text-gray-800 mb-2">Encryption & Authentication</h5>
              <ul className="text-sm text-gray-700 space-y-1">
                <li>• AES-256-GCM for PHI data encryption</li>
                <li>• RS256 JWT with 15-minute expiry</li>
                <li>• Token blacklisting for secure logout</li>
                <li>• Role-based access control (RBAC)</li>
              </ul>
            </div>
            <div>
              <h5 className="font-semibold text-gray-800 mb-2">API Security</h5>
              <ul className="text-sm text-gray-700 space-y-1">
                <li>• Rate limiting (10-20 requests/minute)</li>
                <li>• CORS with strict origin validation</li>
                <li>• Security headers (CSP, HSTS, etc.)</li>
                <li>• Request/response validation</li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* Code Implementation Preview */}
      <div className="bg-gray-50 p-6 rounded-xl">
        <h4 className="text-xl font-bold text-gray-900 mb-4">Implementation Highlights</h4>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-white p-4 rounded-lg">
            <h5 className="font-semibold text-gray-800 mb-2">Encrypted Data Handling</h5>
            <div className="bg-gray-900 text-green-400 p-3 rounded font-mono text-xs overflow-x-auto">
              <pre>{`@app.post("/api/v1/health-data/ingest")
@limiter.limit("10/minute")
async def ingest_health_data(
    data: EncryptedHealthData,
    current_user: Dict = Depends(require_role(["healthcare_provider"]))
):
    # Decrypt PHI data
    decrypted_data = decrypt_data(data.encrypted_data)
    health_info = json.loads(decrypted_data)
    
    # Generate embeddings
    text_content = f"{health_info.get('symptoms', '')} {health_info.get('concerns', '')}"
    embeddings = sentence_model.encode([text_content])[0].tolist()
    
    # Store with encrypted metadata
    encrypted_metadata = encrypt_data(json.dumps({
        "patient_id": data.patient_id,
        "data_type": data.data_type,
        "provider_id": current_user["user_id"]
    }))
    
    health_collection.add(
        embeddings=[embeddings],
        documents=[text_content],
        metadatas=[{"encrypted_metadata": encrypted_metadata}],
        ids=[f"{data.patient_id}_{int(time.time())}"]
    )`}</pre>
            </div>
          </div>
          <div className="bg-white p-4 rounded-lg">
            <h5 className="font-semibold text-gray-800 mb-2">AI Coaching Generation</h5>
            <div className="bg-gray-900 text-green-400 p-3 rounded font-mono text-xs overflow-x-auto">
              <pre>{`@app.post("/api/v1/coaching/generate")
@limiter.limit("20/minute")
async def generate_coaching(
    coaching_request: CoachingRequest,
    current_user: Dict = Depends(require_role(["ai_user"]))
):
    # Semantic search for context
    query_embedding = sentence_model.encode([coaching_request.query])[0].tolist()
    search_results = health_collection.query(
        query_embeddings=[query_embedding],
        n_results=5
    )
    
    # Generate coaching with GPT-4
    response = await client.post(
        "https://api.openai.com/v1/chat/completions",
        json={
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        }
    )
    
    # Structure response with confidence scoring
    return CoachingResponse(
        recommendations=parsed_recommendations,
        confidence_score=calculated_confidence,
        coaching_type="personalized_wellness",
        audit_id=audit_id
    )`}</pre>
            </div>
          </div>
        </div>
      </div>

      {/* Deployment & Testing */}
      <div className="bg-indigo-50 p-6 rounded-xl border border-indigo-200">
        <h4 className="text-xl font-bold text-indigo-900 mb-4">Deployment & Testing Strategy</h4>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-white p-4 rounded-lg">
            <h5 className="font-semibold text-gray-800 mb-2 flex items-center">
              <Server className="w-4 h-4 mr-2 text-blue-600" />
              Docker Deployment
            </h5>
            <ul className="text-sm text-gray-700 space-y-1">
              <li>• Multi-stage Docker builds</li>
              <li>• Non-root user security</li>
              <li>• Health check endpoints</li>
              <li>• Docker Compose orchestration</li>
            </ul>
          </div>
          <div className="bg-white p-4 rounded-lg">
            <h5 className="font-semibold text-gray-800 mb-2 flex items-center">
              <Activity className="w-4 h-4 mr-2 text-green-600" />
              Kubernetes Ready
            </h5>
            <ul className="text-sm text-gray-700 space-y-1">
              <li>• Horizontal pod autoscaling</li>
              <li>• Rolling update deployments</li>
              <li>• ConfigMaps and Secrets</li>
              <li>• Ingress with TLS termination</li>
            </ul>
          </div>
          <div className="bg-white p-4 rounded-lg">
            <h5 className="font-semibold text-gray-800 mb-2 flex items-center">
              <CheckCircle className="w-4 h-4 mr-2 text-purple-600" />
              Testing Suite
            </h5>
            <ul className="text-sm text-gray-700 space-y-1">
              <li>• Unit tests with pytest</li>
              <li>• Integration test coverage</li>
              <li>• Security vulnerability scans</li>
              <li>• Performance benchmarking</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Live Implementation */}
      <div className="bg-gradient-to-r from-green-50 to-emerald-50 p-6 rounded-xl border border-green-200">
        <div className="flex items-start space-x-4">
          <div className="bg-green-100 p-3 rounded-xl">
            <Zap className="w-6 h-6 text-green-600" />
          </div>
          <div className="flex-1">
            <h4 className="text-xl font-bold text-green-900 mb-2">Complete Implementation Available</h4>
            <p className="text-green-800 mb-4">
              The full FastAPI microservice is implemented with all security features, database integration, 
              AI coaching capabilities, and production deployment configurations. The codebase includes:
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <ul className="text-sm text-green-700 space-y-1">
                <li>• Complete FastAPI application (healthcare_microservice/main.py)</li>
                <li>• Docker containerization with security best practices</li>
                <li>• Kubernetes deployment manifests</li>
                <li>• Comprehensive test suite</li>
              </ul>
              <ul className="text-sm text-green-700 space-y-1">
                <li>• Production requirements.txt</li>
                <li>• Security configurations</li>
                <li>• Monitoring and health checks</li>
                <li>• HIPAA compliance features</li>
              </ul>
            </div>
          </div>