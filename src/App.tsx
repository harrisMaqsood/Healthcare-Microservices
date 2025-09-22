import React, { useState } from 'react';
import { Shield, Database, Brain, Users, Server, Lock, Activity, GitBranch } from 'lucide-react';

function App() {
  const [selectedChallenge, setSelectedChallenge] = useState(1);

  const challenges = [
    { id: 1, title: "Secure Multi-Agent Architecture", icon: Shield },
    { id: 2, title: "Advanced LangChain Workflow", icon: Brain },
    { id: 3, title: "Startup Scaling Strategy", icon: Users },
    { id: 4, title: "FastAPI Implementation", icon: Server }
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
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
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
          {selectedChallenge === 2 && <Challenge2 />}
          {selectedChallenge === 3 && <Challenge3 />}
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

function Challenge2() {
  return (
    <div className="space-y-6">
      <div className="flex items-center space-x-3 mb-6">
        <Brain className="w-8 h-8 text-purple-600" />
        <h2 className="text-3xl font-bold text-gray-900">Advanced LangChain/LangGraph Workflow</h2>
      </div>

      {/* Agent Workflow */}
      <div className="bg-purple-50 p-6 rounded-lg">
        <h3 className="text-xl font-semibold mb-4">Multi-Agent Health Coaching System</h3>
        <div className="space-y-4">
          <div className="bg-white p-4 rounded-lg border-l-4 border-purple-500">
            <h4 className="font-semibold text-gray-900 mb-2">Agent Orchestration Flow</h4>
            <div className="font-mono text-sm bg-gray-100 p-4 rounded">
              <pre>{`class HealthCoachingOrchestrator:
    def __init__(self):
        self.agents = {
            'router': RouterAgent(),
            'nutrition': NutritionAgent(), 
            'fitness': FitnessAgent(),
            'mental_health': MentalHealthAgent(),
            'supervisor': SupervisorAgent()
        }
        self.memory = ConversationBufferWindowMemory(k=10)
        self.vector_store = PineconeVectorStore()

    async def process_query(self, query: str, user_context: dict):
        # 1. Intent Classification & Routing
        routing_decision = await self.agents['router'].classify_intent(
            query, user_context, confidence_threshold=0.85
        )
        
        # 2. Retrieve Relevant Context
        similar_docs = await self.vector_store.similarity_search(
            query, user_context['user_id'], k=5
        )
        
        # 3. Agent Processing
        if routing_decision.confidence > 0.85:
            specialist_response = await self.agents[
                routing_decision.agent_type
            ].process_query(query, similar_docs, self.memory)
        else:
            # Multi-agent collaboration for ambiguous queries
            specialist_response = await self.coordinate_agents(
                query, similar_docs, routing_decision.candidates
            )
        
        # 4. Confidence Evaluation & Human Handoff
        final_response = await self.agents['supervisor'].evaluate_response(
            specialist_response, confidence_threshold=0.80
        )
        
        if final_response.requires_human_handoff:
            return await self.escalate_to_human(query, final_response)
            
        # 5. Update Conversation Memory
        await self.memory.save_context(
            {"input": query}, {"output": final_response.content}
        )
        
        return final_response`}</pre>
            </div>
          </div>
        </div>
      </div>

      {/* State Management */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white p-6 rounded-lg border">
          <h4 className="font-semibold text-gray-900 mb-3">Conversation State Management</h4>
          <div className="font-mono text-sm bg-gray-100 p-4 rounded">
            <pre>{`class ConversationState:
    def __init__(self):
        self.user_profile = UserProfile()
        self.session_context = {}
        self.agent_history = []
        self.confidence_scores = []
        
    async def update_state(self, interaction):
        # Update user profile
        await self.user_profile.update_preferences(
            interaction.preferences
        )
        
        # Track agent performance
        self.confidence_scores.append({
            'agent': interaction.agent_type,
            'confidence': interaction.confidence,
            'feedback': interaction.user_feedback
        })
        
        # Maintain session context
        self.session_context.update({
            'last_topic': interaction.topic,
            'user_mood': interaction.sentiment,
            'goals_mentioned': interaction.goals
        })`}</pre>
          </div>
        </div>
        <div className="bg-white p-6 rounded-lg border">
          <h4 className="font-semibold text-gray-900 mb-3">Vector Search Integration</h4>
          <div className="font-mono text-sm bg-gray-100 p-4 rounded">
            <pre>{`class PersonalizedRetrieval:
    async def similarity_search(self, query, user_id):
        # Generate query embedding
        query_embedding = await self.embed_query(query)
        
        # User-specific filtering
        filter_conditions = {
            'user_id': user_id,
            'preferences': user.health_conditions,
            'goals': user.fitness_goals
        }
        
        # Hybrid search (semantic + keyword)
        results = await self.vector_db.search(
            vector=query_embedding,
            filter=filter_conditions,
            hybrid_search=True,
            alpha=0.7  # Semantic vs keyword weight
        )
        
        # Re-rank based on user engagement
        reranked_results = await self.rerank_by_engagement(
            results, user_id
        )
        
        return reranked_results`}</pre>
          </div>
        </div>
      </div>
    </div>
  );
}

function Challenge3() {
  return (
    <div className="space-y-6">
      <div className="flex items-center space-x-3 mb-6">
        <Users className="w-8 h-8 text-green-600" />
        <h2 className="text-3xl font-bold text-gray-900">Startup Scaling Strategy</h2>
      </div>

      {/* Team Organization */}
      <div className="bg-green-50 p-6 rounded-lg">
        <h3 className="text-xl font-semibold mb-4">20-Week Production Launch Plan</h3>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div className="bg-white p-4 rounded-lg">
              <h4 className="font-semibold text-green-900 mb-2">Sprint Structure (2-week sprints)</h4>
              <div className="text-sm text-gray-700 space-y-2">
                <div className="flex justify-between"><span>Sprints 1-2:</span> <span>Architecture & Security Foundation</span></div>
                <div className="flex justify-between"><span>Sprints 3-4:</span> <span>Core AI Services Development</span></div>
                <div className="flex justify-between"><span>Sprints 5-6:</span> <span>Frontend & API Integration</span></div>
                <div className="flex justify-between"><span>Sprints 7-8:</span> <span>HIPAA Compliance & Security Audit</span></div>
                <div className="flex justify-between"><span>Sprints 9-10:</span> <span>Production Deployment & Monitoring</span></div>
              </div>
            </div>
            <div className="bg-white p-4 rounded-lg">
              <h4 className="font-semibold text-green-900 mb-2">Risk Mitigation</h4>
              <ul className="text-sm text-gray-700 space-y-1">
                <li>• Multi-provider AI strategy (OpenAI + Azure OpenAI)</li>
                <li>• Circuit breaker patterns for API failures</li>
                <li>• Comprehensive integration testing</li>
                <li>• Fallback to rule-based systems</li>
              </ul>
            </div>
          </div>
          <div className="space-y-4">
            <div className="bg-white p-4 rounded-lg">
              <h4 className="font-semibold text-green-900 mb-2">Quality Gates</h4>
              <ul className="text-sm text-gray-700 space-y-1">
                <li>• 80% code coverage requirement</li>
                <li>• Security scan on every PR</li>
                <li>• Performance benchmarks (< 200ms API response)</li>
                <li>• HIPAA compliance checklist validation</li>
              </ul>
            </div>
            <div className="bg-white p-4 rounded-lg">
              <h4 className="font-semibold text-green-900 mb-2">Monitoring & Incident Response</h4>
              <ul className="text-sm text-gray-700 space-y-1">
                <li>• Real-time alerting with PagerDuty</li>
                <li>• SLA targets: 99.9% uptime</li>
                <li>• Automated rollback procedures</li>
                <li>• Post-incident review process</li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* Team Allocation */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white p-4 rounded-lg border-l-4 border-blue-500">
          <h4 className="font-semibold text-blue-900">Backend (3)</h4>
          <p className="text-sm text-gray-600 mt-2">
            • Microservices architecture<br/>
            • Security & compliance<br/>
            • Database optimization
          </p>
        </div>
        <div className="bg-white p-4 rounded-lg border-l-4 border-green-500">
          <h4 className="font-semibold text-green-900">Frontend (2)</h4>
          <p className="text-sm text-gray-600 mt-2">
            • React dashboard<br/>
            • Mobile responsiveness<br/>
            • Accessibility compliance
          </p>
        </div>
        <div className="bg-white p-4 rounded-lg border-l-4 border-purple-500">
          <h4 className="font-semibold text-purple-900">ML Engineers (2)</h4>
          <p className="text-sm text-gray-600 mt-2">
            • Agent orchestration<br/>
            • Model fine-tuning<br/>
            • Vector database optimization
          </p>
        </div>
        <div className="bg-white p-4 rounded-lg border-l-4 border-red-500">
          <h4 className="font-semibold text-red-900">DevOps (1)</h4>
          <p className="text-sm text-gray-600 mt-2">
            • Kubernetes deployment<br/>
            • CI/CD pipelines<br/>
            • Security monitoring
          </p>
        </div>
      </div>
    </div>
  );
}

function Challenge4() {
  return (
    <div className="space-y-6">
      <div className="flex items-center space-x-3 mb-6">
        <Server className="w-8 h-8 text-indigo-600" />
        <h2 className="text-3xl font-bold text-gray-900">FastAPI Implementation</h2>
      </div>

      <div className="bg-indigo-50 p-6 rounded-lg">
        <h3 className="text-xl font-semibold mb-4">Production-Ready Healthcare AI Microservice</h3>
        <p className="text-gray-700 mb-4">
          The complete implementation includes encrypted data handling, vector search, AI coaching generation, 
          and comprehensive audit logging. This service demonstrates enterprise-grade security and scalability patterns.
        </p>
        
        <div className="bg-white p-4 rounded-lg border">
          <h4 className="font-semibold text-gray-900 mb-2">Key Features Implemented:</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <ul className="text-sm text-gray-700 space-y-1">
              <li>• AES-256-GCM encryption for PHI data</li>
              <li>• JWT authentication with role-based access</li>
              <li>• Vector similarity search with Chroma DB</li>
              <li>• GPT-4 integration for personalized coaching</li>
            </ul>
            <ul className="text-sm text-gray-700 space-y-1">
              <li>• Comprehensive audit logging</li>
              <li>• Request/response validation with Pydantic</li>
              <li>• Rate limiting and security headers</li>
              <li>• Health checks and metrics endpoints</li>
            </ul>
          </div>
        </div>
      </div>

      <div className="bg-yellow-50 p-4 rounded-lg border-l-4 border-yellow-400">
        <div className="flex items-start">
          <div className="flex-shrink-0">
            <Activity className="w-5 h-5 text-yellow-600 mt-0.5" />
          </div>
          <div className="ml-3">
            <h4 className="text-yellow-800 font-semibold">Live Implementation</h4>
            <p className="text-yellow-700 text-sm mt-1">
              Click "Start Implementation" below to deploy the complete FastAPI microservice with all security features, 
              database integration, and monitoring capabilities.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;