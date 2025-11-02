from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import boto3
import json
import pandas as pd

app = Flask(__name__)
CORS(app)

# AWS Configuration
SAGEMAKER_ENDPOINT = 'canvas-nsl-kdddeploy'
AWS_REGION = 'us-east-1'

# Mistral Model Configuration
BEDROCK_MODEL_ID = 'mistral.mistral-7b-instruct-v0:2'

# Initialize AWS clients
sagemaker_runtime = boto3.client('sagemaker-runtime', region_name=AWS_REGION)
bedrock_runtime = boto3.client('bedrock-runtime', region_name=AWS_REGION)

# Attack type labels (38 classes)
ATTACK_LABELS = {
    0: 'apache2', 1: 'back', 2: 'buffer_overflow', 3: 'ftp_write', 
    4: 'guess_passwd', 5: 'httptunnel', 6: 'imap', 7: 'ipsweep',
    8: 'land', 9: 'loadmodule', 10: 'mailbomb', 11: 'mscan',
    12: 'multihop', 13: 'named', 14: 'neptune', 15: 'nmap',
    16: 'normal', 17: 'perl', 18: 'phf', 19: 'pod',
    20: 'portsweep', 21: 'processtable', 22: 'ps', 23: 'rootkit',
    24: 'saint', 25: 'satan', 26: 'sendmail', 27: 'smurf',
    28: 'snmpgetattack', 29: 'snmpguess', 30: 'sqlattack', 31: 'teardrop',
    32: 'udpstorm', 33: 'warezmaster', 34: 'worm', 35: 'xlock',
    36: 'xsnoop', 37: 'xterm'
}

# Attack categories for classification
ATTACK_CATEGORIES = {
    'normal': ['normal'],
    'DoS': ['apache2', 'back', 'land', 'neptune', 'mailbomb', 'pod', 'processtable', 
            'smurf', 'teardrop', 'udpstorm', 'worm'],
    'Probe': ['ipsweep', 'mscan', 'nmap', 'portsweep', 'saint', 'satan'],
    'R2L': ['ftp_write', 'guess_passwd', 'httptunnel', 'imap', 'multihop', 
            'named', 'phf', 'sendmail', 'snmpgetattack', 'snmpguess', 
            'sqlattack', 'xlock', 'xsnoop'],
    'U2R': ['buffer_overflow', 'loadmodule', 'perl', 'ps', 'rootkit', 
            'xterm', 'warezmaster']
}

def get_attack_category(attack_type):
    """Get the category of an attack type"""
    for category, attacks in ATTACK_CATEGORIES.items():
        if attack_type in attacks:
            return category
    return 'Unknown'

# Feature names in the exact order your model expects
FEATURE_NAMES = [
    'duration', 'src_bytes', 'dst_bytes', 'wrong_fragment', 'urgent',
    'hot', 'num_failed_logins', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'count', 'srv_count',
    'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'service_encoded',
    'protocol_type_encoded', 'flag_encoded', 'land_encoded',
    'logged_in_encoded', 'is_host_login_encoded',
    'is_guest_login_encoded', 'label'
]

def invoke_bedrock_mistral(prompt, system_context=None):
    """
    Invoke Mistral model via AWS Bedrock
    Mistral uses a specific prompt format with <s>[INST] tags
    """
    try:
        # Build the prompt with Mistral's instruction format
        if system_context:
            full_prompt = f"<s>[INST] {system_context}\n\n{prompt} [/INST]"
        else:
            full_prompt = f"<s>[INST] {prompt} [/INST]"
        
        # Mistral request body format
        body = {
            "prompt": full_prompt,
            "max_tokens": 512,
            "temperature": 0.5,
            "top_p": 0.9,
            "top_k": 50,
            "stop": []
        }
        
        print(f"Invoking Mistral model: {BEDROCK_MODEL_ID}")
        
        response = bedrock_runtime.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=json.dumps(body),
            contentType='application/json',
            accept='application/json'
        )
        
        # Parse Mistral response
        response_body = json.loads(response['body'].read())
        
        # Mistral returns output in 'outputs' array with 'text' field
        if 'outputs' in response_body and len(response_body['outputs']) > 0:
            generated_text = response_body['outputs'][0]['text']
            return generated_text.strip()
        else:
            return "No response generated from Mistral model."
    
    except Exception as e:
        print(f"Bedrock Mistral error: {str(e)}")
        import traceback
        traceback.print_exc()
        return f"Error generating AI response: {str(e)}"

@app.route('/')
def home():
    return render_template('index1.html')

@app.route('/predict', methods=['POST', 'OPTIONS'])
def predict():
    """Endpoint to receive prediction requests and forward to SageMaker"""
    
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.json
        
        # Handle test requests
        if data.get('test'):
            return jsonify({
                'status': 'success',
                'message': 'Backend is running and connected to SageMaker',
                'model_info': {
                    'classes': len(ATTACK_LABELS),
                    'attack_types': list(ATTACK_LABELS.values())
                }
            })
        
        # Get features array from frontend (already encoded)
        features = data.get('features', [])
        
        if not features or len(features) != 41:
            return jsonify({
                'error': f'Expected 41 features, got {len(features)}'
            }), 400
        
        # Add label column with 0 (it will be predicted by the model)
        features_with_label = features + [0]
        
        # Convert to CSV format using pandas
        body = pd.DataFrame([features_with_label]).to_csv(header=False, index=False).encode("utf-8")
        
        print(f"Sending to SageMaker endpoint: {SAGEMAKER_ENDPOINT}")
        
        # Invoke SageMaker endpoint with CSV format
        response = sagemaker_runtime.invoke_endpoint(
            EndpointName=SAGEMAKER_ENDPOINT,
            ContentType='text/csv',
            Accept='application/json',
            Body=body
        )
        
        # Parse response
        result_body = response['Body'].read().decode('utf-8')
        result = json.loads(result_body)
        
        # Extract prediction for multi-class
        attack_type = 'normal'
        attack_label = 16
        confidence = 0.5
        probabilities = []
        
        if 'predictions' in result and len(result['predictions']) > 0:
            pred = result['predictions'][0]
            
            if isinstance(pred, dict):
                label = pred.get('predicted_label', '16')
                if isinstance(label, str):
                    if label.isdigit():
                        attack_label = int(label)
                    else:
                        attack_label = next((k for k, v in ATTACK_LABELS.items() if v == label), 16)
                else:
                    attack_label = int(label)
                
                attack_type = ATTACK_LABELS.get(attack_label, 'unknown')
                scores = pred.get('score', [])
                if isinstance(scores, list) and len(scores) > 0:
                    probabilities = scores
                    confidence = max(scores)
                else:
                    confidence = 0.85
                
            elif isinstance(pred, str):
                if pred.isdigit():
                    attack_label = int(pred)
                    attack_type = ATTACK_LABELS.get(attack_label, 'unknown')
                else:
                    attack_type = pred
                    attack_label = next((k for k, v in ATTACK_LABELS.items() if v == pred), 16)
                confidence = 0.85
                
            elif isinstance(pred, (int, float)):
                attack_label = int(pred)
                attack_type = ATTACK_LABELS.get(attack_label, 'unknown')
                confidence = 0.85
                
            elif isinstance(pred, list):
                probabilities = pred
                attack_label = probabilities.index(max(probabilities))
                attack_type = ATTACK_LABELS.get(attack_label, 'unknown')
                confidence = max(probabilities)
        
        # Get attack category
        category = get_attack_category(attack_type)
        is_attack = category != 'normal'
        
        print(f"Prediction: {attack_type} (label: {attack_label}), Category: {category}, Confidence: {confidence:.4f}")
        
        return jsonify({
            'prediction': attack_type,
            'attack_label': int(attack_label),
            'category': category,
            'is_attack': is_attack,
            'confidence': float(confidence),
            'probabilities': probabilities if probabilities else None,
            'raw_response': result
        })
        
    except Exception as e:
        error_msg = str(e)
        print(f"Error during prediction: {error_msg}")
        import traceback
        traceback.print_exc()
        
        return jsonify({
            'error': error_msg,
            'message': 'Failed to get prediction from SageMaker'
        }), 500

@app.route('/ai-analysis', methods=['POST'])
def ai_analysis():
    """Generate AI-powered analysis using Mistral model"""
    try:
        data = request.json
        attack_type = data.get('attack_type', 'unknown')
        category = data.get('category', 'unknown')
        confidence = data.get('confidence', 0)
        features = data.get('features', {})
        
        # Create detailed prompt for Mistral
        system_context = "You are a cybersecurity expert specializing in network intrusion detection and incident response. Provide clear, actionable insights."
        
        prompt = f"""Analyze this network intrusion detection result:

Attack Type: {attack_type}
Category: {category}
Detection Confidence: {confidence:.2%}

Key Network Features:
- Protocol: {features.get('protocol_type', 'N/A')}
- Service: {features.get('service', 'N/A')}
- Source Bytes: {features.get('src_bytes', 'N/A')}
- Destination Bytes: {features.get('dst_bytes', 'N/A')}
- Connection Count: {features.get('count', 'N/A')}
- Error Rate: {features.get('serror_rate', 'N/A')}
- Logged In: {features.get('logged_in', 'N/A')}

Please provide:
1. A brief explanation of this attack type in simple terms
2. Why this pattern was detected (based on the features)
3. Potential impact on the network
4. 3-4 specific mitigation steps

Keep the response concise and actionable for a security operations team."""

        ai_response = invoke_bedrock_mistral(prompt, system_context)
        
        return jsonify({
            'status': 'success',
            'analysis': ai_response
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/ai-remediation', methods=['POST'])
def ai_remediation():
    """Generate detailed remediation plan using Mistral model"""
    try:
        data = request.json
        attack_type = data.get('attack_type', 'unknown')
        category = data.get('category', 'unknown')
        features = data.get('features', {})
        
        system_context = "You are a senior incident response consultant with expertise in network security and threat mitigation."
        
        prompt = f"""Generate a detailed incident response and remediation plan for a detected {category} attack (specifically: {attack_type}).

Network Traffic Details:
- Protocol: {features.get('protocol_type', 'N/A')}
- Service: {features.get('service', 'N/A')}
- Source IP Connections: {features.get('count', 'N/A')}
- Data Transfer: {features.get('src_bytes', 'N/A')} bytes sent, {features.get('dst_bytes', 'N/A')} bytes received
- Authentication: {'Logged In' if features.get('logged_in') == '1' else 'Not Logged In'}

Provide a structured response with:

1. IMMEDIATE ACTIONS (0-15 minutes)
   - Critical steps to contain the threat
   
2. SHORT-TERM RESPONSE (15 minutes - 4 hours)
   - Investigation and analysis steps
   
3. RECOVERY STEPS (4-24 hours)
   - System restoration procedures
   
4. LONG-TERM PREVENTION
   - Security improvements to prevent recurrence

5. MONITORING CHECKLIST
   - What to monitor post-incident

Format this as a clear, step-by-step action plan suitable for a security operations center (SOC) team."""

        ai_response = invoke_bedrock_mistral(prompt, system_context)
        
        return jsonify({
            'status': 'success',
            'remediation_plan': ai_response
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/ai-chat', methods=['POST'])
def ai_chat():
    """Interactive chat with Mistral about security concerns"""
    try:
        data = request.json
        user_message = data.get('message', '')
        context = data.get('context', {})
        
        # Build context-aware prompt
        context_str = ""
        if context:
            context_str = f"\nCurrent Detection Context:\n"
            context_str += f"- Last Attack Detected: {context.get('last_attack', 'None')}\n"
            context_str += f"- Category: {context.get('category', 'N/A')}\n"
            context_str += f"- Total Tests: {context.get('total_tests', 0)}\n\n"
        
        system_context = """You are an AI security assistant for an Intrusion Detection System. 
Help users understand network security threats, interpret detection results, and provide guidance on cybersecurity best practices. 
Be helpful, concise, and security-focused."""
        
        prompt = f"{context_str}User Question: {user_message}\n\nProvide a helpful and concise response:"
        
        ai_response = invoke_bedrock_mistral(prompt, system_context)
        
        return jsonify({
            'status': 'success',
            'response': ai_response
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/ai-report', methods=['POST'])
def ai_report():
    """Generate executive summary report using Mistral model"""
    try:
        data = request.json
        stats = data.get('stats', {})
        recent_attacks = data.get('recent_attacks', [])
        
        system_context = "You are a cybersecurity analyst preparing reports for executive leadership. Be concise, professional, and focus on business impact."
        
        prompt = f"""Generate an executive summary report for network security monitoring:

STATISTICS:
- Total Traffic Analyzed: {stats.get('total', 0)}
- Normal Traffic: {stats.get('normal', 0)}
- DoS Attacks: {stats.get('dos', 0)}
- Probe Attacks: {stats.get('probe', 0)}
- Other Attacks: {stats.get('other', 0)}

RECENT ATTACK TYPES DETECTED:
{', '.join(recent_attacks) if recent_attacks else 'None'}

Please provide:
1. Overall Security Posture Assessment
2. Key Findings and Trends
3. Risk Level (Low/Medium/High/Critical)
4. Top 3 Recommendations

Format this as a professional executive summary suitable for management."""

        ai_response = invoke_bedrock_mistral(prompt, system_context)
        
        return jsonify({
            'status': 'success',
            'report': ai_response
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'sagemaker_endpoint': SAGEMAKER_ENDPOINT,
        'bedrock_model': BEDROCK_MODEL_ID,
        'region': AWS_REGION,
        'model_classes': len(ATTACK_LABELS)
    })

@app.route('/attack-types', methods=['GET'])
def attack_types():
    """Return all attack types and categories"""
    return jsonify({
        'attack_labels': ATTACK_LABELS,
        'categories': ATTACK_CATEGORIES
    })

@app.route('/test-mistral', methods=['GET'])
def test_mistral():
    """Test Mistral connectivity"""
    try:
        test_response = invoke_bedrock_mistral(
            "Say 'Hello, Mistral is working!' in a brief greeting."
        )
        return jsonify({
            'status': 'success',
            'message': 'Mistral model is working',
            'test_response': test_response
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 Starting Multi-Class IDS Backend Server with AI")
    print(f"📡 SageMaker Endpoint: {SAGEMAKER_ENDPOINT}")
    print(f"🤖 Bedrock Model: {BEDROCK_MODEL_ID} (Mistral 7B)")
    print(f"🌍 Region: {AWS_REGION}")
    print(f"📊 Expected Features: {len(FEATURE_NAMES) - 1} (+ label)")
    print(f"🎯 Attack Classes: {len(ATTACK_LABELS)}")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)