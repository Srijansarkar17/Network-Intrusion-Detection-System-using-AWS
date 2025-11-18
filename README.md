# Network Intrusion Detection System (IDS)

A sophisticated AI-powered Intrusion Detection System built on AWS infrastructure that detects and classifies 38 different types of network attacks in real-time using machine learning.

## 🎯 Project Overview

This project implements a multi-class network intrusion detection system that analyzes network traffic patterns and identifies potential security threats. The system leverages AWS services for scalable machine learning inference and provides AI-powered security analysis using the Mistral 7B model.

### Key Features

- **Multi-Class Attack Detection**: Identifies 38 different attack types across 4 major categories
- **Real-Time Prediction**: Instant classification of network traffic patterns
- **AI-Powered Analysis**: Detailed threat analysis and remediation plans using AWS Bedrock (Mistral 7B)
- **Interactive Dashboard**: User-friendly web interface for network monitoring
- **Scalable Architecture**: Built on AWS for enterprise-grade performance

## 🏗️ System Architecture

```
NSL-KDD Dataset → S3 Storage → AWS Glue ETL → SageMaker Canvas → Endpoint
                                                                        ↓
                                                              Flask Backend ← AWS Bedrock
                                                                        ↓
                                                                 Frontend UI
```

### Architecture Components

1. **Data Layer**: NSL-KDD dataset stored in Amazon S3
2. **Processing Layer**: AWS Glue for ETL and feature engineering
3. **Model Layer**: SageMaker Canvas endpoint for predictions
4. **Application Layer**: Flask backend with REST API
5. **AI Layer**: AWS Bedrock (Mistral 7B) for intelligent analysis
6. **Presentation Layer**: Interactive web interface

## 📊 Dataset

**Source**: [NSL-KDD Dataset](https://www.kaggle.com/datasets/hassan06/nslkdd)

The NSL-KDD dataset is an improved version of the KDD Cup 1999 dataset, containing network connection records with labeled attack types.

### Attack Categories

- **Normal**: Legitimate network traffic
- **DoS (Denial of Service)**: 11 attack types (apache2, back, land, neptune, etc.)
- **Probe**: 6 attack types (ipsweep, mscan, nmap, portsweep, etc.)
- **R2L (Remote to Local)**: 13 attack types (ftp_write, guess_passwd, httptunnel, etc.)
- **U2R (User to Root)**: 7 attack types (buffer_overflow, loadmodule, perl, etc.)

## 🛠️ Technology Stack

### Cloud Services (AWS)
- **Amazon S3**: Dataset storage
- **AWS Glue**: ETL pipeline and data transformation
- **Amazon SageMaker Canvas**: ML model training and deployment
- **AWS Bedrock**: AI-powered analysis (Mistral 7B Instruct)
- **AWS Region**: us-east-1

### Backend
- **Flask**: Python web framework
- **Flask-CORS**: Cross-origin resource sharing
- **Boto3**: AWS SDK for Python
- **Pandas**: Data manipulation

### Frontend
- HTML5, CSS3, JavaScript
- RESTful API integration

## 📋 Prerequisites

- AWS Account with appropriate permissions
- Python 3.8+
- AWS CLI configured
- SageMaker Canvas endpoint deployed
- AWS Bedrock access enabled

## 🚀 Installation & Setup

### 1. Clone the Repository

```bash
git clone <repository-url>
cd intrusion-detection-system
```

### 2. Install Dependencies

```bash
pip install flask flask-cors boto3 pandas
```

### 3. Configure AWS Credentials

```bash
aws configure
# Enter your AWS Access Key ID
# Enter your AWS Secret Access Key
# Default region: us-east-1
```

### 4. Update Configuration

Edit the configuration variables in `app.py`:

```python
SAGEMAKER_ENDPOINT = 'your-endpoint-name'
AWS_REGION = 'us-east-1'
BEDROCK_MODEL_ID = 'mistral.mistral-7b-instruct-v0:2'
```

### 5. Run the Application

```bash
python app.py
```

The server will start on `http://localhost:5000`

## 📡 API Endpoints

### Prediction Endpoints

#### `POST /predict`
Predicts attack type from network traffic features.

**Request Body**:
```json
{
  "features": [array of 41 numerical features]
}
```

**Response**:
```json
{
  "prediction": "attack_type",
  "category": "DoS",
  "is_attack": true,
  "confidence": 0.95,
  "attack_label": 14
}
```

### AI Analysis Endpoints

#### `POST /ai-analysis`
Generate AI-powered analysis of detected attacks.

#### `POST /ai-remediation`
Get detailed remediation plans for specific threats.

#### `POST /ai-chat`
Interactive chat with AI security assistant.

#### `POST /ai-report`
Generate executive summary reports.

### Utility Endpoints

#### `GET /health`
Health check and system status.

#### `GET /attack-types`
List all attack types and categories.

#### `GET /test-mistral`
Test Bedrock Mistral connectivity.

## 🔄 Data Pipeline

### 1. Data Ingestion
- Upload NSL-KDD dataset to Amazon S3 bucket
- Organize data in structured folders

### 2. ETL Processing (AWS Glue)
The Glue job performs:
- **Data Cleaning**: Handle missing values and inconsistencies
- **Feature Engineering**: Create derived features from raw data
- **Label Encoding**: Transform categorical variables (protocol_type, service, flag) into numerical format
- **Data Validation**: Ensure data quality and consistency

### 3. Model Training (SageMaker Canvas)
- Import cleaned data from S3
- Train multi-class classification model
- Validate model performance
- Deploy endpoint for real-time inference

### 4. Prediction Pipeline
- Frontend sends traffic features to Flask backend
- Backend formats data as CSV
- Invokes SageMaker endpoint
- Parses prediction results
- Returns classification to frontend

## 🎨 Features

### Core Functionality
- **Real-time Attack Detection**: Instant classification of 38 attack types
- **Confidence Scoring**: Probability scores for predictions
- **Category Classification**: Groups attacks into 4 major categories

### AI-Enhanced Features
- **Threat Analysis**: Detailed explanation of detected attacks
- **Impact Assessment**: Evaluate potential damage to network
- **Remediation Plans**: Step-by-step incident response procedures
- **Interactive Chat**: Ask questions about security threats
- **Executive Reports**: Management-ready security summaries

## 🔮 Future Scope

### Real-Time Data Integration
- **AWS Kinesis Integration**: Stream live network traffic data
- **Website Monitoring**: Fetch real-time network data from websites
- **Continuous Prediction**: Real-time threat detection pipeline
- **Alert System**: Automated notifications for critical threats

### Enhanced Features
- **Historical Analysis**: Trend analysis and pattern recognition
- **Custom Rules**: User-defined detection rules
- **Multi-Model Ensemble**: Combine multiple ML models
- **Integration APIs**: Connect with SIEM systems

## 📊 Model Information

### Input Features (41 features)
- Connection duration, protocol type, service type
- Bytes transferred (source/destination)
- Connection statistics and error rates
- Host-based traffic features
- Encoded categorical variables

### Output
- **Predicted Class**: One of 38 attack types
- **Confidence Score**: Model certainty (0-1)
- **Category**: High-level attack classification
- **Is Attack**: Boolean flag for attack detection

## 🔒 Security Considerations

- AWS credentials should be stored securely (use IAM roles in production)
- Enable VPC endpoints for SageMaker and Bedrock
- Implement API rate limiting
- Use HTTPS in production
- Regularly update dependencies

## 📝 Environment Variables

```bash
export AWS_REGION=us-east-1
export SAGEMAKER_ENDPOINT=canvas-nsl-kdddeploy
export BEDROCK_MODEL_ID=mistral.mistral-7b-instruct-v0:2
```

## 🐛 Troubleshooting

### Common Issues

**SageMaker Endpoint Not Found**
- Verify endpoint name matches deployed model
- Check AWS region configuration
- Ensure endpoint is in "InService" status

**Bedrock Access Denied**
- Enable Bedrock model access in AWS Console
- Verify IAM permissions for Bedrock

**Feature Count Mismatch**
- Ensure exactly 41 features are provided
- Verify feature order matches training data

## 📈 Performance Metrics

- **Attack Detection Accuracy**: ~95%+ (depends on model training)
- **Prediction Latency**: < 100ms (average)
- **Supported Throughput**: Scalable based on SageMaker instance


## 📄 License

Specify your license here.

## 🙏 Acknowledgments

- NSL-KDD Dataset: University of New Brunswick
- AWS Services: Amazon Web Services
- Mistral AI: Mistral 7B Instruct Model

## 📞 Support

For issues and questions:
- Open an issue on GitHub
- Contact: srijanb463@gmail.com

---
