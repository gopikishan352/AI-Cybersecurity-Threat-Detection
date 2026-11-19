# 🛡️ AI Cyber Threat Detection System (SOC Dashboard v2.0)

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue?style=for-the-badge&logo=python">
  <img src="https://img.shields.io/badge/Flask-REST_API-black?style=for-the-badge&logo=flask">
  <img src="https://img.shields.io/badge/ML-Random_Forest_5--Class-success?style=for-the-badge">
  <img src="https://img.shields.io/badge/Dataset-NSL--KDD-informational?style=for-the-badge">
  <img src="https://img.shields.io/badge/Groq_AI-Llama--3.3--70B-orange?style=for-the-badge">
  <img src="https://img.shields.io/badge/Database-SQLite3-lightgrey?style=for-the-badge">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge">
</p>

---

## 🚀 Live Demo

**AI Cybersecurity Threat Detection System**

Experience the AI-powered cybersecurity dashboard with machine learning-based threat detection, network traffic analysis, and security monitoring.

🌐 **Live Application:** [Launch AI Cyber Threat Detection](https://ai-cyber-threat-detection-t8cq.onrender.com/)

**Technology Stack:** Python, Flask, Machine Learning, HTML, CSS, JavaScript

**Deployment Platform:** Render

*Note: The free Render instance may take approximately 50 seconds or longer to wake up after inactivity.*

## 📌 1. Project Overview

The **AI Cyber Threat Detection System** is an enterprise-grade, SOC (Security Operations Center) cybersecurity dashboard and machine learning classification pipeline. Designed to detect, categorize, and mitigate malicious network intrusions, the system analyzes network traffic flows using a multi-class **Random Forest Classifier** trained on the benchmark **NSL-KDD dataset** (125,973 records).

### Key Highlights
- **Multi-Class Anomaly Classification**: Accurately classifies network flows into 5 distinct categories: **Normal**, **DoS** (Denial of Service), **Probe** (Reconnaissance), **R2L** (Remote to Local), and **U2R** (User to Root).
- **Automated Risk Assessment**: Dynamically tags network traffic with severity risk levels (**LOW**, **MEDIUM**, **HIGH**, **CRITICAL**).
- **Persistent Audit Logging**: Thread-safe SQLite database preserving detection events with full search, category filtering, risk filtering, and pagination.
- **Live Traffic Simulation**: Real-time traffic stream replaying records from the NSL-KDD test dataset with synthetic IP/port telemetry and start/stop controls.
- **Defensive SOC AI Intelligence**: Integrated with **Groq LLM (Llama-3.3-70B-versatile)** to generate contextual incident summaries, detection rationales, potential impact analysis, and actionable mitigation guidance. Includes a graceful deterministic fallback if an API key is not configured.
- **Reporting Engine**: One-click server-side **Executive PDF reports** (via ReportLab) and SIEM-ready **CSV telemetry exports**.
- **Tested & Grounded Metrics**: Displays genuine evaluated metrics (99.88% validation accuracy) calculated directly from model evaluation, with an interactive 5x5 Confusion Matrix.

---

## ⚙️ 2. Technology Stack

| Layer | Technology |
|---|---|
| **Backend & REST API** | Python, Flask, Flask-CORS, Gunicorn, Werkzeug |
| **Machine Learning** | Scikit-Learn (RandomForestClassifier, StandardScaler, LabelEncoder), NumPy, Pandas, Joblib |
| **Generative AI** | Groq API (`llama-3.3-70b-versatile`), Python-dotenv |
| **Database** | SQLite3 (thread-safe connection pool, indexes on timestamps, risk levels, threat types) |
| **Report Generation** | ReportLab (multi-page PDF generator), Python CSV Engine |
| **Frontend & UI** | HTML5, CSS3 (SOC Dark Theme), Bootstrap 5, Bootstrap Icons, Chart.js |
| **Testing & Quality** | Pytest, Scapy abstraction adapter |

---

## 📂 3. Project Directory Structure

```text
AI-Cyber-Threat-Detection/
├── data_sources/              # Traffic ingestion layer
│   ├── __init__.py
│   ├── base_source.py         # Abstract traffic source interface
│   ├── dataset_source.py      # Simulated NSL-KDD replay source
│   └── live_capture.py        # Optional future Scapy sniffer adapter
├── dataset/                   # NSL-KDD benchmark datasets
│   ├── KDDTrain+.txt          # 125,973 training records (43 columns)
│   └── KDDTest+.txt           # 22,544 test records
├── model/                     # Trained machine learning artifacts
│   ├── model.pkl              # 5-class Random Forest Classifier
│   ├── scaler.pkl             # StandardScaler fitted on 41 features
│   ├── label_encoders.pkl     # Categorical encoders (protocol, service, flag)
│   └── metrics.json           # Actual evaluated benchmark metrics & confusion matrix
├── static/
│   ├── css/
│   │   └── style.css          # SOC dark theme stylesheet
│   └── js/
│       └── script.js          # SOC dashboard interactive controller
├── templates/
│   └── index.html             # Multi-tab SOC dashboard interface
├── utils/                     # Core backend utilities
│   ├── __init__.py
│   ├── constants.py           # NSL-KDD schema, attack mapping, threat intel
│   ├── database.py            # SQLite threat history and statistics engine
│   ├── preprocess.py          # Unified preprocessing for training & inference
│   ├── ai_analyzer.py         # Groq LLM integration with safe SOC fallback
│   └── pdf_generator.py       # ReportLab PDF report generation engine
├── tests/                     # Automated unit and integration test suite
│   ├── test_model.py          # ML artifact & inference tests
│   ├── test_preprocess.py     # Preprocessing & categorical encoding tests
│   ├── test_database.py       # SQLite CRUD & aggregation tests
│   ├── test_api.py            # REST API route integration tests
│   └── test_reports.py        # PDF & CSV generation tests
├── app.py                     # Flask application server & REST API
├── train_model.py             # Script to train 5-class model and compute metrics
├── requirements.txt           # Python dependencies
├── pytest.ini                 # Pytest configuration
├── .env.example               # Example environment variables
└── README.md                  # Comprehensive documentation
```

---

## 🚀 4. Installation & Setup (Windows, macOS, Linux)

### Step 1: Clone the Repository
```bash
git clone https://github.com/Ashish-bytes/AI-Cyber-Threat-Detection.git
cd AI-Cyber-Threat-Detection
```

### Step 2: Create a Virtual Environment

**On Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\activate
```

**On Windows (Command Prompt):**
```cmd
python -m venv venv
venv\Scripts\activate.bat
```

**On Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Copy `.env.example` to `.env`:
```powershell
copy .env.example .env
```
Open `.env` in a text editor:
```env
# Optional: Set your Groq API Key (get one free at https://console.groq.com)
GROQ_API_KEY=your_actual_groq_api_key_here

# Server Port
PORT=5000
```
*(Note: If `GROQ_API_KEY` is left blank, the application runs with full functionality using built-in deterministic SOC Threat Intelligence.)*

---

## 🧠 5. Model Training & Evaluation

The repository already includes pre-trained artifacts in the `model/` directory. If you wish to retrain the 5-class Random Forest model from scratch on `KDDTrain+.txt`:

```powershell
python train_model.py
```

### What Happens During Training:
1. Loads `dataset/KDDTrain+.txt` (125,973 network flow records).
2. Maps all 39 granular attack types to 5 standard classes (**Normal**, **DoS**, **Probe**, **R2L**, **U2R**).
3. Encodes categorical variables (`protocol_type`, `service`, `flag`) and normalizes 41 features with `StandardScaler`.
4. Splits data into 80% train / 20% stratified validation.
5. Fits a 100-tree Random Forest Classifier with balanced subsampling.
6. Evaluates actual metrics on both the 20% validation split and external `dataset/KDDTest+.txt`.
7. Saves `model.pkl`, `scaler.pkl`, `label_encoders.pkl`, and writes exact performance figures to `model/metrics.json`.

---

## 💻 6. Running the Application

Start the Flask server:
```powershell
python app.py
```

Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 🖥️ 7. Dashboard Sections & Usage

The application features 10 specialized SOC tabs:

1. **Dashboard**: High-level telemetry stat cards (Total, Threats, Safe, High/Critical Risk, Detection Rate), 5-Class Threat Doughnut chart, Severity Bar chart, Detection Timeline, and Recent Alert Feed.
2. **Live Monitoring**: Real-time traffic replay simulation from `KDDTest+.txt`. Click **START MONITORING** to stream incoming traffic events, inspect protocol/service, and view dynamic counter updates.
3. **Single Prediction**: Manual traffic inspector. Enter 41 comma-separated feature values or click one of the quick scenario presets (**Normal Web Browsing**, **DoS Neptune Attack**, **Recon Probe**, **R2L Password Guessing**) to view instant ML classifications, confidence meters, and defensive guidance.
4. **Dataset Analysis**: Batch processing center. Upload any `.csv` or `.txt` NSL-KDD dataset to classify thousands of flows simultaneously, view category progress bars, and inspect row-by-row previews.
5. **Threat History**: Searchable SQLite detection log with real-time text search, filtering by threat type and risk level, pagination, and a modal viewer for full event details.
6. **Analytics**: Deep-dive visualizations comparing multi-class distributions and risk severity breakdown.
7. **Model Performance**: Displays genuine evaluation metrics (**99.88% Accuracy**, **Precision**, **Recall**, **F1 Score**), complete 5x5 Confusion Matrix, and per-class performance breakdowns.
8. **Reports & Export**: Download customized, printable **Executive PDF reports** generated on the fly via ReportLab, or export complete detection history as **CSV**.
9. **AI Intelligence**: View Groq Llama-3.3-70B connection status, knowledge base definitions for DoS, Probe, R2L, and U2R attacks, and configuration guides.
10. **About & Architecture**: Technical pipeline flowcharts, ingestion layer specs, and NSL-KDD feature definitions.

---

## 📡 8. REST API Documentation

All API responses follow consistent JSON formats with proper HTTP status codes.

| Method | Endpoint | Description | Sample Request / Query |
|---|---|---|---|
| `GET` | `/api/health` | Operational health and subsystem status | None |
| `GET` | `/metrics` | Legacy model metrics endpoint | None |
| `GET` | `/api/model-performance` | Evaluated metrics, confusion matrix, dataset specs | None |
| `POST` | `/api/predict` | Predict single flow classification | `{"preset": "dos"}` or `{"features": [...]}` |
| `POST` | `/api/upload` | Upload and batch-classify CSV/TXT dataset | `multipart/form-data` with `file` |
| `GET` | `/api/statistics` | Aggregated metrics for dashboard visualizations | None |
| `GET` | `/api/history` | Paginated, searchable threat audit logs | `?page=1&per_page=15&search=192.168&threat_type=DoS` |
| `DELETE` | `/api/history` | Clear detection audit logs | None |
| `GET` | `/api/threats` | Threat category mappings and intelligence | None |
| `GET` | `/api/simulation/feed` | Stream simulated replay network traffic events | `?count=3` |
| `GET` | `/api/export/csv` | Download filtered history as CSV | `?threat_type=ALL&risk_level=HIGH` |
| `GET` | `/api/export/pdf` | Generate and download executive PDF report | None |
| `GET` | `/api/presets` | Quick test scenario sample features | None |

---

## 🧪 9. Automated Testing

The project includes a full test suite built with `pytest`:

```powershell
pytest tests/ -v
```

### Test Coverage (20 Passing Tests):
- **Model Tests (`tests/test_model.py`)**: Validates presence of `model.pkl`, `scaler.pkl`, `label_encoders.pkl`, verifies 5-class inference and probability distributions.
- **Preprocessing Tests (`tests/test_preprocess.py`)**: Validates attack category mapping, list and DataFrame inputs, and handling of unseen categorical strings without crashing.
- **Database Tests (`tests/test_database.py`)**: Tests SQLite initialization, single insertion, batch insertion, text search, threat/risk filtering, and log clearing.
- **API Tests (`tests/test_api.py`)**: Tests all REST endpoints (`/api/health`, `/metrics`, `/api/model-performance`, `/api/predict`, `/api/upload`, `/api/simulation/feed`, `/api/statistics`, `/api/history`).
- **Report Tests (`tests/test_reports.py`)**: Tests ReportLab PDF document compilation and CSV streaming exports.

---

## 🔧 10. Troubleshooting & FAQs

#### Q1: What if I don't have a Groq API key?
> **Answer**: The application does **not** crash. If `GROQ_API_KEY` is not provided in `.env`, the system automatically activates its built-in **Deterministic SOC Threat Intelligence Engine**, providing complete threat descriptions, potential impacts, and defensive recommendations.

#### Q2: Can I upload a CSV without column headers?
> **Answer**: Yes. The dataset upload handler dynamically inspects the file structure. It supports standard 43-column NSL-KDD raw files (e.g. `KDDTest+.txt`), 42-column files, and 41-feature clean CSVs, with or without headers.

#### Q3: Does Live Monitoring capture real network packets?
> **Answer**: No. To ensure safe, cross-platform execution without requiring administrator/root privileges or WinPcap/Npcap drivers, Live Monitoring operates as a **Simulated Traffic Replay** from the NSL-KDD test set. A modular adapter (`data_sources/live_capture.py`) is included for future Scapy integration.

---

## 📜 11. License

This project is licensed under the **MIT License**.
