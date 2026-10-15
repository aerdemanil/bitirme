# 🛡️ ADS Guardian — Real-Time Web Attack Detection System

ADS Guardian watches the HTTP traffic of an nginx web server running in Docker and
detects attacks **in real time**. Every access-log line is parsed into a feature
vector and passed through a set of pluggable detectors that combine
**machine learning** (scikit-learn) with **rule-based scoring**. Results are streamed
to a live web dashboard over WebSockets.

> Graduation (capstone) project.

## Features

| Attack | Detection method |
|--------|------------------|
| **DoS / DDoS** | Random Forest trained on the CIC-IDS2018 dataset (network-flow features mapped to HTTP log features) |
| **Brute Force** | Rule-based score (401/403 responses, sensitive paths like `/login`, request rate, POST, short User-Agent) combined with the ML model |
| **SQL Injection** | Regex rules + weighted anomaly score + TF-IDF / Logistic Regression model on the request path |

- **Live dashboard** (Flask + Socket.IO): traffic time series, attack type distribution, active attack sessions, live log stream, threat level indicator, toast/modal alerts
- **Test lab** inside the dashboard: offline checks of the models and a live attack generator (DoS, brute force, SQLi and mixed scenarios) that sends real requests to the target container
- **Optional AI assistant**: attack analysis, chat and summaries through a local [Ollama](https://ollama.com) model (`gemma3:4b`)
- **Terminal mode** (`detect.py`) with colored alerts, cooldowns and per-IP attack session summaries
- **Plugin architecture**: drop a new detector into `detector/attacks/` and it is loaded automatically

## How it works

```
nginx container (Docker) ──► access log stream ──► parse_log_line()
                                                        │
                                       feature vector (requests/IP in last 60 s,
                                       bytes sent, status code, method, path depth,
                                       User-Agent length, SQLi scores …)
                                                        │
                          ┌─────────────────────────────┼─────────────────────────────┐
                          ▼                             ▼                             ▼
                    DosDetector                BruteForceDetector          SqlInjectionDetector
                  (Random Forest)               (rules + ML)              (regex + score + ML)
                          └─────────────────────────────┼─────────────────────────────┘
                                                        ▼
                                   Flask + Socket.IO ──► browser dashboard
```

The key idea of the project is the **feature mapping** in `ml_pipeline/train_cic_http.py`:
CIC-IDS2018 contains network-flow features, while the running system only sees nginx
log lines. Flow features are therefore mapped to their closest HTTP-log equivalents
(e.g. `Flow Pkts/s × 60 → requests_per_ip_last_60s`, `TotLen Fwd Pkts → bytes_sent`)
before training, so the model can interpret real log data.

## Project structure

```
bitirme/
├── app/                          # The detection system
│   ├── run.py                    # One-command launcher (checks deps + model, starts dashboard)
│   ├── dashboard.py              # Flask + Socket.IO backend, REST API, live test lab
│   ├── detect.py                 # Terminal-only real-time detection
│   ├── test_system.py            # Detector/model smoke tests (no Docker needed)
│   ├── requirements.txt
│   ├── models/                   # Trained models go here (git-ignored)
│   ├── detector/
│   │   ├── base_attack.py        # Abstract base class for all detectors
│   │   ├── attack_registry.py    # @register decorator + auto-loading of detectors
│   │   ├── feature_extractor.py  # nginx log line → feature vector, SQLi scoring
│   │   └── attacks/
│   │       ├── dos_detector.py
│   │       ├── brute_force.py
│   │       └── sql_injection.py
│   ├── templates/dashboard.html
│   └── static/                   # dashboard.js, dashboard.css
├── ml_pipeline/                  # Data preparation and model training
│   ├── explore_labels.py         # Label distribution of the CIC-IDS2018 CSV files
│   ├── clean_dataset.py          # Builds a balanced DoS / BruteForce / Benign dataset
│   ├── train_cic_http.py         # Trains the Random Forest (DoS / BruteForce / Benign)
│   ├── train_sqli_model.py       # Trains the TF-IDF + Logistic Regression SQLi model
│   └── test_sqli_real.py         # Evaluates the SQLi model on real honeypot traffic
└── docs/                         # Detailed project notes (Turkish)
    ├── project_overview_tr.txt
    └── presentation_notes_tr.txt
```

## Getting started

### Requirements

- Python 3.10+
- Docker
- (Optional) Ollama with `gemma3:4b` for the AI features

### 1. Start the target web server

The system monitors an nginx container named `hedef-sunucu` by default. The official
nginx image already writes access logs to stdout in the combined format:

```bash
docker run -d --name hedef-sunucu -p 8080:80 nginx
```

The live test lab sends its requests to `http://localhost:8080`.

### 2. Install dependencies

```bash
cd app
pip install -r requirements.txt
```

### 3. Add the trained models

Model files are not stored in the repository. Train them (see
[Training the models](#training-the-models)) so that `app/models/` contains:

```
dos_model.pkl  ml_scaler.pkl  ml_encoder.pkl  sqli_model.pkl  sqli_vectorizer.pkl
```

### 4. Run

```bash
python run.py                                  # dashboard on http://localhost:5000
python run.py --container my-nginx --port 8000 # custom container / port
python detect.py                               # terminal mode only
python test_system.py                          # smoke tests
```

## Training the models

The datasets are large and are **not** included in the repository (`*.csv` is git-ignored).
Place them in `ml_pipeline/` before running the scripts.

| Script | Input | Output |
|--------|-------|--------|
| `explore_labels.py` | CIC-IDS2018 daily CSVs (`02-14-2018.csv`, …) | `label_distribution.txt` |
| `clean_dataset.py` | CIC-IDS2018 daily CSVs | `cleaned_dataset.csv` (50,000 rows per class) |
| `train_cic_http.py` | `cleaned_dataset.csv` | `ml_model.pkl`, `ml_scaler.pkl`, `ml_encoder.pkl`, also copied to `app/models/` (`dos_model.pkl`, …) |
| `train_sqli_model.py` | `sqli.csv`, `sqliv2.csv`, `SQLiV3.csv` (SQL injection datasets) | `sqli_model.pkl`, `sqli_vectorizer.pkl` |
| `test_sqli_real.py` | `sqli_model.pkl` + `../tanner_last_12h_unique.csv` (Tanner honeypot export) | Accuracy on real traffic |

```bash
cd ml_pipeline
python clean_dataset.py
python train_cic_http.py
python train_sqli_model.py
cp sqli_model.pkl sqli_vectorizer.pkl ../app/models/
```

Each training script also writes a text report (`*_report.txt`) and evaluation plots
(class distribution, confusion matrix, feature importance, ROC, cross-validation)
to `ml_pipeline/plots/`.

## REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Dashboard |
| GET | `/api/stats` | Counters, active attacks, time series |
| GET | `/api/logs` | Recent log lines |
| GET | `/api/attacks` | Recent detections |
| GET | `/api/detectors` | Loaded detectors |
| GET | `/api/health` | Container and model status |
| POST | `/api/test/offline` | Run test cases against the models in memory |
| POST | `/api/live-test/{dos,bruteforce,sqli,scenario}` | Start a live attack simulation against the target container |
| GET / DELETE | `/api/live-test/status/<id>`, `/api/live-test/<id>` | Follow or stop a live test |
| POST | `/api/ai/analyze`, `/api/ai/chat`, `/api/ai/summary` | AI analysis via Ollama |
| GET | `/api/ai/ip-risk` | AI-based IP risk assessment |

Socket.IO events pushed to the browser: `init`, `log`, `attack`, `uptime`, `system`.

## Adding a new detector

Create a file in `app/detector/attacks/` — nothing else needs to change:

```python
from detector.base_attack import BaseAttackDetector
from detector.attack_registry import register

@register
class MyDetector(BaseAttackDetector):
    name = "my_attack"

    def detect(self, features: dict) -> bool:
        return features["requests_per_ip_last_60s"] > 200

    def confidence(self, features: dict) -> float:
        return min(features["requests_per_ip_last_60s"] / 500, 1.0)
```

## Tech stack

Python · Flask · Flask-SocketIO · Docker SDK · scikit-learn · pandas · NumPy ·
matplotlib / seaborn · Chart.js · Tailwind CSS · Ollama

## Disclaimer

The live attack generator and test tools are intended **only** for your own test
environment. Do not use them against systems you do not own or have permission to test.
