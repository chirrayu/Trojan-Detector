# Trojan Detector

A Python-based **behavioral Trojan detection and investigation tool** designed to identify suspicious software by correlating file characteristics, process activity, DNS resolution, network connections, and other runtime indicators.

> **Project status:** Early development / prototype

This project is intentionally different from a traditional signature-only antivirus. An unknown IP, domain, process, or file is **not automatically considered malicious**. Instead, unusual behavior acts as a signal that triggers deeper investigation and risk scoring.

---

## 🎯 Project Goal

The goal is to build a lightweight CLI security tool that can:

- Analyze suspicious executables before execution.
- Calculate and track file hashes.
- Inspect Windows PE files and suspicious imports.
- Monitor running processes and parent/child relationships.
- Observe DNS requests and network connections.
- Correlate processes with destination IPs and domains.
- Compare observed addresses against expected networks/subnets where applicable.
- Detect behavioral anomalies.
- Assign a risk score based on multiple signals.
- Warn the user before potentially dangerous execution.
- Quarantine or terminate a suspicious process after user confirmation.
- Store confirmed detections in MongoDB for future intelligence.
- Reuse previous detection information to warn about known files.

The core philosophy is:

```text
Unknown ≠ Malicious

Unknown
   ↓
Investigation
   ↓
Behavior Correlation
   ↓
Risk Assessment
   ↓
User Decision / Response
```

---

## 🧠 Detection Philosophy

Traditional detection often relies heavily on known malware signatures or hashes.

This project focuses on **behavioral correlation**.

For example:

```text
Suspicious executable
        ↓
Unexpected child process
        ↓
DNS request
        ↓
Unexpected external IP
        ↓
Connection over network
        ↓
Additional suspicious behavior
        ↓
Risk score increases
        ↓
User warning
```

An unusual IP by itself should not result in an immediate malware verdict.

Instead, the system combines multiple indicators before making a recommendation.

---

## 🏗️ High-Level Architecture

```text
                         ┌──────────────────────┐
                         │      CLI Interface   │
                         │ scan / monitor /     │
                         │ investigate / kill   │
                         └──────────┬───────────┘
                                    │
                         ┌──────────▼───────────┐
                         │   Detection Engine   │
                         └──────────┬───────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
       ┌──────▼──────┐      ┌──────▼──────┐      ┌──────▼──────┐
       │ File / PE   │      │   Process   │      │   Network   │
       │ Analysis    │      │ Monitoring  │      │ Monitoring  │
       └──────┬──────┘      └──────┬──────┘      └──────┬──────┘
              │                    │                    │
              │             ┌──────▼──────┐             │
              │             │     DNS     │             │
              │             │ Correlation │             │
              │             └──────┬──────┘             │
              │                    │                    │
              └────────────────────┼────────────────────┘
                                   │
                         ┌─────────▼─────────┐
                         │ Correlation Engine │
                         └─────────┬─────────┘
                                   │
                         ┌─────────▼─────────┐
                         │    Risk Engine    │
                         └─────────┬─────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    │                             │
                 Low Risk                    Suspicious
                    │                             │
                 Continue                    Investigate
                                                  │
                                      ┌───────────┴───────────┐
                                      │                       │
                                  Quarantine              Terminate
                                      │                       │
                                      └───────────┬───────────┘
                                                  │
                                           MongoDB Intel
```

---

## 🛠️ Technology Stack

### Core

| Component | Technology | Link |
|---|---|---|
| Language | Python 3.12+ | https://www.python.org/ |
| CLI | Typer | https://typer.tiangolo.com/ |
| Terminal UI | Rich | https://rich.readthedocs.io/en/latest/ |
| Process monitoring | psutil | https://psutil.readthedocs.io/en/latest/ |
| Packet/network analysis | Scapy | https://scapy.readthedocs.io/en/latest/ |
| DNS analysis | dnspython | https://dnspython.readthedocs.io/en/latest/ |
| IP/subnet analysis | Python `ipaddress` | https://docs.python.org/3/library/ipaddress.html |
| File monitoring | watchdog | https://python-watchdog.readthedocs.io/en/stable/ |
| Hashing | Python `hashlib` | https://docs.python.org/3/library/hashlib.html |
| PE analysis | pefile | https://pefile.readthedocs.io/en/latest/ |
| Binary analysis | LIEF | https://lief.re/doc/latest/index.html |
| Rule-based detection | YARA / yara-python | https://yara.readthedocs.io/en/latest/ |
| Database | MongoDB | https://www.mongodb.com/docs/ |
| MongoDB driver | PyMongo | https://pymongo.readthedocs.io/en/stable/ |
| API | FastAPI | https://fastapi.tiangolo.com/ |
| API server | Uvicorn | https://uvicorn.dev/ |
| Configuration | Pydantic | https://pydantic.dev/docs/ |
| Testing | pytest | https://docs.pytest.org/en/stable/ |
| Linting | Ruff | https://docs.astral.sh/ruff/ |
| Formatting | Black | https://black.readthedocs.io/en/stable/ |

---

## 📦 Installation

### 1. Clone the repository

```bash
git https://github.com/chirrayu/Trojan-Detector
cd trojan-detector
```

### 2. Create a virtual environment

Windows:

```bash
python -m venv .venv
.venv\Scripts\activate
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Install development dependencies

```bash
pip install pytest ruff black mypy
```

---

## ⚙️ Configuration

Configuration should be kept outside the detection logic.

Example:

```yaml
monitor_network: true
monitor_processes: true
monitor_files: true

risk_threshold: 75

mongodb_enabled: true

mongodb_uri: "mongodb://localhost:27017"
database_name: "trojan_detector"
```

Sensitive credentials should be supplied through environment variables rather than committed to Git.

Example:

```text
MONGODB_URI=mongodb://localhost:27017
```

---

# 🚀 CLI Usage

The planned CLI interface is:

```bash
trojan-detector scan <file>
```

Scan a file before execution.

```bash
trojan-detector monitor
```

Start continuous behavioral monitoring.

```bash
trojan-detector investigate <ip>
```

Investigate a network destination.

```bash
trojan-detector hash <file>
```

Calculate the file's SHA-256 hash.

```bash
trojan-detector quarantine <file>
```

Move a suspicious file into a controlled quarantine location.

```bash
trojan-detector kill --pid <PID>
```

Terminate a suspicious process after confirmation.

---

# 🔍 Detection Pipeline

## 1. File Identification

The system calculates a cryptographic hash:

```text
File
 ↓
SHA-256
 ↓
Local / Community Intelligence
```

SHA-256 is used as the primary file identifier.

File names are **not** considered reliable identifiers because malware can easily rename itself.

---

## 2. Static Analysis

Before execution, the detector can inspect executable structure.

For Windows PE files, information may include:

- PE headers
- Sections
- Entry point
- Imported DLLs
- Imported functions
- File characteristics
- Entropy
- Digital signature information
- Suspicious strings
- YARA matches

Static analysis produces signals rather than an automatic verdict.

---

## 3. Process Monitoring

The detector monitors:

```text
PID
Process name
Executable path
Parent process
Child processes
CPU usage
Memory usage
Open files
Network connections
```

Example behavioral chain:

```text
document.exe
      ↓
powershell.exe
      ↓
unknown.exe
      ↓
external network connection
```

A chain like this can contribute to the overall risk score.

---

## 4. DNS Correlation

DNS information is correlated with network activity:

```text
Process
   ↓
DNS request
   ↓
Domain
   ↓
Resolved IP
   ↓
Actual network connection
```

This helps prevent simplistic IP-only detection.

---

## 5. Network Monitoring

The detector can observe network activity such as:

```text
Source IP
Destination IP
Source port
Destination port
Protocol
DNS activity
TCP connections
UDP traffic
```

The system can compare observed destinations with known or expected network ranges.

For example:

```text
Expected network:
10.0.0.0/24

Observed:
10.0.0.45

Result:
Expected subnet
```

versus:

```text
Expected network:
10.0.0.0/24

Observed:
185.x.x.x

Result:
External destination → investigate
```

An external destination is **not automatically malicious**.

---

# 🧮 Risk Engine

The risk engine combines multiple signals.

Example:

```text
Known malicious hash          +100
Suspicious PE imports          +15
YARA detection                 +25
Unexpected DNS                 +10
Unexpected external IP         +10
Suspicious child process       +20
Persistence behavior           +25
Unusual file modification      +10
```

Example:

```text
Risk Score: 72/100

Classification:
HIGH RISK

Reasons:
- Suspicious child process
- Unexpected external destination
- Suspicious PE imports
- Unusual DNS behavior
```

The exact scoring system will be calibrated during testing.

---

# 🗄️ MongoDB Intelligence Layer

MongoDB is **not the detection engine**.

It acts as the system's long-term intelligence and history layer.

Potential collections:

```text
files
detections
network_events
domains
ip_addresses
incidents
```

Example detection record:

```json
{
  "sha256": "example-sha256",
  "filename": "update.exe",
  "risk_score": 87,
  "classification": "suspicious",
  "behaviors": [
    "unexpected_network_connection",
    "suspicious_child_process"
  ],
  "domains": [
    "example.com"
  ],
  "ips": [
    "185.x.x.x"
  ]
}
```

Future users can then receive a warning when the same file hash is encountered again.

```text
New File
   ↓
SHA-256
   ↓
MongoDB Intelligence
   ↓
Previously detected?
   ↓
YES
   ↓
Warn User
```

---

# 🌐 API Layer

FastAPI can eventually expose intelligence services.

Planned endpoints:

```text
POST /api/v1/check/hash
POST /api/v1/report/detection

GET /api/v1/intelligence/hash/{sha256}
GET /api/v1/intelligence/ip/{ip}
GET /api/v1/intelligence/domain/{domain}
```

The API is optional during the initial prototype.

The local detection engine should remain functional without requiring a remote server.

---

# 📁 Project Structure

```text
trojan-detector/
│
├── trojandetector/
│   ├── cli.py
│   ├── config.py
│   ├── logger.py
│   ├── models.py
│   │
│   ├── scanner/
│   │   ├── file_scanner.py
│   │   ├── hash_scanner.py
│   │   ├── pe_analyzer.py
│   │   └── yara_engine.py
│   │
│   ├── network/
│   │   ├── packet_monitor.py
│   │   ├── dns_monitor.py
│   │   ├── ip_analyzer.py
│   │   └── connection_tracker.py
│   │
│   ├── process/
│   │   ├── process_monitor.py
│   │   ├── process_tree.py
│   │   └── process_analyzer.py
│   │
│   ├── behavior/
│   │   ├── behavior_engine.py
│   │   └── anomaly_detector.py
│   │
│   ├── risk/
│   │   └── risk_engine.py
│   │
│   ├── intelligence/
│   │   ├── hash_intelligence.py
│   │   ├── ip_intelligence.py
│   │   └── database.py
│   │
│   ├── response/
│   │   ├── quarantine.py
│   │   └── process_terminator.py
│   │
│   └── api/
│       └── server.py
│
├── rules/
│   └── yara/
│
├── tests/
│
├── docs/
│
├── requirements.txt
├── pyproject.toml
├── README.md
└── LICENSE
```

---

# 🧪 Testing Strategy

Testing should be performed with **safe test samples and isolated environments**.

The project should not rely on executing real malware on a development machine.

Testing categories:

### Unit Tests

Test:

- Hash generation
- IP/subnet matching
- DNS correlation
- Risk calculations
- File classification
- Database operations

### Integration Tests

Test:

```text
File → Scanner → Risk Engine
```

```text
Process → Network → Correlation → Risk Engine
```

```text
Detection → MongoDB
```

### Behavioral Tests

Use controlled test programs that intentionally perform benign behaviors such as:

- Creating child processes
- Making DNS requests
- Connecting to a test server
- Creating files
- Modifying files

This allows the detector to be tested without deploying real malware.

---

# 🔐 Security Considerations

This project is intended for defensive security research and authorized environments.

Important principles:

- Do not execute unknown malware directly on your primary machine.
- Use an isolated VM or sandbox for dynamic analysis.
- Restrict network access during malware analysis.
- Do not automatically terminate processes solely because an IP is unknown.
- Require user confirmation before destructive response actions where appropriate.
- Store secrets such as MongoDB credentials in environment variables.
- Validate all data received from external sources.
- Treat third-party threat intelligence as untrusted input.
- Keep detection and response logic separate.

---

# 🛣️ Development Roadmap

## Phase 1 — MVP

- [x] CLI
- [x] File hashing
- [x] Basic file scanner
- [x] PE analysis
- [x] Process monitoring
- [x] DNS monitoring
- [x] Network connection tracking
- [x] IP/subnet correlation
- [x] Basic risk engine
- [x] Terminal alerts

## Phase 2 — Behavioral Detection

- [ ] Process tree analysis
- [ ] Parent/child process correlation
- [ ] File system monitoring
- [ ] DNS-to-IP correlation
- [ ] Network-to-process correlation
- [ ] YARA integration
- [ ] Improved risk scoring

## Phase 3 — Intelligence

- [ ] MongoDB integration
- [ ] Hash intelligence
- [ ] IP intelligence
- [ ] Domain intelligence
- [ ] Historical detections
- [ ] Community detection reporting

## Phase 4 — Response

- [ ] Quarantine
- [ ] Safe process termination
- [ ] Incident reports
- [ ] Evidence collection
- [ ] Recovery workflow

## Phase 5 — Advanced Analysis

- [ ] Isolated sandbox
- [ ] Dynamic analysis
- [ ] Behavioral baselines
- [ ] Anomaly detection
- [ ] Advanced correlation
- [ ] API service
- [ ] Optional Tkinter GUI

---

# 🎯 MVP Definition

The first successful version should be able to do this:

```text
                    Suspicious File
                           │
                           ▼
                       SHA-256
                           │
                           ▼
                     Static Scan
                           │
                           ▼
                     File Executed
                           │
                           ▼
                  Process Monitoring
                           │
                           ▼
                     DNS Request
                           │
                           ▼
                    IP Resolution
                           │
                           ▼
                  Network Connection
                           │
                           ▼
                  Behavior Correlation
                           │
                           ▼
                      Risk Score
                           │
                 ┌─────────┴─────────┐
                 ▼                   ▼
              LOW RISK           SUSPICIOUS
                                     │
                                     ▼
                                  ALERT
                                     │
                                     ▼
                              User Decision
```

If this pipeline works reliably, the project already has a strong foundation.

---

# 📌 Future Vision

The long-term goal is to evolve the project from a simple scanner into a **local behavioral security agent with shared threat intelligence**.

The detector should eventually be able to answer:

> **"What is this program doing, what resources is it touching, where is it communicating, how did it get here, and does that behavior match what we expect?"**

rather than simply:

> **"Does this file match a known malware signature?"**

---

## ⚠️ Disclaimer

This project is intended for cybersecurity education, defensive research, malware analysis in controlled environments, and authorized security testing.

Never analyze or execute malware on systems you do not own or have explicit authorization to test.

---

## 👨‍💻 Author

**Chirrayu**

B.Tech Computer Science Engineering  
Cyber Security

Built with Python, curiosity, and an unhealthy distrust of suspicious `.exe` files.
