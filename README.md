# Trojan Detector

Trojan Detector is a Python command-line prototype for investigating suspicious files and host activity. It combines file hashes and Windows PE metadata with process, DNS, network, and optional YARA signals, then reports an explainable risk score.

It is a defensive analysis aid, not a replacement for antivirus, endpoint detection, or a sandbox. An unknown file, process, domain, or IP is not automatically malicious. Use the tool only on systems and files you are authorized to inspect.

## What works today

- Hash files with SHA-256, SHA-1, and MD5; inspect PE files and suspicious imports.
- Optionally scan files with local YARA rules in `rules/yara/`.
- Snapshot running processes, inspect a process tree, and list active network connections.
- Resolve domains and inspect IP/subnet properties.
- Watch a directory for file create, modify, move, and delete events.
- Correlate DNS answers with connection IPs and group network connections by process through Python helpers.
- Optionally look up hashes, IPs, and domains in MongoDB intelligence, retain detection history, and submit explicitly confirmed reports.
- Calculate risk scores from explicit signals and show the reasons behind them.

Process and connection commands take snapshots; they do not run a continuous endpoint agent. Filesystem watching is continuous until stopped with Ctrl+C.

## Requirements

- Python 3.12 or newer.
- Windows, Linux, or macOS. Some process and socket details require elevated privileges and vary by operating system.
- MongoDB is optional and only needed for persistent intelligence.
- YARA and watchdog support depend on the corresponding packages being installed.

## Install

From the repository root, create and activate a virtual environment, then install the project and its listed dependencies.

### Windows PowerShell

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install -r requirements.txt
```

### Linux or macOS

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install -r requirements.txt
```

For development tools, install the `dev` extra:

```bash
python -m pip install -e ".[dev]"
```

MongoDB support is an optional package extra if you install only from `pyproject.toml`:

```bash
python -m pip install -e ".[intelligence]"
```

The repository's `requirements.txt` also includes PyMongo, watchdog, and the configured YARA package.

## Configure MongoDB (optional)

Copy `.env.example` to `.env` and set the MongoDB options. Keep credentials out of source control.

```dotenv
MONGODB_ENABLED=true
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=trojan_detector
```

The MongoDB service must be running and reachable at the configured URI. Check the connection and create the required lookup indexes with:

```bash
trojan-detector intel status
```

Without MongoDB enabled, scanning and local investigation remain available. Intelligence lookup and reporting require MongoDB.

## CLI

Run `trojan-detector --help` or `trojan-detector <command> --help` for options.

### Scan and hash files

```bash
trojan-detector scan ./path/to/file
trojan-detector hash ./path/to/file
```

`scan` hashes the file, attempts PE analysis when applicable, scans configured YARA rules when YARA is available, and prints a risk assessment. With MongoDB enabled, it also checks for a prior confirmed SHA-256 report. Scanning does not execute the file.

### Inspect processes and connections

```bash
trojan-detector monitor --top 20
trojan-detector process-tree 1234
trojan-detector connections
trojan-detector connections --external
```

`monitor` takes a process snapshot and ranks the displayed processes by CPU use. `process-tree` prints descendants for a PID. System connection visibility can be limited without administrator/root permissions.

### Investigate an IP or domain

```bash
trojan-detector investigate 8.8.8.8
trojan-detector investigate example.com
```

IP investigation reports address properties and configured subnet matches. Domain investigation resolves DNS and analyzes the returned IP addresses. A failed DNS lookup can mean the name is unavailable or the environment has no network access.

### Watch filesystem activity

```bash
trojan-detector watch-files ./directory
trojan-detector watch-files ./directory --no-recursive
```

The command requires watchdog support and runs until Ctrl+C.

### Query and report intelligence

```bash
trojan-detector intel status
trojan-detector intel lookup <sha256-or-ip-or-domain>
trojan-detector intel history --limit 25
trojan-detector intel report malicious --sha256 <64-character-sha256> --risk-score 90 --reason "Analyst-confirmed behavior" --confirmed
```

Reports can include repeated IP and domain indicators:

```bash
trojan-detector intel report suspicious --sha256 <sha256> --ip 203.0.113.10 --domain example.test --risk-score 55 --reason "Observed in an authorized investigation" --confirmed
```

Reporting requires the explicit `--confirmed` flag and a `suspicious` or `malicious` classification. Include evidence in the reason. A report is stored as history and updates searchable indicator summaries. Never submit unverified or sensitive third-party data.

## Risk scoring

The risk engine combines explainable indicators, including suspicious PE imports, high-entropy PE sections, YARA matches, process ancestry, resource use, and unexpected external destinations. Scores are clamped to 0–100 and mapped to LOW, MEDIUM, HIGH, or CRITICAL. A confirmed malicious hash match adds 100 points; a confirmed suspicious hash match adds 50.

Scores are investigation priorities, not proof of compromise. Heuristics can produce false positives and should be assessed with the surrounding evidence. The thresholds and weights are prototype defaults and need calibration against safe, representative samples.

## YARA rules

Local rules are loaded from `rules/yara/` by default. Add `.yar` or `.yara` files there, or use the Python API with an explicit rule path. If the YARA module is not installed, file scanning continues without YARA matches and logs that the feature is unavailable. A rule match is one signal in the risk assessment, not an automatic verdict.

## Python intelligence and correlation APIs

The `trojandetector.intelligence` package provides hash, IP, and domain lookup/history helpers and MongoDB persistence. Cross-source correlation helpers are in `trojandetector.behavior.correlation`; DNS answers from the DNS monitor can be matched against observed connection destinations. These helpers do not themselves provide a background event collection service.

## Project layout

```text
Trojan-Detector/
├── trojandetector/
│   ├── behavior/       # Filesystem monitoring and correlation helpers
│   ├── intelligence/   # Optional MongoDB and indicator lookups
│   ├── network/        # DNS, IP, packet, and connection utilities
│   ├── process/        # Process snapshots and ancestry
│   ├── response/       # Quarantine and termination utilities
│   ├── risk/           # Explainable risk scoring
│   └── scanner/        # Hashing, PE analysis, and YARA
├── rules/yara/         # Local YARA rules
├── tests/              # pytest suite
└── docs/               # Architecture and detection notes
```

## Development and verification

Run the test suite with:

```bash
python -m pytest -q
```

Compile the package with:

```bash
python -m compileall -q trojandetector
```

Some existing DNS tests require outbound DNS access. When running in a restricted environment, DNS-dependent failures should be distinguished from local code failures. Do not test with live malware; use benign fixtures and isolated test programs.

## Roadmap

### Implemented

- **Phase 1 — MVP:** CLI, hashing, basic file and PE scanning, process/network snapshots, DNS resolution, IP/subnet analysis, and risk reports.
- **Phase 2 — Behavioral detection foundations:** Process tree inspection, filesystem watching, YARA scanning, correlation helpers, and additional risk signals.
- **Phase 3 — Intelligence:** Optional MongoDB storage, hash/IP/domain summaries, detection history, and explicit community reporting.

### Planned

- **Phase 4 — Response:** Safer quarantine workflow, confirmation-gated process termination, incident reports, evidence collection, and recovery guidance.
- **Phase 5 — Advanced analysis:** Isolated sandbox support, dynamic analysis, behavioral baselines, broader live event correlation, and a maintained API service.

## Safety

- Do not execute unknown samples on your primary machine.
- Use an isolated, disposable VM or sandbox for dynamic analysis and restrict its network access.
- Do not terminate or quarantine a process based solely on an unknown IP or one weak indicator.
- Treat files, DNS answers, process metadata, YARA rules, and imported intelligence as untrusted data.
- Keep MongoDB credentials in environment variables or a local ignored `.env` file.

## License and author

The repository includes a `LICENSE` file. The project metadata credits Chirrayu.
