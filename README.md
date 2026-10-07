# NetSentinel

**NetSentinel** is a local network monitoring and anomaly-detection tool built with Python Flask and a simple web dashboard.

It captures local network traffic, analyzes packets, detects unusual patterns, and shows alerts and investigation scores.

## Project Structure

```text
NetSentinel/
├── backend/
│   ├── main.py       # Main local server
│   ├── models.py     # Data models
│   ├── capture.py    # Packet capture
│   ├── detector.py   # Detection rules
│   ├── parser.py     # CSV/Wireshark parser
│   └── report.py     # Report generation
│
├── web/
│   ├── index.html    # Dashboard
│   ├── script.js     # Frontend logic
│   └── styles.css    # Dashboard styling
│
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

## Run Locally — Windows 11

### 1. Install prerequisites

- Python 3.10+
- Git
- Npcap (required for live packet capture)

### 2. Clone the repository

```powershell
git clone https://github.com/YOUR-USERNAME/NetSentinel.git
cd NetSentinel
```

### 3. Create virtual environment

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 5. Start NetSentinel

```powershell
cd backend
python main.py
```

Open:

```text
http://127.0.0.1:8000
```

## GitHub Push

```powershell
git init
git add .
git commit -m "Initial NetSentinel release"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/NetSentinel.git
git push -u origin main
```

## Notes

- NetSentinel is designed for **local/educational network analysis**.
- Live packet capture requires appropriate permissions and a working packet-capture driver such as Npcap on Windows.
- Generated reports are kept locally and are not committed to Git.
- The server listens on `127.0.0.1:8000` by default.

## Disclaimer

Use NetSentinel only on networks and systems you own or are authorized to monitor.
