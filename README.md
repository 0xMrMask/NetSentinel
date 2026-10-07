# NetSentinel

**NetSentinel** is a local network monitoring and anomaly-detection tool built with Python Flask and a simple web dashboard.

It captures local network traffic, analyzes packets, detects unusual patterns, and shows alerts and investigation scores. The dashboard can optionally be shared remotely through a **Cloudflare Tunnel (`cloudflared`)**.

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
- cloudflared (optional, only for remote access)

### 2. Clone the repository

```powershell
git clone https://github.com/RudraPateL-003/NetSentinel.git
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

Open PowerShell **as Administrator** if you want live packet capture.

```powershell
cd backend
python main.py
```

Open:

```text
http://127.0.0.1:8000
```

## Remote Access with Cloudflare Tunnel (cloudflared)

A Cloudflare Tunnel lets you open the dashboard from another device without opening router ports. NetSentinel keeps listening on `127.0.0.1:8000`; `cloudflared` forwards traffic to it.

> **Security warning:** the dashboard shows information about your network. The tunnel link is public, so share it only with people you trust and stop the tunnel when you are done.

### 1. Install cloudflared (easy method)

1. Open the [Cloudflare downloads page](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/) and download the **Windows 64-bit MSI** (`cloudflared-windows-amd64.msi`).
2. Double-click the `.msi` file and finish the installer. (Moving it to a folder like `C:\Cloudflared\bin\` first is optional.)
3. Close all PowerShell windows, open a new one, and verify:

```powershell
cloudflared --version
```

If it says "not recognized", restart your PC so the PATH update applies.

> `cloudflared` does not auto-update on Windows. Re-download the MSI occasionally to get the latest version.

### 2. Start a quick tunnel (temporary, no account needed)

**Window 1** (PowerShell as Administrator): start NetSentinel.

```powershell
cd NetSentinel\backend
python main.py
```

**Window 2**: start the tunnel.

```powershell
cloudflared tunnel --url http://127.0.0.1:8000
```

After a few seconds cloudflared prints a random `https://<random-words>.trycloudflare.com` URL. Open it from any device. Press `Ctrl+C` to stop the tunnel; the URL stops working and a new one is generated next time.

Anyone with the link can see the dashboard. Use this for quick demos and testing only.

## Troubleshooting

- **Error 502 / Bad gateway:** NetSentinel is not running, or not on port 8000. Start `python main.py` first.
- **No packets captured:** Install Npcap and run the terminal as Administrator.
- **`cloudflared` not recognized:** Close and reopen PowerShell after installing.

## Notes

- NetSentinel is designed for **local/educational network analysis**.
- Live packet capture requires appropriate permissions and a working packet-capture driver such as Npcap on Windows.
- Generated reports are kept locally and are not committed to Git.
- The server listens on `127.0.0.1:8000` by default.

## Disclaimer

Use NetSentinel only on networks and systems you own or are authorized to monitor.
