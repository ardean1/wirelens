```
 __        ___          _                   
 \ \      / (_)_ __ ___| |    ___ _ __  ___ 
  \ \ /\ / /| | '__/ _ \ |   / _ \ '_ \/ __|
   \ V  V / | | | |  __/ |__|  __/ | | \__ \
    \_/\_/  |_|_|  \___|_____\___|_| |_|___/
         See what your PC is talking to
```

# WireLens


**Free for everyone to use.** Optional donations help cover Ardean’s costs — this is not a paid product and not a cloud security service.

**See what *this computer* is talking to** — live TCP/UDP connections, reverse-DNS names, and plain-English suspicion flags — in a dark local dashboard. No SIEM, no subscription, no sending your traffic to someone else’s cloud.

## Why it’s useful

- **Catch surprises** — unknown processes, odd remote ports, CGNAT/cloud endpoints, short-lived connection bursts
- **Farm / home / IT** — one host visibility when you do not want a full IDS appliance
- **Transparent rules** — every flag is explained (`GET /api/rules`); no fake “threat scores”
- **Works offline-first** — binds **localhost only** by default (`127.0.0.1:8787`)
- **Demo mode** — try the UI without admin privileges

**Not a perimeter IDS.** WireLens only sees what this host can see via its own sockets (`psutil`). Heuristics are for triage, not malware verdicts.

## Windows — download, run, and close (start here)

### 1. Download
1. Open the GitHub page in your browser.
2. Click the green **Code** button.
3. Click **Download ZIP**.
4. Save the ZIP somewhere easy, like your **Desktop** or **Downloads**.

### 2. Extract and keep the folder
1. Right-click the ZIP → **Extract All...** (or open it and drag the inner folder out).
2. Put the extracted folder somewhere permanent, for example your Desktop:
   - Desktop\wirelens
3. Open that folder until you see **start.bat**, **start-live.bat**, and the **wirelens** folder.

### 3. One-time: install Python (if you do not have it)
1. Install **Python 3.10 or newer** from https://www.python.org/downloads/
2. On the installer, check **Add python.exe to PATH**.
3. Finish install, then continue below.

### 4. Launch
1. Double-click **start.bat** for **demo mode** (safe first try — sample traffic so you can learn the screens).
2. Or double-click **start-live.bat** for **real** connections on this PC.
3. A black **Command Prompt** window opens — **leave it open** (first run may install packages into a local `.venv` folder; wait until it finishes).
4. Open a browser to http://127.0.0.1:8787/

### 5. Close properly
1. Close the **browser tab** for WireLens (optional but tidy).
2. Click the **Command Prompt** window that is running WireLens.
3. Press **Ctrl+C**, or click the **X** on that window.
4. That stops the dashboard. To use it again later, double-click **start.bat** or **start-live.bat** again.

**Tips:** Keep the folder; do not run from inside the ZIP. If the window closes immediately with an error, install/reinstall Python with PATH checked, then retry.

### Advanced (optional)
```bash
python -m venv .venv
# Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m wirelens --demo
python -m wirelens
```


## Cost / API keys

**No cloud API keys. No Grok Bot / Cursor session is used when you run WireLens.** It only inspects the machine it runs on. Other people running copies do **not** create usage charges for the author.

## Optional support

Tips are **100% optional**.

| Method | Handle |
|--------|--------|
| Cash App | [$AnthonyDean16](https://cash.app/$AnthonyDean16) |

## Features

- Live connections: addresses, ports, protocol, state, process name/PID/exe, first/last seen
- DNS panel: reverse-DNS cache with TTL
- Suspicion rules: `raw_ip`, `many_short`, `unusual_port`, `cgnat_or_public`, `blocklist_hit`
- Search / “suspicious only” / detail drawer / WebSocket ~2s / CSV export
- Optional blocklist file (`blocklists/example.txt`)

## API

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Liveness + counts |
| `GET /api/connections` | Connection snapshot |
| `GET /api/dns` | Reverse-DNS cache |
| `GET /api/rules` | Suspicion rule catalog |
| `GET /api/export.csv` | CSV download |
| `WS /ws` | Live snapshots |
| `GET /` | Dashboard |

## Tests

```bash
pip install -r requirements.txt
pytest
```

## License

App code: [MIT](LICENSE).

## Credits

Built by **Tony Dean** (Ardean).

Assisted by **Grok Bot** — [https://x.ai/bot](https://x.ai/bot) · download: [https://cursor.com/download/bot](https://cursor.com/download/bot)
