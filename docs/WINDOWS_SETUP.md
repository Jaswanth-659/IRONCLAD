# Windows Environment Setup Guide for IRONCLAD

This guide provides step-by-step instructions for deploying and running the **IRONCLAD Network Telemetry and Cryptographic Defence Engine** on Windows 10/11 or Windows Server.

---

## 1. Prerequisites

### 1.1 Python 3.11 or Newer
- Download Python from [python.org](https://www.python.org/downloads/).
- During installation, **ensure you check the box**:
  `[x] Add Python to PATH`

Verify installation in PowerShell:
```powershell
python --version
pip --version
```

---

## 2. Packet Capture Driver: Npcap (Required for Scapy Live Capture)

Scapy on Windows relies on **Npcap** to access native network interfaces and capture raw packet drivers.

1. Download the Npcap installer from [npcap.com](https://npcap.com/#download).
2. Run the installer with administrator privileges.
3. **CRITICAL INSTALLATION OPTION**:
   - Check `[x] Install Npcap in WinPcap API-compatible Mode`.
   - Optional: Check `[x] Support raw 802.11 traffic` if analyzing WiFi headers.
4. Finish installation. (A system reboot is recommended if upgrading from older WinPcap drivers).

> [!NOTE]
> Offline PCAP analysis (reading pre-recorded `.pcap` or `.pcapng` files) works natively via Scapy without Npcap. Npcap is only required when performing live interface packet sniffing on Windows.

---

## 3. Optional: Wireshark / TShark (For PyShark Integration)

PyShark is an optional component of IRONCLAD that interfaces with `tshark.exe` (Wireshark's CLI dissector) for deep application-layer protocol parsing.

1. Download and install Wireshark from [wireshark.org](https://www.wireshark.org/download.html).
2. By default, Wireshark installs `tshark.exe` into:
   `C:\Program Files\Wireshark\tshark.exe`
3. Add `C:\Program Files\Wireshark` to your Windows System `PATH`, or set the environment variable:
   ```powershell
   [System.Environment]::SetEnvironmentVariable("TSHARK_PATH", "C:\Program Files\Wireshark\tshark.exe", "User")
   ```

---

## 4. Virtual Environment Setup (PowerShell)

### Step 4.1: Adjust PowerShell Execution Policy (One-Time Setup)
By default, Windows blocks script execution (`Activate.ps1`). Enable script execution for your user account:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force
```

### Step 4.2: Create and Activate the Virtual Environment
Navigate to the IRONCLAD repository root:

```powershell
cd E:\2030_PROJECTS\IRONCLAD_2

# Create virtual environment named '.venv'
python -m venv .venv

# Activate the virtual environment
.venv\Scripts\Activate.ps1
```

Once activated, your command prompt will be prefixed with `(.venv)`.

---

## 5. Dependency Installation

### Step 5.1: Upgrade Package Manager
```powershell
python -m pip install --upgrade pip setuptools wheel
```

### Step 5.2: Install Core Dependencies
```powershell
pip install -r requirements.txt
```

### Step 5.3: Install Development & Testing Dependencies
```powershell
pip install -r requirements-dev.txt
```

### Step 5.4: Install IRONCLAD in Editable Mode
```powershell
pip install -e .
```

---

## 6. Verification and Validation

### Step 6.1: Run the Full Pytest Suite
Execute all unit and integration tests:

```powershell
pytest -v
```

Expected output:
```text
tests/test_anomaly.py .................
tests/test_features.py ................
tests/test_graph.py ..................
tests/test_ingestion.py ...............
tests/test_parsing.py .................
tests/test_pipeline.py ................
tests/test_risk.py ....................
tests/test_stats.py ...................
========================= 28 passed in < 1.0s =========================
```

### Step 6.2: Run the Synthetic Telemetry Audit CLI
Generate a synthetic network capture and audit it through the end-to-end pipeline:

```powershell
python scripts/run_engine.py --generate-synthetic
```

---

## 7. Troubleshooting Windows-Specific Issues

| Issue | Cause | Resolution |
| :--- | :--- | :--- |
| `Activate.ps1 cannot be loaded because running scripts is disabled` | Restricted PowerShell execution policy | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in your session. |
| `WARNING: No libpcap provider available !` | Npcap is missing or not installed in WinPcap compatibility mode | Install Npcap with the "WinPcap API-compatible Mode" checkbox enabled. |
| `TSharkNotFoundException` | `tshark.exe` is not in System PATH | Set `$env:TSHARK_PATH = "C:\Program Files\Wireshark\tshark.exe"`. |
| `ModuleNotFoundError: No module named 'ironclad'` | Current directory not in `sys.path` | Run `pip install -e .` from the project root. |
