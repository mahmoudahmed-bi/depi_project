# Email Security Scanner v1

A simple email inspection tool that detects **malicious URLs** and **suspicious file attachments** using the **VirusTotal API**.  
It extracts URLs and attachments from emails, submits them to VirusTotal for analysis, and generates a clean/simple security report.

---

## Features
- Extracts URLs from email body
- Checks URL reputation using VirusTotal v3 API
- Scans file attachments for malware
- Classifies emails as **clean**, **suspicious**, or **malicious**
- Command-line usage and modular code for integration
- Ready for integration into desktop apps or backend services

---

## Requirements
- Python 3.8+
- VirusTotal API Key (free or premium): https://www.virustotal.com
- Dependencies listed in `requirements.txt`

---

## Setup

### 1. Clone Repository
```bash
git clone https://github.com/mahmoudahmed-bi/depi_project.git
cd depi_project
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Set VirusTotal API Key
```bash
export VT_API_KEY="YOUR_API_KEY"
```
```powershell
setx VT_API_KEY="YOUR_API_KEY"
```

### 4. Usage
```bash
python3 scanner.py https://example.com
```

### 5. Expected output
```ini
malicious=6 suspicious=1 stats={'harmless': 70, 'malicious': 6, 'suspicious': 1, 'undetected': 13, 'timeout': 0}
```
