# 🛡️ Advanced Intrusion Detection System (IDS)

A production-grade Intrusion Detection System that detects real cyber threats in real-time.

## Features ✨

- **SQL Injection Detection** - Detects UNION-based and blind SQL injection attempts
- **XSS Detection** - Identifies Cross-Site Scripting attacks
- **Real-time Analysis** - Analyzes payloads instantly
- **Alert Storage** - Stores all detected threats in database
- **REST API** - Easy integration with other tools

## Quick Start

```bash
# Activate Python environment
.\venv\Scripts\Activate.ps1

# Run the API
python app.py

# Test it
curl http://localhost:8000/health
```

## Test Detection

```powershell
# Test SQL Injection
$payload = @{
    payload = "SELECT * FROM users WHERE id=1 OR 1=1"
    src_ip = "192.168.1.100"
    dst_ip = "10.0.0.1"
    src_port = 54321
    dst_port = 80
} | ConvertTo-Json

curl -UseBasicParsing -Method POST http://localhost:8000/analyze `
  -Headers @{"Content-Type"="application/json"} `
  -Body $payload
```

## API Endpoints

- `GET /health` - Health check
- `POST /analyze` - Analyze payload for threats
- `GET /alerts` - Get all detected alerts
- `GET /stats` - Get alert statistics

## Architecture
## Tech Stack

- **Python 3.14** - Threat detection logic
- **FastAPI** - High-performance API framework
- **SQLite** - Alert storage
- **Go** - (Coming) High-speed packet capture

## Roadmap

- [x] SQL Injection detection
- [x] XSS detection
- [x] REST API with FastAPI
- [x] Alert database storage
- [ ] Go packet sniffer
- [ ] React dashboard
- [ ] Docker containerization
- [ ] Kubernetes deployment
- [ ] ML anomaly detection

## Author

**Aryan Patil** - Sheffield University

## License

MIT
