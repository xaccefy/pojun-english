# FOFA asset search tool

[English Version](#english-version)

## Features
- FOFA asset information lookup
- Combined multi-condition queries (domain/IP/port/page content, etc.)
- Security risk assessment suggestions
- Formatted bulk output

## Stack
- Python 3.12
- FastAPI framework
- httpx async HTTP client
- FOFA official API

## Installation
```bash
# install uv
# install with pipx (isolated env recommended)
pip install uv

# verify the install
uv --version
# clone the code
git clone https://github.com/hnking-star/fofa_MCP.git

# configure mcpServers in Cursor or another client
"mcpServers": {
    "fofa-mcp-server": {
      "command": "uv",
      "args": [
        "run",
        "--active",
        "F:\\ai\\mcp\\fofamcp\\fofa\\fofa.py"
      ]
    }
}

Configure the key
![image](https://github.com/user-attachments/assets/0e5a01a9-06bb-436f-810a-84314121df06)


```

## Usage examples
```python
![image](https://github.com/user-attachments/assets/b8fdccc5-6d0e-4573-add4-4f6707903b7c)

from fofa import get_alerts

# basic query
results = await get_alerts(domain="example.com")

# combined query
results = await get_alerts(
    ip="192.168.1.1",
    port="80,443",
    body="Apache Tomcat"
)
```

## Security notes
1. Keep the API key safe
2. Follow the FOFA API terms of use
3. Never scan without authorization
4. Configure request rate limits

## License
[MIT License](LICENSE)

---

<a name="english-version"></a>
# FOFA Asset Search Tool

## Features
- FOFA asset information retrieval
- Multi-condition combined query
- Security risk assessment
- Batch result formatting

## Tech Stack
- Python 3.12
- FastAPI Framework
- httpx Async Client
- FOFA Official API

## Installation
```bash
# Create virtual environment
python -m venv .venv

# Activate environment
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage Example
```python
from fofa import get_alerts

# Basic query
results = await get_alerts(domain="example.com")

# Advanced query
results = await get_alerts(
    ip="192.168.1.1",
    port="80,443",
    body="Apache Tomcat"
)
```

## Security Notice
1. Keep API keys secure
2. Comply with FOFA API terms
3. Unauthorized scanning prohibited
4. Recommended request rate limiting

## License
[MIT License](LICENSE)
