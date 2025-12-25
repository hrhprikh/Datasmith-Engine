# Datasmith Engine

AI-powered security log analyzer with threat detection, attack visualization, and PDF report generation.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0-green.svg)
![React](https://img.shields.io/badge/React-18-61DAFB.svg)

## Features

- 📊 **Multi-format Log Analysis** - Supports Web (Apache/Nginx), SSH, FTP, and SMTP logs
- 🔍 **Threat Detection** - Identifies brute force attacks, suspicious IPs, and anomalous patterns
- 🗺️ **Attack Visualization** - Interactive attack maps and statistical charts
- 📄 **PDF Reports** - Generate comprehensive security reports
- 🤖 **AI Assistant** - Get AI-powered insights and recommendations
- 🔄 **Data Converter** - Convert between different log formats
- 📜 **Analysis History** - Track and review past analyses

## Installation

### Backend Setup

```bash
# Clone the repository
git clone https://github.com/hrhprikh/Datasmith-Engine.git
cd Datasmith-Engine

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Frontend Setup

```bash
cd frontend
npm install
```

## Usage

### Start the Backend Server

```bash
python app.py
```

### Start the Frontend (Development)

```bash
cd frontend
npm start
```

The application will be available at `http://localhost:3000`

## Supported Log Formats

| Log Type | Format |
|----------|--------|
| Web | Apache/Nginx combined format |
| SSH | OpenSSH authentication logs |
| FTP | vsftpd/ProFTPD logs |
| SMTP | Email server authentication logs |

## Project Structure

```
Datasmith-Engine/
├── app.py              # Flask backend server
├── llm.py              # AI/LLM integration
├── requirements.txt    # Python dependencies
├── frontend/           # React frontend
│   └── src/
│       └── components/
│           ├── AIAssistant/
│           ├── AttackMap/
│           ├── DataConverter/
│           ├── History/
│           ├── Navbar/
│           └── SecurityReport/
├── static/             # Static assets
├── templates/          # HTML templates
└── history/            # Analysis history storage
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/analyze` | POST | Analyze uploaded log file |
| `/report` | POST | Generate PDF security report |
| `/history` | GET | Get analysis history |
| `/convert` | POST | Convert log formats |

## Technologies

- **Backend**: Python, Flask, Pandas, Matplotlib, ReportLab
- **Frontend**: React, JavaScript
- **AI**: LLM integration for intelligent analysis

## License

MIT License

## Author

Harsh Parikh
