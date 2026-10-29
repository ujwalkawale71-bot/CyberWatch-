# CYBERWATCH

Unified Web & Browser Threat Detection Platform

## 1. Project overview
CyberWatch is a comprehensive cybersecurity platform designed to detect, analyze, and mitigate threats across the web.

## 2. Architecture overview
- **Frontend (Web):** React + Vite
- **Backend (API):** Node.js + Express
- **AI Service:** Python + FastAPI
- **Browser Extension:** Chrome Manifest V3
- **Database:** MongoDB

## 3. Technology stack
- TypeScript, Python
- React, Tailwind CSS
- Node.js, Express, MongoDB
- FastAPI, Pydantic

## 4. Repository structure
- `apps/web`: Frontend application
- `apps/api`: Backend application
- `apps/ai-service`: AI threat analysis service
- `apps/extension`: Browser extension
- `packages/shared`: Shared types and constants

## 5. Local development prerequisites
- Node.js v18+
- Python 3.10+
- Docker & Docker Compose

## 6. Environment setup
Copy `.env.example` to `.env` in the root directory.

## 7. How to run the project
Start the database:
```bash
docker-compose up -d
```
Install dependencies:
```bash
npm install
```
Start both web and api servers together:
```bash
npm run dev
```

Or start servers individually in dedicated terminals:
```bash
npm run dev:api    # Start only API (port 5000 with nodemon auto-restart)
npm run dev:web    # Start only Web frontend (port 5173 with Vite)
```

For AI Service:
```bash
cd apps/ai-service
python -m venv venv
source venv/bin/activate # or venv\Scripts\activate on Windows
pip install -r requirements.txt
python main.py
```

## 8. How to run tests
```bash
npm test
```

## 9. How to run linting
```bash
npm run lint
```

## 10. Development roadmap
- Phase 1: Project Foundation (Current)
- Phase 2: Core Scanning Engine (Future)
- Phase 3: AI Threat Analysis (Future)
- Phase 4: Browser Extension (Future)
- Phase 5: Dashboard and Reporting (Future)
