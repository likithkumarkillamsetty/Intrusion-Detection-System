# Lightweight Intrusion Detection System (IDS) - Dashboard Edition

A production-ready Full-Stack Intrusion Detection System built for an academic project, featuring a React-based interactive cybersecurity dashboard and a lightweight Python (Flask + Scapy) detection engine.

## Core Features

- **Dashboard UI**: Modern, sleek, dark-themed dashboard updating mock or physical system traffic every 2.5 seconds.
- **Rules Engine**:
  - SYN Flood Detection (Anomaly/Behavioral)
  - Port Scan Detection (Anomaly/Behavioral)
  - Disallowed Port Access (Signature)
  - Blacklisted IPs (Signature)
- **Hybrid Capture State**: Operates gracefully via real `scapy` packet sniffing or falls back to an internal **Simulator** to ensure the demonstration works flawlessly even in restricted deployment environments (e.g., Render, Vercel).

---

## Project Structure

```text
/
├── backend/
│   ├── app.py           # Flask entry point and REST API
│   ├── detector.py      # Core evaluation engine 
│   ├── simulator.py     # Generates mock data when Scapy isn't available
│   ├── signatures.py    # List of recognized bad IPs and ports
│   └── logger.py        # Logs events to ids_alerts.log natively
│
├── frontend/
│   ├── src/             # Vite + React interface
│   │   ├── App.jsx      # Dashboard logic & API interactions
│   │   ├── App.css      # Custom card-based layout
│   │   └── index.css    # Premium dark theme layout configurations
│   ├── package.json     # Frontend dependencies
│   └── vite.config.js   # Build tooling
│
└── requirements.txt     # Python dependencies
```

---

## Local Development (Testing)

### 1. Run the Backend API

```bash
cd backend
pip install -r ../requirements.txt
python app.py
```
> The API will launch on `http://localhost:5000`. By default, starting the engine via the dashboard falls back to simulation mode to prevent sudden OS privilege errors.

### 2. Run the Frontend UI

Open a new terminal session.
```bash
cd frontend
npm install
npm run dev
```
> Navigate to the mapped Vite local host port (usually `http://localhost:5173`) to view the interactive dashboard.

---

## Deployment Instructions

### Deploying the Backend on Render
1. Push this repository to GitHub.
2. Sign in to [Render.com](https://render.com) and create a new **Web Service**.
3. Point Render to your repository.
4. Set the Root Directory to `backend` (if Render asks) or define the build command: `pip install -r ../requirements.txt` / `pip install -r requirements.txt`.
5. Set the Start Command to: `gunicorn app:app --host 0.0.0.0 --port $PORT` (you may need to add `gunicorn` to your requirements.txt first).
6. Click **Deploy**. Since Render doesn't support root networking, the engine will safely operate exclusively via the **Simulator mode**, serving functional mock data.

### Deploying the Frontend on Vercel
1. Sign in to [Vercel](https://vercel.com) and click **Add New Project**.
2. Select the GitHub repository containing this logic.
3. Under **Framework Preset**, select **Vite** (Vercel usually detects this automatically).
4. Set the **Root Directory** to `frontend`.
5. Under Environment Variables, Vercel doesn't need much unless you change the API URI. Before deploying, ensure `API_BASE` in `frontend/src/App.jsx` points to your rendered `https://YOUR_RENDER_URL/api` backend address (currently it points to `http://localhost:5000/api` for local testing).
6. Click **Deploy**.

The app is now fully available across the web!
