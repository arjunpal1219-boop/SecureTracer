# SecureTracer

**File & Device Security Platform**

SecureTracer is a college project for checking important files and basic endpoint activity. The project combines a React web page, a Node.js API, MongoDB and a Python endpoint agent.

## What the project does

1. A user registers an important file.
2. The system creates a SHA-256 hash for that file.
3. The hash is stored as the trusted value.
4. Later, the file can be checked again.
5. If the new hash is different, a tampering event is created.
6. The Python agent watches the protected folder and USB/removable-drive activity.
7. Events are sent to the backend and shown on the dashboard.
8. The ML part uses recent events to give a simple risk score.

## Technologies used
- React + Vite
- Node.js + Express
- MongoDB + Mongoose
- Python
- SHA-256
- JWT + bcrypt
- Multer
- scikit-learn / Isolation Forest

## Project folders

```text
SecureTracer
├── backend
├── frontend
├── security-agent
├── PROJECT_IDENTITY.md
└── README.md
```

## Windows setup

### Backend
First create the local environment file from the example. In PowerShell, run these commands from the `backend` folder:
```powershell
Copy-Item .env.example .env
npm install
npm run dev
```
If you extracted the project to another folder, use that actual folder path before running the commands. Keep the `.env` file local and do not share it.

The API normally runs at `http://localhost:5000`.

### Frontend
Open another PowerShell window:
```powershell
cd "<your-extracted-folder>\SecureTracer\frontend"
npm install
npm run dev
```

The Vite page normally opens at `http://localhost:5173`.

### Security agent
Open a third PowerShell window:
```powershell
cd "<your-extracted-folder>\SecureTracer\security-agent"
copy config.example.json config.json
py -m pip install -r requirements.txt
py agent.py
```

Set the values in `config.json` before running the agent if your backend uses a different key or account.

## Simple testing

- Add a small test file to `security-agent\protected-data`.
- Start the backend, frontend and agent.
- Change the test file and check the dashboard for the file event.
- Connect a test USB drive and check the USB event.
- Use the dashboard to register and verify a file.

## Simple viva explanation

**File side:** Register → SHA-256 hash → Save trusted hash → Verify → Compare hashes → Show result.

**Endpoint side:** Watch files/USB → Create event → Send to backend → Store in MongoDB → Show on dashboard.

**ML side:** Read recent security events → calculate a risk value → show the risk level on the dashboard.

## Important scope
This is a college-level endpoint security prototype. A normal Python/Node application cannot guarantee that every possible Windows copy method is blocked. Enterprise products use additional Windows security controls for that. This project focuses on monitoring, detection, alerts, risk analysis and audit logging.

## USB monitoring setup

1. Start MongoDB and the backend API.
2. Start the React frontend.
3. Open `security-agent/config.json` and set `owner_email` to the same email used for the SecureTracer login.
4. From the `security-agent` folder run:
   - `python agent.py`
5. Keep that terminal open.
6. Disconnect and reconnect a USB drive. The dashboard should record `USB_CONNECTED` and `USB_DISCONNECTED` events.
7. Protect a test file in SecureTracer, then copy that protected file to the USB drive. The agent checks the SHA-256 fingerprint and can record `DATA_EXFILTRATION_ATTEMPT` when the same protected content is found on removable media.

The agent supports both `protected_directory` and `protected_directories`. The default configuration monitors the agent's `protected-data` folder and the backend `uploads` folder.

`enforcement_mode` is `alert-only` in this student prototype. It records and alerts on detected activity; it does not claim to block every possible Windows copy route.

## Windows quick start (important)

1. Install Node.js LTS and MongoDB Community Server, and make sure MongoDB is running locally.
2. Open this extracted `SecureTracer` project folder in VS Code.
3. In Terminal 1 run:
   ```powershell
   cd backend
   npm install
   npm run dev
   ```
4. In Terminal 2 run:
   ```powershell
   cd frontend
   npm install
   npm run dev
   ```
5. Open `http://localhost:5173`, create a new account with a password of at least 8 characters, then use **+ Protect file**.
6. Keep both terminals open. Backend must show `SecureTracer API running on http://localhost:5000`. The backend `.env` file is included for local demo use; do not use its demo secrets for a public deployment.

If registration reports a MongoDB connection error, start MongoDB first. If you previously tried logging in while the JWT secret was missing, log out and sign in again after restarting the backend.

**Verification note:** The dashboard verifies the file selected in the Verify dialog. It flags content changes (SHA-256 mismatch) and a different uploaded filename. Merely renaming a file on disk does not create a live alert unless the endpoint agent is configured and running to monitor that folder.


## Windows quick start (registration fix)

1. Start MongoDB Windows service.
2. Open PowerShell window 1:
   `cd .\backend` then `npm install` (first run only), then `npm run dev`.
3. Keep window 1 open. Confirm it says `SecureTracer API running on http://localhost:5000`.
4. Open PowerShell window 2:
   `cd .\frontend` then `npm install` (first run only), then `npm run dev`.
5. Open the exact Vite URL shown in window 2 (often `http://localhost:5173` or `http://localhost:5175`).
6. Click **Create account** and register with a password of at least 8 characters.

The backend accepts Vite localhost ports 5173–5999 to avoid CORS errors when Vite selects a different port. The health check is `http://localhost:5000/api/health`.
