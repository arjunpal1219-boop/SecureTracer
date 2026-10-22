# SecureTracer — Endpoint Agent

**BSc IT Project — Rohit Pal — TYIT37**

This Python program runs on the Windows computer and reports basic security activity to the SecureTracer dashboard.

## It checks
- Changes in the protected-data folder
- USB/removable-drive connections
- A protected file appearing on removable media
- Recent events used for the ML risk calculation

## Run
```powershell
cd "E:\SecureTracer\SecureTracer\security-agent"
copy config.example.json config.json
py -m pip install -r requirements.txt
py agent.py
```

The ML part uses Isolation Forest when scikit-learn is available. A simple rule check is used as a fallback so the demo can still run.
