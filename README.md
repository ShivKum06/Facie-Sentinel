# FACIE Sentinel — real-time hackathon demo

A self-contained presentation prototype that connects the supplied FACIE battle-simulation idea, risk scoring, response policy, and reinforcement-learning memory into one live dashboard.

The application is strictly a **safe telemetry simulation**. It makes no network connections beyond serving the local browser page, does not scan hosts, and executes no attacks.

## Start it

From this folder, use any installed Python 3:

```powershell
python app.py
```

Then open [http://127.0.0.1:8080](http://127.0.0.1:8080). No packages, database, Node.js, or internet connection are required.

## Demo flow

1. Begin with the live dashboard to introduce FACIE’s adaptive security control plane.
2. Select **Inject safe scenario** for one controlled incident, and explain its signals, risk score, and response.
3. Select **Start live mode** to generate a decision every four seconds.
4. Point out the incident ledger and the Policy Learning card: successful outcomes raise the policy confidence that selects future actions.
5. Use **Reset session** to replay the story cleanly.

## What was connected

- **Red-team concept:** harmless incident scenarios model reconnaissance, credential abuse, anomalous egress, and benign change.
- **Blue-team concept:** the guard evaluates behavior signals, computes risk, and chooses observe, challenge, or contain.
- **RL concept:** every decision updates an in-memory policy reward, visualized immediately in the dashboard.
- **API + UI:** standard-library HTTP routes and Server-Sent Events keep the browser synchronized in real time.

## Endpoints

- `GET /api/snapshot` — current dashboard state
- `GET /api/stream` — real-time Server-Sent Events
- `POST /api/simulate` — generate one safe scenario
- `POST /api/auto` — turn recurring simulation on or off
- `POST /api/reset` — clear the demonstration session

This version purposely avoids the incomplete imports from the supplied archive and works with Python’s standard library alone.
