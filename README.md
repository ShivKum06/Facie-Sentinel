# API Sentinel + Facie

An API security gateway connected to the Facie adaptive policy engine. Sentinel captures every request, evaluates deterministic and anomaly signals, applies a safety policy, persists incidents in SQLite, and broadcasts threats to connected dashboards. Facie recommends a response in real time and learns from reviewer overrides.

## Run

```powershell
cd "C:\Users\Shiv\Desktop\INIT' 26\Codes - Copy"
python -m pip install -r requirements.txt
uvicorn sentinel.main:app --reload
```

Open `frontend/index.html` while the API is running. API docs are available at `http://127.0.0.1:8000/docs`.

## Demo traffic

Run these in separate terminals while the server is active:

```powershell
python simulator/normal.py
python simulator/enumeration.py
python simulator/brute_force.py
python simulator/injection.py
```

The API exposes the protected routes (`/login`, `/products`, `/users`, `/users/{id}`, `/search`, `/payment`, `/admin/data`) and dashboard routes (`/api/events`, `/api/incidents`, `/api/endpoints`, `/api/stats`, `/api/facie/status`, `/api/incidents/{id}`, `/api/incidents/{id}/override`). The integrated controls include BOLA protection at `/api/v1/orders/{order_id}`, strict profile schema validation at `/api/v1/user/profile`, and response PII masking at `/api/v1/user/statement`. WebSocket events use `/ws/events`.

## Contracts

`RequestContext`, `SecurityResult`, and `DecisionResult` in `sentinel/models.py` are the shared interfaces. `sentinel/facie.py` is the bridge for the attached Facie RL concept: it maps security state to actions, persists policy values in `facie_policy.json`, and updates them from reviewer overrides. High-confidence injection traffic remains blocked independently of the learner. The database is created and migrated as `sentinel.db` on startup.

For a container run:

```powershell
docker compose up
```

The dashboard is a static file, so open `frontend/index.html` after the API starts. Keep `sentinel.db` and `facie_policy.json` on persistent storage in a hosted deployment.

## Tests

```powershell
python -m pytest -q
```
