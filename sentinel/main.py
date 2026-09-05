import time
import uuid
import json
import os
import re
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import unquote_plus
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from sentinel import database
from sentinel.detection import detect
from sentinel.facie import facie
from sentinel.ml_anomaly import anomaly_score
from sentinel.models import OverrideRequest, RequestContext, utc_now
from sentinel.protection import redact_sensitive_data, inspect_request_controls, RESOURCE_OWNERSHIP
from sentinel.response import decide
from sentinel.risk import build_result

AUDIT_LOG_PATH = Path(__file__).resolve().parent.parent / "sentinel_audit.log"
MAX_BODY_BYTES = int(os.getenv("SENTINEL_MAX_BODY_BYTES", "1048576"))
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
AUDIT_LOCK = threading.Lock()


def write_audit_log(incident_id: int, original_action: str, new_action: str, reason: str, reviewer: str) -> None:
    entry = {"timestamp": utc_now(), "incident_id": incident_id, "original_action": original_action, "new_action": new_action, "reviewer": reviewer, "reason": reason}
    with AUDIT_LOCK, AUDIT_LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, separators=(",", ":")) + "\n")

class Hub:
    def __init__(self): self.connections: set[WebSocket] = set()
    async def broadcast(self, message: dict):
        for socket in list(self.connections):
            try: await socket.send_json(message)
            except Exception: self.connections.discard(socket)

hub = Hub()


async def redact_json_response(response: Response) -> tuple[Response, list[str]]:
    if not response.headers.get("content-type", "").startswith("application/json"):
        return response, []
    if getattr(response, "body", None) is not None:
        body = response.body
    else:
        body = b"".join([chunk async for chunk in response.body_iterator])
    sanitized, leaks = redact_sensitive_data(body.decode("utf-8", "ignore"))
    if not leaks:
        sanitized = body.decode("utf-8", "ignore")
    headers = dict(response.headers)
    headers.pop("content-length", None)
    return Response(content=sanitized, status_code=response.status_code, headers=headers), leaks

@asynccontextmanager
async def lifespan(app: FastAPI):
    database.init_db()
    if not AUDIT_LOG_PATH.exists():
        AUDIT_LOG_PATH.write_text("# API Sentinel audit log\n# Timestamp | incident_id | original_action | new_action | reviewer | reason\n", encoding="utf-8")
    yield

app = FastAPI(title="API Sentinel", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.middleware("http")
async def security_gateway(request: Request, call_next):
    started = time.perf_counter()
    declared_length = request.headers.get("content-length")
    if declared_length and declared_length.isdigit() and int(declared_length) > MAX_BODY_BYTES:
        return JSONResponse({"detail": "Request body exceeds configured limit", "max_bytes": MAX_BODY_BYTES}, status_code=413)
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        return JSONResponse({"detail": "Request body exceeds configured limit", "max_bytes": MAX_BODY_BYTES}, status_code=413)
    supplied_request_id = request.headers.get("x-request-id", "")
    request_id = supplied_request_id if REQUEST_ID_PATTERN.fullmatch(supplied_request_id) else f"REQ-{uuid.uuid4().hex[:12].upper()}"
    if database.one("SELECT id FROM api_requests WHERE request_id = ?", (request_id,)):
        request_id = f"REQ-{uuid.uuid4().hex[:12].upper()}"
    forwarded_for = request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip")
    ip = forwarded_for.split(",")[0].strip() if forwarded_for else (request.client.host if request.client else "127.0.0.1")
    query = unquote_plus(str(request.url.query))
    context = RequestContext(request_id=request_id, timestamp=utc_now(), ip=ip, user_id=request.headers.get("x-user-id"), method=request.method, endpoint=request.url.path, request_size=len(body), query=query, body=body.decode("utf-8", "ignore"))
    history_rows = database.rows("SELECT * FROM api_requests ORDER BY id DESC LIMIT 20")
    history = [
        RequestContext(
            request_id=row["request_id"],
            timestamp=row["timestamp"],
            ip=row.get("ip") or "127.0.0.1",
            user_id=row.get("user_id"),
            method=row["method"],
            endpoint=row["endpoint"],
            request_size=row["request_size"] or 0,
            response_size=row["response_size"] or 0,
            status_code=row["status_code"] or 200,
            latency_ms=float(row["latency"] or 0),
            query="",
            body="",
        )
        for row in history_rows
    ]
    history.append(context)
    anomaly_value = anomaly_score(history)
    signals = detect(context)
    signals.extend(inspect_request_controls(context))
    security = build_result(request_id, signals, anomaly_score=anomaly_value)
    baseline_decision = decide(security)
    facie_result = facie.recommend(security, baseline_decision)
    decision = baseline_decision.model_copy(update={"decision": facie_result["action"], "reason": facie_result["reason"], "policy": "FACIE-ADAPTIVE"})
    dashboard_api = request.url.path in {"/api/events", "/api/incidents", "/api/endpoints", "/api/stats", "/api/facie/status"} or request.url.path.startswith("/api/incidents/")
    if decision.decision == "BLOCK" and not dashboard_api:
        response = JSONResponse({"detail": "Blocked by API Sentinel", "request_id": request_id}, status_code=403)
    elif decision.decision == "RATE_LIMIT" and not dashboard_api:
        response = JSONResponse({"detail": "Rate limit exceeded", "request_id": request_id}, status_code=429, headers={"Retry-After": "60"})
    else:
        response = await call_next(request)
    response, pii_leaks = await redact_json_response(response)
    if pii_leaks:
        signals.append({
            "type": "EXCESSIVE_DATA_EXPOSURE",
            "score": 88,
            "reason": f"Sensitive response data was masked: {', '.join(pii_leaks)}",
        })
        security = build_result(request_id, signals, anomaly_score=anomaly_value)
        baseline_decision = decide(security)
        facie_result = facie.recommend(security, baseline_decision)
        decision = baseline_decision.model_copy(update={"decision": facie_result["action"], "reason": facie_result["reason"], "policy": "FACIE-ADAPTIVE"})
    context.status_code = response.status_code
    context.response_size = int(response.headers.get("content-length", "0"))
    context.latency_ms = round((time.perf_counter() - started) * 1000, 2)
    if not signals and request.url.path == "/login" and context.status_code in (401, 403):
        signals = detect(context)
        security = build_result(request_id, signals)
        decision = decide(security)
    request_row = context.model_dump(exclude={"query", "body", "latency_ms"})
    request_row["latency"] = context.latency_ms
    database.insert("api_requests", request_row)
    if signals:
        event_id = database.insert("security_events", {"request_id": request_id, "threat_type": security.threat_type, "rule_score": security.threat_score, "anomaly_score": security.anomaly_score, "risk_score": security.risk_score, "severity": security.severity, "reason": "; ".join(security.reasons), "created_at": utc_now()})
        incident_id = database.insert("incidents", {"event_id": event_id, "endpoint": context.endpoint, "ip": ip, "threat_type": security.threat_type, "risk_score": security.risk_score, "action": decision.decision, "status": "OPEN", "created_at": utc_now(), "ai_action": facie_result["action"], "ai_confidence": facie_result["confidence"], "ai_reason": facie_result["reason"], "facie_state": facie_result["state"]})
        await hub.broadcast({"event": "THREAT_DETECTED", "incident_id": f"INC-{incident_id}", "risk_score": security.risk_score, "severity": security.severity, "endpoint": context.endpoint, "threat_type": security.threat_type, "action": decision.decision, "facie": facie_result})
    response.headers["x-request-id"] = request_id
    return response

@app.get("/products")
def products(): return [{"id": 1, "name": "Demo Widget", "price": 19.99}]

@app.get("/users")
def users(): return [{"id": 1, "name": "Demo User"}, {"id": 2, "name": "Test User"}]

@app.get("/users/{user_id}")
def user(user_id: int): return {"id": user_id, "name": f"Demo User {user_id}"}

@app.get("/api/v1/orders/{order_id}")
def order(order_id: str):
    return {"order_id": order_id, "owner": RESOURCE_OWNERSHIP.get(order_id, "unknown"), "status": "DELIVERED"}

@app.get("/api/v1/user/statement")
def user_statement():
    return {"email": "demo.user@example.com", "credit_card": "4532 8921 4410 9982", "balance": 18450.50}

@app.post("/api/v1/user/profile")
def profile(payload: dict[str, object]):
    return {"status": "UPDATED", "profile": payload}

@app.post("/login")
def login(payload: dict):
    return JSONResponse({"detail": "Invalid credentials"}, status_code=401) if payload.get("password") != "demo-pass" else {"token": "demo-token", "user_id": "demo-user"}

@app.get("/search")
def search(q: str = ""): return {"query": q, "results": []}

@app.post("/payment")
def payment(): return {"status": "accepted", "mode": "demo"}

@app.get("/admin/data")
def admin_data(): return {"message": "Demo-only admin data"}

@app.get("/api/events")
def events(): return database.rows("SELECT * FROM security_events ORDER BY id DESC LIMIT 10")

@app.get("/api/incidents")
def incidents(): return database.rows("SELECT * FROM incidents ORDER BY id DESC LIMIT 10")

@app.get("/api/incidents/{incident_id}")
def incident(incident_id: int):
    result = database.one("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    return result or JSONResponse({"detail": "Incident not found"}, status_code=404)

@app.post("/api/incidents/{incident_id}/override")
def override(incident_id: int, payload: OverrideRequest):
    incident_row = database.one("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    if not incident_row: return JSONResponse({"detail": "Incident not found"}, status_code=404)
    original_action = incident_row["action"]
    database.insert("audit_logs", {"incident_id": incident_id, "original_action": original_action, "new_action": payload.action, "reason": payload.reason, "actor": payload.reviewer, "created_at": utc_now()})
    write_audit_log(incident_id, original_action, payload.action, payload.reason, payload.reviewer)
    with database.connect() as db: db.execute("UPDATE incidents SET action = ?, status = 'OVERRIDDEN' WHERE id = ?", (payload.action, incident_id))
    if incident_row.get("facie_state"):
        reward = 2 if payload.action == incident_row.get("ai_action") else -1
        facie.learn(incident_row["facie_state"], payload.action, reward)
    return {"incident_id": incident_id, "action": payload.action, "status": "OVERRIDDEN"}

@app.get("/api/endpoints")
def endpoints(): return database.rows("SELECT endpoint, COUNT(*) AS requests FROM api_requests GROUP BY endpoint ORDER BY requests DESC")

@app.get("/api/stats")
def stats():
    return {"apis_protected": 7, "requests": database.one("SELECT COUNT(*) AS count FROM api_requests")["count"], "threats": database.one("SELECT COUNT(*) AS count FROM security_events")["count"], "blocked": database.one("SELECT COUNT(*) AS count FROM incidents WHERE action = 'BLOCK'")["count"], "critical": database.one("SELECT COUNT(*) AS count FROM incidents WHERE risk_score >= 80")["count"], "facie": facie.status()}

@app.get("/api/facie/status")
def facie_status():
    return facie.status()

@app.websocket("/ws/events")
async def websocket_events(socket: WebSocket):
    await socket.accept(); hub.connections.add(socket)
    try:
        while True: await socket.receive_text()
    except WebSocketDisconnect: hub.connections.discard(socket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
