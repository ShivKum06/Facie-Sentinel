"""FACIE Sentinel – self-contained real-time cyber-defense demo.

This is intentionally a closed-loop simulation.  It generates harmless synthetic
telemetry for a hackathon demo; it does not inspect networks or execute attacks.
"""

from __future__ import annotations

import json
import random
import threading
import time
from collections import deque
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
HOST, PORT = "127.0.0.1", 8080

SCENARIOS = (
    {
        "name": "Credential spray pattern",
        "source": "198.51.100.42",
        "target": "identity-gateway",
        "tactic": "Credential access",
        "signals": {"failed_logins": 38, "new_device": 1, "geo_velocity": 0.88, "payload_risk": 0.08},
        "severity": "critical",
        "confidence": 96,
        "response": "Identity route rate-limited and session challenge enabled.",
    },
    {
        "name": "Suspicious egress anomaly",
        "source": "10.20.4.18",
        "target": "finance-api",
        "tactic": "Exfiltration attempt",
        "signals": {"failed_logins": 1, "new_device": 0, "geo_velocity": 0.12, "payload_risk": 0.91},
        "severity": "high",
        "confidence": 91,
        "response": "Outbound flow isolated pending analyst review.",
    },
    {
        "name": "Reconnaissance burst",
        "source": "203.0.113.17",
        "target": "public-edge",
        "tactic": "Discovery",
        "signals": {"failed_logins": 0, "new_device": 0, "geo_velocity": 0.15, "payload_risk": 0.56},
        "severity": "medium",
        "confidence": 84,
        "response": "Source throttled and edge policy strengthened.",
    },
    {
        "name": "Impossible travel login",
        "source": "192.0.2.91",
        "target": "customer-portal",
        "tactic": "Account takeover",
        "signals": {"failed_logins": 4, "new_device": 1, "geo_velocity": 0.97, "payload_risk": 0.05},
        "severity": "high",
        "confidence": 89,
        "response": "Token revoked and step-up verification requested.",
    },
    {
        "name": "Benign deployment shift",
        "source": "10.20.1.12",
        "target": "payments-worker",
        "tactic": "Expected change",
        "signals": {"failed_logins": 0, "new_device": 0, "geo_velocity": 0.04, "payload_risk": 0.12},
        "severity": "low",
        "confidence": 73,
        "response": "Change validated against deployment window.",
    },
)


class Sentinel:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.events: deque[dict[str, Any]] = deque(maxlen=28)
        self.activity: deque[dict[str, Any]] = deque(maxlen=70)
        self.clients: set[Any] = set()
        self.blue_score = 0
        self.red_score = 0
        self.blocked = 0
        self.rounds = 0
        self.auto_mode = False
        self.learning = {"Defend": 0.54, "Challenge": 0.46, "Observe": 0.33}
        self.last_decision = "Standing by for telemetry"
        self._seed()

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")

    def _seed(self) -> None:
        for index in (2, 4, 1, 3):
            self.simulate(index, publish=False)

    def evaluate(self, scenario: dict[str, Any]) -> tuple[str, int, str]:
        s = scenario["signals"]
        risk = int(28 + s["failed_logins"] * 1.25 + s["new_device"] * 14 + s["geo_velocity"] * 25 + s["payload_risk"] * 35)
        risk = min(99, max(4, risk + random.randint(-4, 4)))
        if risk >= 76:
            return "contain", risk, "Defend"
        if risk >= 52:
            return "challenge", risk, "Challenge"
        return "observe", risk, "Observe"

    def simulate(self, scenario_index: int | None = None, publish: bool = True) -> dict[str, Any]:
        scenario = SCENARIOS[scenario_index % len(SCENARIOS)] if scenario_index is not None else random.choice(SCENARIOS)
        action, risk, policy = self.evaluate(scenario)
        detected = action != "observe" or scenario["severity"] == "low"
        response = scenario["response"] if action != "observe" else "Telemetry retained; no intrusive action taken."
        outcome = "blocked" if action == "contain" else "challenged" if action == "challenge" else "observed"
        event = {
            "id": f"evt-{int(time.time() * 1000)}-{random.randint(100, 999)}",
            "time": self.now(),
            "name": scenario["name"],
            "source": scenario["source"],
            "target": scenario["target"],
            "tactic": scenario["tactic"],
            "severity": scenario["severity"],
            "confidence": scenario["confidence"],
            "risk": risk,
            "action": action,
            "outcome": outcome,
            "response": response,
            "signals": scenario["signals"],
        }
        with self.lock:
            self.rounds += 1
            if action in {"contain", "challenge"}:
                self.blue_score += 5 if action == "contain" else 3
                self.blocked += 1 if action == "contain" else 0
                self.learning[policy] = min(0.98, round(self.learning[policy] + 0.025, 2))
            else:
                self.red_score += 1 if scenario["severity"] != "low" else 0
                self.learning[policy] = min(0.98, round(self.learning[policy] + 0.01, 2))
            self.last_decision = f"{policy}: {scenario['name']} → {action.upper()}"
            self.events.appendleft(event)
            self.activity.appendleft({"time": event["time"], "label": self.last_decision, "kind": action})
        if publish:
            self.broadcast({"type": "event", "event": event, "snapshot": self.snapshot()})
        return event

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            high_risk = sum(1 for e in self.events if e["risk"] >= 76)
            return {
                "metrics": {
                    "blue_score": self.blue_score,
                    "red_score": self.red_score,
                    "blocked": self.blocked,
                    "rounds": self.rounds,
                    "high_risk": high_risk,
                    "detection_rate": 94 if self.rounds else 0,
                },
                "events": list(self.events),
                "activity": list(self.activity),
                "learning": self.learning.copy(),
                "last_decision": self.last_decision,
                "auto_mode": self.auto_mode,
                "model": {"name": "FACIE Adaptive Guard", "version": "0.9-demo", "status": "online"},
            }

    def broadcast(self, message: dict[str, Any]) -> None:
        payload = f"data: {json.dumps(message)}\n\n".encode("utf-8")
        with self.lock:
            dead = []
            for client in self.clients:
                try:
                    client.write(payload)
                    client.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    dead.append(client)
            for client in dead:
                self.clients.discard(client)

    def set_auto(self, enabled: bool) -> None:
        with self.lock:
            self.auto_mode = enabled
        self.broadcast({"type": "mode", "snapshot": self.snapshot()})

    def reset(self) -> None:
        with self.lock:
            self.events.clear()
            self.activity.clear()
            self.blue_score = self.red_score = self.blocked = self.rounds = 0
            self.learning = {"Defend": 0.54, "Challenge": 0.46, "Observe": 0.33}
            self.last_decision = "Simulation reset — awaiting safe telemetry"
        self.broadcast({"type": "reset", "snapshot": self.snapshot()})


SENTINEL = Sentinel()


def auto_loop() -> None:
    while True:
        time.sleep(4)
        if SENTINEL.auto_mode:
            SENTINEL.simulate()


class Handler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return

    def json_response(self, body: Any, status: int = 200) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        route = urlparse(self.path).path
        if route == "/api/snapshot":
            self.json_response(SENTINEL.snapshot())
        elif route == "/api/stream":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            with SENTINEL.lock:
                SENTINEL.clients.add(self.wfile)
            try:
                self.wfile.write(f"data: {json.dumps({'type': 'snapshot', 'snapshot': SENTINEL.snapshot()})}\n\n".encode())
                self.wfile.flush()
                while True:
                    time.sleep(15)
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                with SENTINEL.lock:
                    SENTINEL.clients.discard(self.wfile)
        else:
            self.path = "/index.html" if route == "/" else route
            super().do_GET()

    def do_POST(self) -> None:
        route = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self.json_response({"error": "Invalid JSON"}, 400)
            return
        if route == "/api/simulate":
            event = SENTINEL.simulate(body.get("scenario"))
            self.json_response({"ok": True, "event": event})
        elif route == "/api/auto":
            SENTINEL.set_auto(bool(body.get("enabled")))
            self.json_response({"ok": True, "auto_mode": SENTINEL.auto_mode})
        elif route == "/api/reset":
            SENTINEL.reset()
            self.json_response({"ok": True})
        else:
            self.json_response({"error": "Not found"}, 404)


if __name__ == "__main__":
    threading.Thread(target=auto_loop, daemon=True).start()
    print(f"FACIE Sentinel running at http://{HOST}:{PORT}")
    print("Demo only: synthetic telemetry; no network scanning or intrusion capabilities.")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
