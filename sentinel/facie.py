import json
import os
import threading
from pathlib import Path
from typing import Any

from sentinel.models import DecisionResult, SecurityResult


class FaciePolicy:
    """Persistent policy learner adapted from the Facie RL prototype."""

    ACTIONS = ("ALLOW", "MONITOR", "RATE_LIMIT", "REVIEW", "BLOCK")
    STATE_ACTIONS = {
        "NONE|LOW|0": {"ALLOW": 4.0, "MONITOR": 1.0},
        "INJECTION|CRITICAL|high": {"BLOCK": 8.0, "REVIEW": 1.0},
        "BRUTE_FORCE|HIGH|medium": {"RATE_LIMIT": 5.0, "REVIEW": 3.0},
        "API_ENUMERATION|HIGH|medium": {"RATE_LIMIT": 4.0, "REVIEW": 5.0},
        "RATE_ABUSE|HIGH|medium": {"RATE_LIMIT": 6.0, "BLOCK": 2.0},
    }

    def __init__(self, state_file: str | Path | None = None) -> None:
        default_path = Path(__file__).resolve().parent.parent / "facie_policy.json"
        self.state_file = Path(state_file or os.getenv("FACIE_STATE_FILE", default_path))
        self._lock = threading.Lock()
        self._q_table = self._load()

    def _load(self) -> dict[str, dict[str, float]]:
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            return {str(key): {str(action): float(value) for action, value in values.items()} for key, values in data.items()}
        except (FileNotFoundError, json.JSONDecodeError, TypeError, ValueError):
            return {key: dict(values) for key, values in self.STATE_ACTIONS.items()}

    def _save(self) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_file.with_suffix(".tmp")
        temporary.write_text(json.dumps(self._q_table, indent=2, sort_keys=True), encoding="utf-8")
        temporary.replace(self.state_file)

    @staticmethod
    def _state(result: SecurityResult) -> str:
        anomaly = "high" if result.anomaly_score >= 0.75 else "medium" if result.anomaly_score >= 0.35 else "0"
        return f"{result.threat_type}|{result.severity}|{anomaly}"

    def recommend(self, result: SecurityResult, baseline: DecisionResult) -> dict[str, Any]:
        state = self._state(result)
        with self._lock:
            scores = dict(self._q_table.get(state, {}))
        scores.setdefault(baseline.decision, 0.5)
        action = max(scores, key=scores.get)
        if result.threat_type == "INJECTION" or result.risk_score >= 80 and result.threat_type not in {"API_ENUMERATION", "BRUTE_FORCE", "RATE_ABUSE"}:
            action = "BLOCK"
        elif result.threat_type == "API_ENUMERATION" and action == "ALLOW":
            action = "REVIEW"
        confidence = min(0.99, max(0.51, 0.5 + abs(scores.get(action, 0.0)) / 20))
        return {
            "action": action,
            "confidence": round(confidence, 3),
            "state": state,
            "reason": f"Facie policy selected {action} for state {state}",
        }

    def learn(self, state: str, action: str, reward: float) -> None:
        if action not in self.ACTIONS:
            return
        with self._lock:
            state_scores = self._q_table.setdefault(state, {})
            state_scores[action] = round(state_scores.get(action, 0.0) + reward, 4)
            self._save()

    def status(self) -> dict[str, Any]:
        with self._lock:
            states = len(self._q_table)
            values = sum(len(actions) for actions in self._q_table.values())
        return {"engine": "FACIE", "status": "ready", "states": states, "action_values": values, "persistent": True}


facie = FaciePolicy()