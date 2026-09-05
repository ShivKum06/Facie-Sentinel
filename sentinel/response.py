from sentinel.models import DecisionResult, SecurityResult


def decide(result: SecurityResult) -> DecisionResult:
    if result.threat_type in {"BRUTE_FORCE", "RATE_ABUSE"}:
        decision, policy = "RATE_LIMIT", "DEFAULT-ABUSE-CONTROL"
    elif result.threat_type == "API_ENUMERATION":
        decision, policy = "REVIEW", "DEFAULT-ELEVATED-RISK"
    elif result.risk_score >= 80 or (result.threat_score >= 90 and result.threat_type != "API_ENUMERATION"):
        decision, policy = "BLOCK", "DEFAULT-HIGH-RISK"
    elif result.risk_score >= 60:
        decision, policy = "REVIEW", "DEFAULT-ELEVATED-RISK"
    elif result.risk_score >= 30:
        decision, policy = "MONITOR", "DEFAULT-MONITOR"
    else:
        decision, policy = "ALLOW", "DEFAULT-ALLOW"
    reason = result.reasons[0] if result.reasons else "No security signals detected"
    return DecisionResult(request_id=result.request_id, decision=decision, reason=reason, policy=policy, risk_score=result.risk_score)
