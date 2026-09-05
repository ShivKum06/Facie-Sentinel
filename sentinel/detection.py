import re
import time
from collections import defaultdict, deque
from sentinel.models import RequestContext

WINDOW_SECONDS = 60
RATE_LIMIT = 75
FAILED_LOGIN_LIMIT = 3

_requests: defaultdict[str, deque[float]] = defaultdict(deque)
_failed_logins: defaultdict[str, deque[float]] = defaultdict(deque)
_objects: defaultdict[tuple[str, str], dict[str, float]] = defaultdict(dict)
MAX_TRACKED_KEYS = 10000


def _recent(bucket: deque[float], now: float) -> int:
    while bucket and now - bucket[0] > WINDOW_SECONDS:
        bucket.popleft()
    return len(bucket)


def detect(context: RequestContext) -> list[dict[str, object]]:
    now = time.time()
    if len(_requests) > MAX_TRACKED_KEYS:
        for key, bucket in list(_requests.items()):
            _recent(bucket, now)
            if not bucket:
                del _requests[key]
            if len(_requests) <= MAX_TRACKED_KEYS:
                break
    if len(_failed_logins) > MAX_TRACKED_KEYS:
        for key, bucket in list(_failed_logins.items()):
            _recent(bucket, now)
            if not bucket:
                del _failed_logins[key]
            if len(_failed_logins) <= MAX_TRACKED_KEYS:
                break
    if len(_objects) > MAX_TRACKED_KEYS:
        cutoff = now - WINDOW_SECONDS
        for key, object_ids in list(_objects.items()):
            for object_id, seen_at in list(object_ids.items()):
                if seen_at < cutoff:
                    del object_ids[object_id]
            if not object_ids:
                del _objects[key]
            if len(_objects) <= MAX_TRACKED_KEYS:
                break
    signals: list[dict[str, object]] = []
    requests = _requests[context.ip]
    requests.append(now)
    request_count = _recent(requests, now)
    if request_count > RATE_LIMIT:
        signals.append({"type": "RATE_ABUSE", "score": min(100, 72 + request_count // 7), "reason": "Requests exceeded configured per-minute threshold"})

    if context.endpoint == "/login" and context.status_code in (401, 403):
        failures = _failed_logins[context.ip]
        failures.append(now)
        failed_count = _recent(failures, now)
        if failed_count >= FAILED_LOGIN_LIMIT:
            signals.append({"type": "BRUTE_FORCE", "score": min(100, 75 + failed_count * 4), "reason": "Repeated authentication failures"})

    match = re.search(r"/(?:users?|products)/(\d+)", context.endpoint)
    if match:
        key = (context.ip, re.sub(r"/\d+$", "/{id}", context.endpoint))
        object_ids = _objects[key]
        cutoff = now - WINDOW_SECONDS
        for object_id, seen_at in list(object_ids.items()):
            if seen_at < cutoff:
                del object_ids[object_id]
        object_ids[match.group(1)] = now
        if len(object_ids) >= 6:
            signals.append({"type": "API_ENUMERATION", "score": min(100, 90 + len(object_ids) // 2), "reason": "Large number of unique object IDs"})

    suspicious = re.compile(r"(?:union\s+select|drop\s+table|<script|or\s+1=1|;--)", re.I)
    if suspicious.search(context.query) or suspicious.search(context.body):
        signals.append({"type": "INJECTION", "score": 98, "reason": "Request contains a known suspicious input pattern"})
    return signals
