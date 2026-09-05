const $ = (id) => document.getElementById(id);
let latest = null;

function text(id, value) { $(id).textContent = value; }
function titleCase(value) { return value.replace(/\b\w/g, (c) => c.toUpperCase()); }

function render(snapshot) {
  latest = snapshot;
  const { metrics, events, learning, last_decision, auto_mode } = snapshot;
  text('blue-score', `+${metrics.blue_score}`);
  text('blocked', metrics.blocked);
  text('blocked-note', metrics.blocked ? `${metrics.rounds} decision rounds` : 'Waiting for telemetry');
  text('detection-rate', metrics.detection_rate);
  text('high-risk', metrics.high_risk);
  text('rounds', `${metrics.rounds} rounds`);
  text('decision-title', last_decision);
  $('auto').textContent = auto_mode ? 'Pause live mode' : 'Start live mode';
  $('auto').classList.toggle('active', auto_mode);
  const latestEvent = events[0];
  if (latestEvent) {
    const angle = Math.max(5, latestEvent.risk * 3.6);
    const color = latestEvent.risk >= 76 ? '#ff7582' : latestEvent.risk >= 52 ? '#f5b97d' : '#61e5dc';
    $('posture-value').textContent = latestEvent.risk;
    $('posture-value').parentElement.parentElement.style.background = `conic-gradient(${color} ${angle}deg, rgba(97,229,220,.15) ${angle}deg)`;
    text('decision-action', latestEvent.action.toUpperCase());
    text('decision-copy', latestEvent.response);
    text('signal-summary', `${latestEvent.tactic} · ${latestEvent.confidence}% confidence`);
    text('response-summary', titleCase(latestEvent.outcome));
    text('reward', latestEvent.action === 'contain' ? '+5' : latestEvent.action === 'challenge' ? '+3' : '+1');
  }
  $('learning-bars').innerHTML = Object.entries(learning).map(([name, value]) => `<div class="learn-item"><span>${name}</span><div class="bar"><i style="width:${Math.round(value * 100)}%"></i></div><b>${Math.round(value * 100)}%</b></div>`).join('');
  $('events').innerHTML = events.length ? events.map((event) => `<tr><td>${event.time}</td><td><span class="scenario">${event.name}</span><br><span class="severity ${event.severity}">${event.severity}</span></td><td class="route">${event.source} → ${event.target}</td><td class="risk">${event.risk}/100</td><td>${event.confidence}% confident</td><td class="action">${event.action}</td></tr>`).join('') : '<tr class="empty"><td colspan="6">Session reset. Inject a safe scenario to begin.</td></tr>';
}

async function post(url, payload = {}) {
  const response = await fetch(url, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
  if (!response.ok) throw new Error('Request failed');
  return response.json();
}

$('simulate').onclick = async () => { $('simulate').disabled = true; try { await post('/api/simulate'); } finally { setTimeout(() => $('simulate').disabled = false, 400); } };
$('auto').onclick = () => post('/api/auto', { enabled: !(latest && latest.auto_mode) });
$('reset').onclick = () => post('/api/reset');

fetch('/api/snapshot').then((r) => r.json()).then(render);
const stream = new EventSource('/api/stream');
stream.onopen = () => { $('connection').classList.add('connected'); $('connection').lastChild.textContent = ' Connected'; };
stream.onmessage = ({ data }) => { const message = JSON.parse(data); if (message.snapshot) render(message.snapshot); };
stream.onerror = () => { $('connection').classList.remove('connected'); $('connection').lastChild.textContent = ' Reconnecting'; };
