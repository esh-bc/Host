#!/usr/bin/env python3
"""Minimal keepalive + dashboard web server for ESH Hosting panel.

- GET /        -> "ok" (UptimeRobot ping target)
- GET /health  -> {"status": "alive"} (UptimeRobot / Render health check)
- GET /dashboard -> aesthetic minimal HTML: bot details, users, bots, VMs.

Reads panel JSON files read-only. Needs no BOT_TOKEN.
Run:  python webserver.py   (PORT env, default 10460)
"""

from __future__ import annotations

import html
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "storage" / "data"
DB_FILE = DATA_DIR / "panel_db.json"
SETTINGS_FILE = DATA_DIR / "panel_settings.json"
PORT = int(os.environ.get("PORT", 10460))

BRAND = "ᴇꜱʜ x ʜᴏꜱᴛɪɴɢ RΒOT v2.1"

app = Flask(__name__)


def _load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _snapshot() -> dict:
    db = _load_json(DB_FILE, {})
    settings = _load_json(SETTINGS_FILE, {})
    users = db.get("users", {}) or {}
    bots = db.get("bots", {}) or {}
    running = sum(1 for b in bots.values() if (b or {}).get("status") == "running")
    vms = settings.get("vm_nodes", {}) or {}
    payments = db.get("payments", []) or []
    pending_pay = sum(1 for p in payments if (p or {}).get("status") == "pending")
    plans: dict = {}
    for u in users.values():
        plans[(u or {}).get("plan", "free")] = plans.get((u or {}).get("plan", "free"), 0) + 1
    try:
        mtime = datetime.fromtimestamp(DB_FILE.stat().st_mtime, tz=timezone.utc).isoformat()
    except Exception:
        mtime = None
    return {
        "brand": BRAND,
        "users": len(users),
        "bots": len(bots),
        "running": running,
        "pending_payments": pending_pay,
        "plans": plans,
        "vms": [
            {"vm_id": vid, "url": (v or {}).get("url", ""), "enabled": (v or {}).get("enabled", True)}
            for vid, v in vms.items()
        ],
        "db_updated": mtime,
    }


@app.route("/")
def root():
    return jsonify({"ok": True, "brand": BRAND})


@app.route("/health")
def health():
    return jsonify({"status": "alive"})


@app.route("/dashboard")
def dashboard():
    s = _snapshot()
    esc = html.escape
    vm_rows = "".join(
        f"<tr><td><code>{esc(v['vm_id'])}</code></td>"
        f"<td><code>{esc(v['url'])}</code></td>"
        f"<td>{'🟢 on' if v['enabled'] else '🔴 off'}</td></tr>"
        for v in s["vms"]
    ) or '<tr><td colspan="3">No VMs yet</td></tr>'
    plan_rows = "".join(
        f"<tr><td>{esc(str(k))}</td><td>{v}</td></tr>" for k, v in sorted(s["plans"].items())
    ) or '<tr><td colspan="2">—</td></tr>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(s['brand'])} — Dashboard</title>
<style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}
body{{margin:0;background:#0b1020;color:#e5e9f5;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:860px;margin:0 auto;padding:32px 20px 60px}}
h1{{font-size:22px;margin:0 0 4px}} .sub{{color:#8b93b0;margin:0 0 24px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:0 0 24px}}
.card{{background:#141b36;border:1px solid #232c55;border-radius:14px;padding:14px 16px}}
.card b{{display:block;font-size:26px;margin:2px 0}} .card span{{color:#8b93b0;font-size:13px}}
table{{width:100%;border-collapse:collapse;background:#141b36;border:1px solid #232c55;border-radius:14px;overflow:hidden}}
th,td{{text-align:left;padding:10px 14px;border-bottom:1px solid #232c55;font-size:14px}}
th{{color:#8b93b0;font-weight:600}} tr:last-child td{{border-bottom:0}}
code{{background:#0b1020;padding:2px 6px;border-radius:6px;font-size:13px}}
h2{{font-size:16px;margin:26px 0 10px}} .foot{{color:#8b93b0;font-size:12px;margin-top:26px}}
a{{color:#7aa2ff}}
</style></head><body><div class="wrap">
<h1>{esc(s['brand'])}</h1>
<p class="sub">Minimal status dashboard · updated {esc(str(s['db_updated']))}</p>
<div class="grid">
<div class="card"><span>Users</span><b>{s['users']}</b></div>
<div class="card"><span>Bots</span><b>{s['bots']}</b></div>
<div class="card"><span>Running</span><b>{s['running']}</b></div>
<div class="card"><span>Pending payments</span><b>{s['pending_payments']}</b></div>
</div>
<h2>VMs ({len(s['vms'])})</h2>
<table><tr><th>ID</th><th>URL</th><th>Status</th></tr>{vm_rows}</table>
<h2>Plans</h2>
<table><tr><th>Plan</th><th>Users</th></tr>{plan_rows}</table>
<p class="foot">UptimeRobot: ping <a href="/">/</a> or <a href="/health">/health</a> · Dashboard: <a href="/dashboard">/dashboard</a></p>
</div></body></html>"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)
