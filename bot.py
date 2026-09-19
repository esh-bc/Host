
from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import random
import re
import secrets
import shutil
import signal
import string
import subprocess
import sys
import importlib
import tarfile
import tempfile
import threading
import time
import traceback
import zipfile
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

# ── Remote-VM + Mongo-pool addons (vm_client.py / mongo_pool.py) ──
# Split imports so PIDs work even if Mongo is missing/broken.
try:
    import vm_client as _vmc
    _VMC_OK = True
except Exception as _vmc_err:
    _vmc = None  # type: ignore
    _VMC_OK = False
    print(f"[addons] vm_client unavailable: {_vmc_err}", file=sys.stderr, flush=True)
try:
    import mongo_pool as _mdb
    _MDB_OK = True
except Exception as _mdb_err:
    _mdb = None  # type: ignore
    _MDB_OK = False
    print(f"[addons] mongo_pool unavailable: {_mdb_err}", file=sys.stderr, flush=True)
_ADDONS_OK = bool(_VMC_OK)


_REQUIRED_PKGS = [
    ("telebot",             "pyTelegramBotAPI"),
    ("requests",            "requests"),
    ("cryptography.fernet", "cryptography"),
    ("flask",               "flask"),
    ("apscheduler",         "APScheduler"),
    ("github",              "PyGithub"),
    ("psutil",              "psutil"),
    ("PIL",                 "Pillow"),
]


def _auto_install_missing() -> None:
    import importlib
    missing: List[str] = []
    for mod, pip_name in _REQUIRED_PKGS:
        try:
            importlib.import_module(mod)
        except ImportError:
            missing.append(pip_name)
    if not missing:
        return
    print(f"[setup] installing missing packages: {', '.join(missing)}")
    # Try several install strategies — different hosts have different
    # restrictions (PEP 668 externally-managed, no root, sandboxed pip,
    # etc.). The first one that succeeds wins.
    strategies = [
        [sys.executable, "-m", "pip", "install", "--upgrade", "--quiet", *missing],
        [sys.executable, "-m", "pip", "install", "--upgrade", "--quiet",
         "--break-system-packages", *missing],
        [sys.executable, "-m", "pip", "install", "--user", "--upgrade", "--quiet", *missing],
        [sys.executable, "-m", "pip", "install", "--user", "--upgrade", "--quiet",
         "--break-system-packages", *missing],
    ]
    last_err: Optional[Exception] = None
    for cmd in strategies:
        try:
            subprocess.run(cmd, check=True)
            print("[setup] install ok — continuing boot")
            return
        except Exception as e:
            last_err = e
            continue
    sys.exit(f"[x] auto-install failed after {len(strategies)} attempts: {last_err}. "
             f"Run manually: pip install {' '.join(missing)}")


_auto_install_missing()

# Now safe to import third-party modules.
import telebot
from telebot import types
from telebot.apihelper import ApiTelegramException
import requests
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, jsonify

# ── TELEGRAM BOT API 9.4 — BUTTON STYLE SUPPORT ──────────────────
# style="primary" = Blue | style="success" = Green | style="danger" = Red
# Graceful fallback: if Telegram ignores the field, buttons work normally.
class Btn(types.InlineKeyboardButton):
    """InlineKeyboardButton with optional style support (Bot API 9.4+)."""
    def __init__(self, *args, style: str = "", **kwargs):
        super().__init__(*args, **kwargs)
        if style:
            self.style = style  # type: ignore[attr-defined]

    def to_dict(self):
        d = super().to_dict()
        if getattr(self, "style", ""):
            d["style"] = self.style
        return d

_SEC_PATTERNS = {
    # ── Real data theft — actively reading & exfiltrating server files ──
    "🔴 Data Theft": [
        # Must have a specific system directory name after the slash (not '/' alone)
        (r'os\.walk\s*\(\s*["\'][/\\](?:root|home|etc|var|proc)["\']',
                                                  "Root/system directory walk — server files chura raha hai"),
        # send_document paired with open() on a SYSTEM path (not relative) = suspicious
        (r'send_document\s*\(.*open\s*\(\s*["\'][/\\](?:root|etc|proc|sys)',
                                                  "System file bahar bhej raha hai"),
        # ZIP + os.walk together with a system root path = suspicious
        (r'zipfile\.ZipFile.*["\']w["\'].*\bos\.walk\b.*["\'][/\\](?:root|etc|home)',
                                                  "System files ZIP mein pack karke bhej raha hai"),
        (r'glob\.glob\s*\(["\'][/\\]\*',          "Root glob scan — server files dhundh raha hai"),
        (r'shutil\.copy.*["\'][/\\]root',         "/root se copy kar raha hai"),
        (r'ROOT_DIR\s*=\s*["\'][/\\]["\']',       "Root directory target kar raha hai"),
    ],
    # ── True backdoors — code that executes arbitrary commands ──
    # NOTE: eval/exec/compile checks are done in AST scan (not regex) so they
    # don't false-positive on string literals like "eval(compile..." inside
    # scanner pattern lists or docstrings.
    "🔴 Backdoor": [
        # __import__('os') detection is done in AST scan (avoids false positives on
        # string literals like "__import__('os')" in scanner pattern lists).
        # subprocess with shell=True AND piped user input on same line only
        (r'subprocess\s*\.\s*(?:Popen|call|run)\s*\([^\n]*shell\s*=\s*True[^\n]*(?:input|stdin)',
                                                  "Shell injection with user input"),
        (r'marshal\.loads\s*\(',                  "Marshalled bytecode — obfuscated execution"),
    ],
    # ── Exposed credentials — actual tokens/secrets in plain text ──
    "🔴 Exposed Credentials": [
        # BOT_TOKEN_REGEX handled separately in _sec_static_scan
    ],
    # ── Obfuscation — actively hiding intent ──
    "🟡 Obfuscation": [
        (r'base64\.b64decode\s*\(.*\)\s*[\)\s]*\bexec\b',
                                                  "Base64 decode + execute — hidden code"),
        (r'(?:\\x[0-9a-fA-F]{2}){6,}',           "Long hex string — obfuscated code"),
        (r'zlib\.decompress\s*\(.*\)\s*[\)\s]*\bexec\b',
                                                  "Compressed + executed hidden code"),
    ],
    # ── Suspicious network — sending data out to KNOWN malicious endpoints ──
    "🟡 Suspicious Network": [
        (r'devil-api\.com|elementfx\.io',         "Known malicious API endpoint"),
        # Only flag if reading a SYSTEM path and posting externally
        (r'open\s*\(\s*["\'][/\\](?:root|etc|proc|sys).*(?:requests|urllib).*(?:post|put)',
                                                  "System file HTTP POST — data exfiltration"),
        (r'pastebin\.com/raw',                    "Pastebin raw fetch — remote code load"),
    ],
    # ── Resource abuse ──
    "🟠 Resource Abuse": [
        (r'multiprocessing\.Pool\s*\(\s*(?:None|\d{3,})',
                                                  "Massive process pool — resource abuse"),
        (r'fork\s*\(\s*\).*fork\s*\(',            "Fork bomb pattern"),
    ],
}

_SEC_TOKEN_RE  = re.compile(r'\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b')


def _sec_static_scan(code: str) -> dict:
    results: Dict[str, List[str]] = {}
    for category, pattern_list in _SEC_PATTERNS.items():
        hits = []
        for pattern, description in pattern_list:
            # No DOTALL — keeps .* within a single line so multi-token patterns
            # don't span the whole file and cause false positives.
            if re.search(pattern, code, re.IGNORECASE | re.MULTILINE):
                hits.append(description)
        if hits:
            results[category] = hits
    tokens = _SEC_TOKEN_RE.findall(code)
    if tokens:
        results.setdefault("🔴 Exposed Credentials", [])
        results["🔴 Exposed Credentials"].append(f"Bot Token mila: {tokens[0][:15]}...")
    return results


def _sec_ast_scan(code: str) -> List[str]:
    import ast as _ast
    findings: List[str] = []
    try:
        tree = _ast.parse(code)
    except SyntaxError as e:
        findings.append(f"Code parse nahi hua: {e} - encoded/obfuscated ho sakta hai")
        return findings
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Call):
            func = node.func
            # os.walk with a literal system path argument
            if isinstance(func, _ast.Attribute):
                if (func.attr == 'walk' and isinstance(func.value, _ast.Name)
                        and func.value.id == 'os' and node.args):
                    arg = node.args[0]
                    if isinstance(arg, _ast.Constant) and isinstance(arg.value, str):
                        if arg.value in ['/root', '/etc', '/home', '/proc']:
                            findings.append(f"os.walk('{arg.value}') - sensitive directory scan")
            # eval/exec only when the argument is itself a function call (dynamic execution)
            # This correctly ignores eval/exec as plain names in string literals
            if isinstance(func, _ast.Name) and func.id in ('eval', 'exec'):
                if node.args:
                    arg0 = node.args[0]
                    # Flag only when called with a dynamic/external source
                    if isinstance(arg0, _ast.Call):
                        findings.append(f"Dangerous: {func.id}() — dynamic code execution")
                    elif isinstance(arg0, _ast.Attribute):
                        findings.append(f"Dangerous: {func.id}() — attribute-based input")
            # __import__('os') — dynamic OS import (AST-only to skip string literals)
            if isinstance(func, _ast.Name) and func.id == '__import__':
                if node.args and isinstance(node.args[0], _ast.Constant):
                    if node.args[0].value == 'os':
                        findings.append("Dynamic __import__('os') — code injection")
    return findings


def _sec_calculate_risk(static_findings: dict, ast_findings: List[str]) -> int:
    # Weights tuned to avoid false positives on legitimate Telegram bots.
    # Only patterns that are unambiguously malicious get high scores.
    weights = {
        "🔴 Data Theft":          40,
        "🔴 Backdoor":            40,
        # Having a token in code is bad practice but NOT necessarily theft —
        # many bots hardcode their token. Weight kept low so it alone can't
        # reach the DANGEROUS threshold.
        "🔴 Exposed Credentials": 10,
        "🟡 Suspicious Network":  12,
        "🟡 Obfuscation":         10,
        "🟠 Resource Abuse":       8,
    }
    score = sum(weights.get(cat, 5) * min(len(hits), 3)
                for cat, hits in static_findings.items()
                if hits)
    # Deduplicate AST findings and cap contribution so repeated path hits
    # don't inflate the score to 100 on legitimate bots.
    unique_ast = list(dict.fromkeys(ast_findings))
    score += min(len(unique_ast) * 5, 20)
    return min(score, 100)


def _sec_get_verdict(risk_score: int, static_findings: dict) -> Tuple[str, str]:
    # Only Data Theft + Backdoor are truly blocking threats.
    # Exposed Credentials alone → SUSPICIOUS (warn user, don't block).
    has_blocking = any(
        static_findings.get(c)
        for c in ("🔴 Data Theft", "🔴 Backdoor")
    )
    has_credentials = bool(static_findings.get("🔴 Exposed Credentials"))

    # REJECT only for real attack patterns at high risk
    if has_blocking and risk_score >= 70:
        return "DANGEROUS", "REJECT"
    if risk_score >= 85:
        return "DANGEROUS", "REJECT"
    # Hardcoded token alone → warn but allow (MANUAL_REVIEW)
    if has_credentials and not has_blocking and risk_score < 40:
        return "SUSPICIOUS", "MANUAL_REVIEW"
    if has_blocking and risk_score >= 35:
        return "SUSPICIOUS", "MANUAL_REVIEW"
    if risk_score >= 55:
        return "SUSPICIOUS", "MANUAL_REVIEW"
    return "SAFE", "APPROVE"


def _sec_scan_code(code: str, filename: str = "file.py") -> dict:
    sf = _sec_static_scan(code)
    af = _sec_ast_scan(code)
    risk = _sec_calculate_risk(sf, af)
    verdict, recommendation = _sec_get_verdict(risk, sf)
    all_threats: List[str] = [f"{c}: {h}" for c, hits in sf.items() for h in hits] + af
    if verdict == "DANGEROUS":
        summary = f"⚠️ File DANGEROUS hai! {len(all_threats)} threats mili hain."
    elif verdict == "SUSPICIOUS":
        summary = "🔍 File suspicious hai. Admin se manual review karwao."
    else:
        summary = "✅ File safe lagti hai. Koi major threat nahi mila."
    return {"verdict": verdict, "risk_score": risk, "findings": sf,
            "ast_findings": af, "all_threats": all_threats,
            "recommendation": recommendation, "summary": summary, "filename": filename}


def _sec_scan_archive(file_path: str) -> dict:
    tmp = tempfile.mkdtemp()
    try:
        if file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as z:
                for name in z.namelist():
                    if name.startswith('/') or '..' in name:
                        return {"verdict": "DANGEROUS", "risk_score": 99,
                                "findings": {"🔴 Zip Slip Attack": ["Dangerous file paths in ZIP!"]},
                                "ast_findings": [], "recommendation": "REJECT",
                                "summary": "ZIP Slip attack detected!", "all_threats": []}
                z.extractall(tmp)
        elif file_path.endswith(('.tar.gz', '.tgz', '.tar')):
            with tarfile.open(file_path, 'r:*') as t:
                t.extractall(tmp)
        py_files = list(Path(tmp).rglob("*.py"))
        if not py_files:
            return {"verdict": "SUSPICIOUS", "risk_score": 20,
                    "findings": {"🟡 Warning": ["Koi .py file nahi mili archive mein"]},
                    "ast_findings": [], "recommendation": "MANUAL_REVIEW",
                    "summary": "Archive mein Python files nahi hain.", "all_threats": []}
        worst = None
        for py_file in py_files[:10]:
            try:
                result = _sec_scan_code(py_file.read_text(errors='ignore'), py_file.name)
                if worst is None or result['risk_score'] > worst['risk_score']:
                    worst = result
            except Exception:
                continue
        return worst or {"verdict": "SAFE", "risk_score": 0, "recommendation": "APPROVE",
                         "summary": "Safe lagti hai", "all_threats": []}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _scan_file(file_path: str) -> dict:
    """Main entry — scan any uploaded file before saving."""
    filename = os.path.basename(file_path)
    try:
        if filename.lower().endswith(('.zip', '.tar.gz', '.tgz', '.tar')):
            return _sec_scan_archive(file_path)
        elif filename.lower().endswith(('.py', '.pyc', '.pyo', '.js')):
            with open(file_path, 'r', errors='ignore') as _f:
                return _sec_scan_code(_f.read(), filename)
        else:
            return {"verdict": "SUSPICIOUS", "risk_score": 30,
                    "findings": {"🟡 Warning": [f"Unknown file type: {filename}"]},
                    "ast_findings": [], "recommendation": "MANUAL_REVIEW",
                    "summary": f"File type '{filename}' allow nahi hai.",
                    "all_threats": [], "filename": filename}
    except Exception as _e:
        return {"verdict": "ERROR", "risk_score": 50, "findings": {},
                "ast_findings": [], "recommendation": "MANUAL_REVIEW",
                "summary": f"Scan error: {_e}", "all_threats": [], "filename": filename}

_SCANNER_OK = True

# ── External scanner module (security_scanner_free.py) ──
# Importing scan_file replaces the built-in _scan_file above so the
# external module's patterns (with all fixes and extra detections)
# are used by _combined_scan → _run_security_scan → _handle_bot_upload.
try:
    # Ensure the scanner module is discoverable even when bot.py is run
    # from a different working directory (e.g. `python3 /path/to/bot.py`).
    import os as _os, sys as _sys
    _here = _os.path.dirname(_os.path.abspath(__file__))
    if _here and _here not in _sys.path:
        _sys.path.insert(0, _here)
    from security_scanner_free import scan_file as _scan_file  # noqa: F811
    _SCANNER_OK = True
except Exception as _ssf_err:
    import sys as _sys
    print(f"[security] security_scanner_free.py not found — using built-in scanner ({_ssf_err})", file=_sys.stderr)
    # Fall back to built-in _scan_file defined above


# ── AI-powered scanner (OpenRouter free model — no API key needed) ──
import urllib.request as _urllib_req
import json as _json

_AI_SCAN_PROMPT = """You are a security expert reviewing uploaded bot code.
Analyze the code below for malicious behavior. Look for:
1. Data theft — reading/sending server files, credentials, databases
2. Backdoors — eval/exec with remote payloads, hidden commands
3. Spyware — logging user data secretly and sending it out
4. Credential theft — stealing tokens, passwords, API keys
5. Resource abuse — fork bombs, crypto mining

Reply ONLY with a JSON object (no markdown, no extra text):
{
  "verdict": "SAFE" | "SUSPICIOUS" | "DANGEROUS",
  "risk_score": <0-100>,
  "reason": "<one sentence summary in simple language>",
  "threats": ["<threat1>", "<threat2>"]
}

IMPORTANT: Normal Telegram bots that use telebot, infinity_polling, CommandHandler,
send_message, send_document for their OWN users are SAFE. Do NOT flag standard
Telegram bot patterns as malicious.

CODE TO ANALYZE:
"""

def _ai_scan_code(code: str, filename: str = "file.py") -> Optional[Dict[str, Any]]:
    """Call OpenRouter free AI model to analyze code. Returns result dict or None on error."""
    base_url = os.environ.get("AI_INTEGRATIONS_OPENROUTER_BASE_URL", "").rstrip("/")
    api_key  = os.environ.get("AI_INTEGRATIONS_OPENROUTER_API_KEY", "no-key")
    if not base_url:
        return None

    # Limit code sent to AI — first 6000 chars covers most bots
    code_snippet = code[:6000]
    payload = _json.dumps({
        "model": "google/gemma-4-31b-it:free",
        "max_tokens": 512,
        "temperature": 0.1,
        "messages": [
            {"role": "user", "content": f"{_AI_SCAN_PROMPT}{code_snippet}"}
        ]
    }).encode("utf-8")

    req = _urllib_req.Request(
        f"{base_url}/chat/completions",
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST"
    )
    try:
        with _urllib_req.urlopen(req, timeout=30) as resp:
            body = _json.loads(resp.read())
        content = body["choices"][0]["message"]["content"].strip()
        # Strip markdown fences if any
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        result = _json.loads(content)
        return {
            "ai_verdict":    result.get("verdict", "SAFE"),
            "ai_risk_score": int(result.get("risk_score", 0)),
            "ai_reason":     result.get("reason", ""),
            "ai_threats":    result.get("threats", []),
        }
    except Exception as _ai_err:
        print(f"[ai_scan] error: {_ai_err}", file=sys.stderr)
        return None


def _combined_scan(file_path: str) -> dict:
    """Run pattern scanner + AI scanner and merge results."""
    pattern_result = _scan_file(file_path)
    filename = os.path.basename(file_path)

    # Only send .py / .js / .ts to AI (skip binary / unknown)
    ai_result = None
    if filename.lower().endswith(('.py', '.js', '.ts')):
        try:
            with open(file_path, 'r', errors='ignore') as _f:
                ai_result = _ai_scan_code(_f.read(), filename)
        except Exception:
            pass

    if ai_result is None:
        # AI unavailable — return pattern result as-is
        return pattern_result

    # ── Merge AI + pattern results ────────────────────────────────
    # Final risk = weighted average (AI 60%, pattern 40%)
    ai_risk  = ai_result["ai_risk_score"]
    pat_risk = pattern_result.get("risk_score", 0)
    merged_risk = int(ai_risk * 0.6 + pat_risk * 0.4)

    # AI says DANGEROUS → always REJECT regardless of pattern score
    # AI says SAFE but pattern is DANGEROUS → MANUAL_REVIEW (trust but verify)
    # AI says SUSPICIOUS → at least MANUAL_REVIEW
    ai_v  = ai_result["ai_verdict"]
    pat_v = pattern_result.get("verdict", "SAFE")

    if ai_v == "DANGEROUS":
        verdict = "DANGEROUS"; recommendation = "REJECT"
    elif ai_v == "SUSPICIOUS" or pat_v == "DANGEROUS":
        verdict = "SUSPICIOUS"; recommendation = "MANUAL_REVIEW"
    elif pat_v == "SUSPICIOUS":
        verdict = "SUSPICIOUS"; recommendation = "MANUAL_REVIEW"
    else:
        verdict = "SAFE"; recommendation = "APPROVE"

    all_threats = list(pattern_result.get("all_threats", []))
    for t in ai_result.get("ai_threats", []):
        entry = f"🤖 AI: {t}"
        if entry not in all_threats:
            all_threats.append(entry)

    ai_label = f"🤖 AI ({ai_v} {ai_risk}/100): {ai_result['ai_reason']}"
    if verdict == "DANGEROUS":
        summary = f"⚠️ File DANGEROUS hai! {ai_label}"
    elif verdict == "SUSPICIOUS":
        summary = f"🔍 File suspicious hai. {ai_label}"
    else:
        summary = f"✅ File safe hai. {ai_label}"

    return {
        **pattern_result,
        "verdict":        verdict,
        "risk_score":     merged_risk,
        "recommendation": recommendation,
        "summary":        summary,
        "all_threats":    all_threats,
        "ai_result":      ai_result,
    }

# ═══════════════════════ END SECURITY SCANNER ════════════════════

try:
    from PIL import Image, ImageDraw, ImageFont, ImageFilter  # type: ignore
    _PIL_OK = True
except Exception:
    Image = ImageDraw = ImageFont = ImageFilter = None  # type: ignore
    _PIL_OK = False

try:
    import psutil
except ImportError:
    psutil = None  # graceful — used only for CPU/RAM telemetry


# ═════════════════════════════════════════════════════════════════
#  1. CONSTANTS & CONFIG
# ═════════════════════════════════════════════════════════════════

BASE_DIR = Path(__file__).resolve().parent

DIRS: Dict[str, Path] = {
    "uploads":  BASE_DIR / "storage" / "uploads",
    "encfiles": BASE_DIR / "storage" / "encfiles",
    "data":     BASE_DIR / "storage" / "data",
    "logs":     BASE_DIR / "storage" / "logs",
    "backups":  BASE_DIR / "storage" / "backups",
    "sandbox":  BASE_DIR / "sandbox",
    "tickets":  BASE_DIR / "storage" / "tickets",
    "bot_data": BASE_DIR / "storage" / "bot_data",
    "photos":   BASE_DIR / "storage" / "photos",
}
for _p in DIRS.values():
    _p.mkdir(parents=True, exist_ok=True)

DB_FILE       = DIRS["data"] / "panel_db.json"
SETTINGS_FILE = DIRS["data"] / "panel_settings.json"
AUDIT_FILE    = DIRS["data"] / "audit.log"
KEYRING_FILE  = DIRS["data"] / "keyring.json"   # tiny local cache only

# ┌──────────────────────────────────────────────────────────────┐
# │  BOT TOKEN  add karo.   ││
# └──────────────────────────────────────────────────────────────┘
BOT_TOKEN_HARDCODED = ""   # ← ADD BOT TOKEN
TOKEN = (
    os.environ.get("BOT_TOKEN")
    or os.environ.get("MAIN_BOT_TOKEN")
    or os.environ.get("TELEGRAM_BOT_TOKEN")
    or BOT_TOKEN_HARDCODED
    or ""
).strip()
try:
    OWNER_ID = int(os.environ.get("OWNER_ID", "8189708860"))
except (TypeError, ValueError):
    OWNER_ID = 0
if not TOKEN:
    sys.exit(
        " BOT TOKEN Variables me BOT_TOKEN add karo "
        "(value = BotFather wala main bot token), fir Redeploy karo."
    )
# OWNER_ID is optional. If not set, the very first user to send /start
# automatically becomes the panel owner and is persisted to settings.
# This lets you deploy with ONLY BOT_TOKEN and claim ownership in one tap.

ANNOUNCE_CHANNEL = os.environ.get("ANNOUNCE_CHANNEL", "").strip()
try:
    KEEPALIVE_PORT = int(os.environ.get("PORT", 10460))
except (TypeError, ValueError):
    KEEPALIVE_PORT = 10000

BRAND       = "ᴇꜱʜ x ʜᴏꜱᴛɪɴɢ RΒOT"
BRAND_VER   = "v2.1"
BRAND_TAG   = f"{BRAND} {BRAND_VER}"
SUPPORT_USR = "@iam_eshh"
UPDATE_CH   = "https://t.me/eshxbots"
FOOTER      = f"\n\n<blockquote>{BRAND_TAG}</blockquote>"

# ── START VIDEO (/start main menu) — AUTOPLAY ANIMATION ──
# Original: owner 8189708860 custom_main.mp4 (11s, 1280x720, with audio).
# Telegram videos with audio need a tap to play. Muted mp4 sent as
# animation autoplays + loops with no click, and keeps playing on back.
# file_id is primary (instant). Local mp4 is fallback for redeploys.
# Set START_USE_VIDEO=False to revert to photo.
START_VIDEO_FILE_ID = os.environ.get(
    "START_VIDEO_FILE_ID",
    "BAACAgUAAxkDAAID12qucA1R0WLZ0Gj86p3UFjEAAY7yHwACSSQAAi_zcFWDCm3ZKQ5twj0E",
).strip()
START_ANIMATION_FILE_ID = os.environ.get(
    "START_ANIMATION_FILE_ID",
    "BAACAgUAAxkDAAID12qucA1R0WLZ0Gj86p3UFjEAAY7yHwACSSQAAi_zcFWDCm3ZKQ5twj0E",
).strip()
START_VIDEO_LOCAL = BASE_DIR / "storage" / "videos" / "start.mp4"
START_ANIMATION_LOCAL = BASE_DIR / "storage" / "videos" / "start_autoplay.mp4"
START_USE_VIDEO = os.environ.get("START_USE_VIDEO", "1").strip().lower() not in ("0", "false", "no", "off")
_VIDEO_FILE_IDS: Dict[str, str] = {}

# ─── glyphs (smart contextual symbols + emojis for the UI) ──────
G = {
    # core status / decisions
    "ok":         "✓",        # ✔
    "no":         "\u2718",        # ✘
    "warn":       "\u26A0",        # ⚠
    "arrow":      "\u2192",        # →
    "bullet":     "\u2022",        # •
    "tri":        "\u25B8",        # ▸
    "diamond":    "\u25C6",        # ◆
    "star":       "\u2605",        # ★
    "spark":      "\u2726",        # ✦
    "back":       "↲",        # ◀
    "fwd":        "\u25B6",        # ▶
    "plus":       "\u2295",        # ⊕
    "minus":      "\u2296",        # ⊖
    "rec":        "\u25C9",        # ◉
    "rec_off":    "\u25CB",        # ○

    # dividers / borders
    "div":        "\u2501" * 16,   # ━━━…
    "div_eq":     "\u2550" * 16,   # ═══…
    "div_dash":   "\u2508" * 16,   # ┈┈┈…
    "block_on":   "\u25A0",        # ■
    "block_off":  "\u25A1",        # □
    "border_top": "\u2550" * 16,   # ═══…
    "border_mid": "\u2501" * 16,   # ━━━…
    "border_bot": "\u2550" * 16,   # ═══…

    # process state
    "play":        "‣",        # ▶
    "stop":        "\u25A0",        # ■
    "pause":       "\u2759\u2759",  # ❙❙
    "refresh":     "\u21BB",        # ↻
    "running":     "\u25B6",        # ▶
    "stopped":     "■",        # ■
    "restarting":  "\u21BB",        # ↻
    "stop_bot":    "■",        # ■

    # security / access
    "lock":     "\u25A3",       # ▣
    "unlock":   "\u25A2",       # ▢
    "secure":   "\u25C8",       # ◈
    "key":      "\u2756",       # ❖
    "shield":   "\u25C7",       # ◇
    "ban":      "\u2694",       # ⚔
    "trash":    "\u2716",       # ✖
    "eye":      "\u25C9",       # ◉

    # people
    "user":   "\u25C8",         # ◈
    "users":  "\u25CE",         # ◎
    "crown":  "\u2654",         # ♔

    # money / commerce
    "wallet":   "\u25C6",       # ◆
    "premium":  "⌬",       #⌬
    "lifetime": "\u2736",       # ✶
    "gift":     "\u2726",       # ✦
    "ticket":   "\u273F",       # ✿
    "trophy":   "\u2605",       # ★

    # data / analytics
    "graph":    "\u25AA",       # ▪
    "stats":    "\u25AA",       # ▪
    "chart_up": "\u25B2",       # ▲
    "plan":     "\u25A4",       # ▤

    # comms
    "broadcast": "⚑",      
    "chat":      "\u25AB",      # ▫

    # storage / files
    "folder":   "\u25B8",       # ▸
    "upload":   "\u25B4",       # ▴
    "download": "\u25BE",       # ▾
    "cloud":    "\u2601",       # ☁

    # tools / time / energy
    "settings": "⚙",       # ⚙
    "cog":      "\u2699",       # ⚙
    "bolt":     "\u26A1",       # ⚡
    "clock":    "\u23F1",       # ⏱
}

_TZ_INDEX_DATA = ""

PLAN_LIMITS: Dict[str, Dict[str, Any]] = {
    "free":       {"name": "Free",       "max_bots": 2,   "ram": 128,  "auto_restart": False, "price": 0,    "days": 0},
    "starter":    {"name": "Starter",    "max_bots": 4,   "ram": 256,  "auto_restart": True,  "price": 99,   "days": 30},
    "basic":      {"name": "Basic",      "max_bots": 6,  "ram": 512,  "auto_restart": True,  "price": 199,  "days": 30},
    "pro":        {"name": "Pro",        "max_bots": 8,  "ram": 2048, "auto_restart": True,  "price": 499,  "days": 30},
    "enterprise": {"name": "Enterprise", "max_bots": 10,  "ram": 4096, "auto_restart": True,  "price": 999,  "days": 30},
    "lifetime":   {"name": "Lifetime",   "max_bots": 15, "ram": 8192, "auto_restart": True,  "price": 1999, "days": 36500},
}

PAYMENT_METHODS: Dict[str, Dict[str, Any]] = {
    "admin":   {"name": "Contact Admin", "number": "@iam_eshh", "type": "DM to pay", "tag": "[A]"},
}

SECRET_ENV_NAMES = {
    "BOT_TOKEN", "OWNER_ID", "ERROR_BOT_TOKEN",
    "MONGO_URL", "MONGO_URL_BACKUP",
    "GITHUB_TOKEN", "GITHUB_REPO", "GITHUB_BRANCH", "GITHUB_KEY_REPO",
    "OWNER_IDS", "SESSION_SECRET",
    "DATABASE_URL", "PGDATABASE", "PGHOST", "PGPORT", "PGUSER", "PGPASSWORD",
    "REPLIT_DB_URL", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GROQ_API_KEY",
    "ANNOUNCE_CHANNEL",
}

ENTRY_NODE = ("index.js", "bot.js", "main.js", "app.js")
ENTRY_PY   = ("bot.py", "main.py", "app.py", "run.py")
LOG_RING   = 200
MAX_LOG_SEND = 50
MAX_UPLOAD_BYTES = 75 * 1024 * 1024  # 75 MB hard cap

# Per-menu photos (URLs). Replaceable; safe placeholders included.
# Each menu has its own banner image. We render these locally with
# Pillow at startup so we don't depend on any external image host
# (placehold.co was returning HTML/redirects on Telegram's fetcher,
# which produced "wrong type of the web page content" and made banners
# invisible). After the first upload Telegram gives us a file_id that
# we cache and reuse for all later sends.
_PHOTO_SPECS: Dict[str, Tuple[str, str, str]] = {
    # key:        (headline,        accent-hex, sub-text)
    "welcome":   ("Wᴇʟᴄᴏᴍᴇ",         "#0F172A", "Eꜱʜ x Hᴏꜱᴛɪɴɢ"),
    "main":      ("Mᴀɪɴ Mᴇɴᴜ",       "#1E1B4B", "Cʜᴏᴏꜱᴇ Aɴ Oᴘᴛɪᴏɴ"),
    "tunnel":    ("Pᴜʙʟɪᴄ Uʀʟ",      "#0E7490", "Cʟᴏᴜᴅꜰʟᴀʀᴇ Tᴜɴɴᴇʟ"),
    "bots":      ("Yᴏᴜʀ Bᴏᴛꜱ",       "#0E7490", "Mᴀɴᴀɢᴇ & Dᴇᴘʟᴏʏ"),
    "upload":    ("Uᴘʟᴏᴀᴅ & Dᴇᴘʟᴏʏ", "#4338CA", "Sᴇɴᴅ Yᴏᴜʀ Fɪʟᴇꜱ"),
    "plans":     ("Pʟᴀɴꜱ ",         "#B45309", "Pɪᴄᴋ A Tɪᴇʀ"),
    "buy":       ("Bᴜʏ Pʟᴀɴ",        "#065F46", "Cʜᴇᴄᴋᴏᴜᴛ"),
    "pay":       ("Pᴀʏᴍᴇɴᴛ",         "#0E7490", "Sᴇɴᴅ Pʀᴏᴏꜰ"),
    "profile":   ("Pʀᴏꜰɪʟᴇ",         "#1E3A8A", "Yᴏᴜʀ Aᴄᴄᴏᴜɴᴛ"),
    "wallet":    ("Wᴀʟʟᴇᴛ",          "#047857", "Tᴏᴘ-Uᴘ & Bᴀʟᴀɴᴄᴇ"),
    "referral":  ("Rᴇꜰᴇʀʀᴀʟ",        "#9333EA", "Iɴᴠɪᴛᴇ & Eᴀʀɴ"),
    "help":      ("Hᴇʟᴘ",            "#334155", "Hᴏᴡ Iᴛ Wᴏʀᴋꜱ"),
    "support":   ("Sᴜᴘᴘᴏʀᴛ",         "#0F766E", "Tᴀʟᴋ Tᴏ Uꜱ"),
    "ticket":    ("Tɪᴄᴋᴇᴛꜱ",         "#0F766E", "Oᴘᴇɴ A Tɪᴄᴋᴇᴛ"),
    "admin":     ("Aᴅᴍɪɴ Pᴀɴᴇʟ",     "#7C2D12", "Rᴇꜱᴛʀɪᴄᴛᴇᴅ Aʀᴇᴀ"),
    "stats":     ("Sᴛᴀᴛꜱ",           "#14532D", "Lɪᴠᴇ Nᴜᴍʙᴇʀꜱ"),
    "github":    ("Gɪᴛʜᴜʙ Bᴀᴄᴋᴜᴘ",   "#24292E", "Sʏɴᴄ & Rᴇꜱᴛᴏʀᴇ"),
    "security":  ("Sᴇᴄᴜʀɪᴛʏ",        "#991B1B", "Aᴜᴅɪᴛ & Kᴇʏꜱ"),
    "bot":       ("Bᴏᴛ Cᴏɴᴛʀᴏʟ",     "#1F2937", "Sᴛᴀʀᴛ • Sᴛᴏᴘ • Lᴏɢꜱ"),
    "logs":      ("Lɪᴠᴇ Lᴏɢꜱ",       "#0F172A", "Sᴛᴅᴏᴜᴛ / Sᴛᴅᴇʀʀ"),
    "trial":     ("Fʀᴇᴇ Tʀɪᴀʟ",      "#A21CAF", "Tʀʏ Pʀᴇᴍɪᴜᴍ Fʀᴇᴇ"),
    "coupon":    ("Cᴏᴜᴘᴏɴ",          "#B91C1C", "Rᴇᴅᴇᴇᴍ Cᴏᴅᴇ"),
    "gift":      ("Gɪꜰᴛ Pʟᴀɴ",       "#9D174D", "Sᴇɴᴅ Tᴏ A Fʀɪᴇɴᴅ"),
    "broadcast": ("Bʀᴏᴀᴅᴄᴀꜱᴛ",       "#1E40AF", "Rᴇᴀᴄʜ Aʟʟ Uꜱᴇʀꜱ"),
    "maint":         ("Mᴀɪɴᴛᴇɴᴀɴᴄᴇ",      "#451A03", "Rᴇᴀᴅ-Oɴʟʏ Mᴏᴅᴇ"),
    "gh_browser":    ("Gɪᴛʜᴜʙ Bʀᴏᴡꜱᴇʀ",  "#24292E", "Bʀᴏᴡꜱᴇ & Rᴜɴ"),
    "pay_config":    ("Pᴀʏᴍᴇɴᴛ Cᴏɴꜰɪɢ",   "#065F46", "Rᴀᴛᴇꜱ & Mᴇᴛʜᴏᴅꜱ"),
    "bot_config":    ("Bᴏᴛ Cᴏɴꜰɪɢ",        "#1F2937", "Lɪᴍɪᴛꜱ & Sᴀɴᴅʙᴏx"),
    "appearance":    ("Aᴘᴘᴇᴀʀᴀɴᴄᴇ",        "#4338CA", "Tʜᴇᴍᴇ & Sᴛʏʟᴇ"),
    "templates":     ("Tᴇᴍᴘʟᴀᴛᴇꜱ",         "#0E7490", "Mᴇꜱꜱᴀɢᴇ Tᴇᴍᴘʟᴀᴛᴇꜱ"),
    "referral_adm":  ("Rᴇꜰᴇʀʀᴀʟ Sʏꜱ",     "#9333EA", "Iɴᴠɪᴛᴇ & Eᴀʀɴ"),
    "janitor":       ("Jᴀɴɪᴛᴏʀ",            "#451A03", "Aᴜᴛᴏ-Cʟᴇᴀɴᴜᴘ"),
    "webhooks":      ("Wᴇʙʜᴏᴏᴋꜱ",          "#0F766E", "Hᴏᴏᴋ Mᴀɴᴀɢᴇʀ"),
    "features":      ("Fᴇᴀᴛᴜʀᴇ Fʟᴀɢꜱ",    "#B45309", "Tᴏɢɢʟᴇ Fᴜɴᴄᴛɪᴏɴꜱ"),
    "monitor":       ("Lɪᴠᴇ Mᴏɴɪᴛᴏʀ",      "#14532D", "Rᴇᴀʟ-ᴛɪᴍᴇ"),
    "scheduler":     ("Tᴀꜱᴋ Sᴄʜᴇᴅᴜʟᴇʀ",  "#4338CA", "Aᴜᴛᴏ Tᴀꜱᴋꜱ"),
    "leaderboard":   ("Lᴇᴀᴅᴇʀʙᴏᴀʀᴅ",      "#9D174D", "Tᴏᴘ Uꜱᴇʀꜱ"),
    "subscriptions": ("Sᴜʙꜱᴄʀɪᴘᴛɪᴏɴꜱ",   "#1E3A8A", "Rᴇɴᴇᴡᴀʟꜱ"),
    "rate_limits":   ("Rᴀᴛᴇ Lɪᴍɪᴛꜱ",      "#991B1B", "Tʜʀᴏᴛᴛʟɪɴɢ"),
    "import_export": ("Iᴍᴘᴏʀᴛ / Exᴘᴏʀᴛ",  "#334155", "Cᴏɴꜰɪɢ I/O"),
    "bot_controls":  ("Bᴏᴛ Cᴏɴᴛʀᴏʟꜱ",     "#7C2D12", "Pᴇʀ-Bᴏᴛ Oᴘꜱ"),
    "lang_panel":    ("Lᴀɴɢᴜᴀɢᴇꜱ",         "#1E3A8A", "Mᴜʟᴛɪ-Lᴀɴɢ"),
    "rev_goals":     ("Rᴇᴠᴇɴᴜᴇ Gᴏᴀʟꜱ",    "#047857", "Tᴀʀɢᴇᴛ Tʀᴀᴄᴋɪɴɢ"),
    "admin_2fa":     ("Adᴍɪɴ 2FA",          "#991B1B", "Tᴡᴏ-Fᴀᴄᴛᴏʀ Auth"),
    "coupon_plus":   ("Cᴏᴜᴘᴏɴ Mɢʀ",        "#B91C1C", "Aᴅᴠ Cᴏᴜᴘᴏɴꜱ"),
}

# Filled in by _build_local_photos() at startup. Keys are the same
# as _PHOTO_SPECS; values are local file paths (str) that telebot can
# upload directly. After the first send_photo, _PHOTO_FILE_IDS caches
# the returned file_id so subsequent sends reuse it (zero re-upload).
PHOTOS: Dict[str, str] = {}
_PHOTO_FILE_IDS: Dict[str, str] = {}

_PHOTO_ICONS: Dict[str, str] = {
    "welcome":"✦","main":"◈","tunnel":"⬡","bots":"▸","upload":"▴",
    "plans":"★","buy":"◆","pay":"◉","profile":"◈","wallet":"◆",
    "referral":"✦","help":"◇","support":"▫","ticket":"✿","admin":"⚔",
    "stats":"▲","github":"⬡","security":"▣","bot":"▶","logs":"▸",
    "trial":"✶","coupon":"◉","gift":"✦","broadcast":"⚑","maint":"⚙",
}


def _build_local_photos() -> None:
    """Render every banner once into storage/photos/<key>.png. Safe to
    call repeatedly — existing files are reused. Falls back gracefully
    if Pillow or fonts are unavailable (PHOTOS gets a "" placeholder so
    show_menu's text-only branch still renders the menu instead of
    raising KeyError)."""
    # Guarantee all keys exist so PHOTOS["main"] etc. never KeyErrors.
    for k in _PHOTO_SPECS:
        PHOTOS.setdefault(k, "")
    try:
        from PIL import Image, ImageDraw, ImageFont
    except Exception as e:
        print(f"[photos] Pillow unavailable: {e}", file=sys.stderr, flush=True)
        return
    out_dir = DIRS["photos"]
    out_dir.mkdir(parents=True, exist_ok=True)

    # Pick the first usable bold TTF.
    font_candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
        "/run/current-system/sw/share/X11/fonts/DejaVuSans-Bold.ttf",
    ]
    font_path: Optional[str] = None
    for fp in font_candidates:
        if Path(fp).exists():
            font_path = fp
            break

    def _hex(c: str) -> Tuple[int, int, int]:
        c = c.lstrip("#")
        return int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)

    for key, (text, color, sub) in _PHOTO_SPECS.items():
        # ── Custom admin-uploaded photo takes priority over generated one ──
        # replace_menu_photo() always writes custom_<key>.png as the
        # persistent marker, so this survives restarts and GitHub restores.
        custom_out = out_dir / f"custom_{key}.png"
        if custom_out.exists() and custom_out.stat().st_size > 1024:
            PHOTOS[key] = str(custom_out)
            continue
        out = out_dir / f"{key}.png"
        if out.exists() and out.stat().st_size > 1024:
            PHOTOS[key] = str(out)
            continue
        try:
            r, g, b = _hex(color)
            # Vertical gradient: lighten the top, darken the bottom.
            img = Image.new("RGB", (900, 460), (r, g, b))
            d = ImageDraw.Draw(img)
            for y in range(460):
                t = y / 459.0
                k = 1.0 - 0.55 * t  # darken toward bottom
                d.line(
                    [(0, y), (900, y)],
                    fill=(int(r * k), int(g * k), int(b * k)),
                )
            # Soft accent stripe along the bottom.
            d.rectangle([(0, 430), (900, 460)], fill=(255, 255, 255))
            d.rectangle([(0, 432), (900, 458)], fill=(r, g, b))

            big = (
                ImageFont.truetype(font_path, 78) if font_path
                else ImageFont.load_default()
            )
            small = (
                ImageFont.truetype(font_path, 28) if font_path
                else ImageFont.load_default()
            )

            def _wh(s: str, f) -> Tuple[int, int]:
                try:
                    bb = d.textbbox((0, 0), s, font=f)
                    return bb[2] - bb[0], bb[3] - bb[1]
                except Exception:
                    return d.textsize(s, font=f)  # type: ignore[attr-defined]

            tw, th = _wh(text, big)
            sw, sh = _wh(sub, small)
            cy = (460 - (th + sh + 18)) // 2
            # Drop-shadow for the headline.
            d.text(((900 - tw) // 2 + 3, cy + 3), text, fill=(0, 0, 0), font=big)
            d.text(((900 - tw) // 2, cy), text, fill=(255, 255, 255), font=big)
            d.text(((900 - sw) // 2, cy + th + 18), sub,
                   fill=(230, 230, 230), font=small)

            img.save(out, "PNG", optimize=True)
            PHOTOS[key] = str(out)
        except Exception as e:
            print(f"[photos] {key} failed: {e}", file=sys.stderr, flush=True)


_build_local_photos()


def _resolve_photo(ref: str):
    """Convert a PHOTOS[...] entry into something telebot's send_photo
    can accept. Order: cached file_id → local file handle → URL."""
    fid = _PHOTO_FILE_IDS.get(ref)
    if fid:
        return fid
    if isinstance(ref, str) and ref.startswith(("http://", "https://")):
        return ref
    try:
        return open(ref, "rb")
    except Exception:
        return ref


def _remember_file_id(ref: str, msg) -> None:
    """Stash the file_id Telegram returned so the next send is a single
    cheap reference instead of a full upload."""
    try:
        if msg and getattr(msg, "photo", None):
            _PHOTO_FILE_IDS[ref] = msg.photo[-1].file_id
    except Exception:
        pass


def _get_start_video_ref() -> Optional[str]:
    """Return best autoplay animation ref for /start, or None to fallback to photo.
    Prefers muted animation (autoplay, no click) over original video."""
    if not START_USE_VIDEO:
        return None
    # 1. animation file_id first (muted, autoplay + loop)
    if START_ANIMATION_FILE_ID:
        return START_ANIMATION_FILE_ID
    # 2. local muted mp4 fallback
    try:
        if START_ANIMATION_LOCAL.exists() and START_ANIMATION_LOCAL.stat().st_size > 1024:
            return str(START_ANIMATION_LOCAL)
    except Exception:
        pass
    # 3. original video file_id (needs click, but better than photo)
    if START_VIDEO_FILE_ID:
        return START_VIDEO_FILE_ID
    try:
        if START_VIDEO_LOCAL.exists() and START_VIDEO_LOCAL.stat().st_size > 1024:
            return str(START_VIDEO_LOCAL)
    except Exception:
        pass
    # 4. setting override (admin can rotate without redeploy)
    try:
        v = get_setting("start_video_file_id", "") or get_setting("start_animation_file_id", "")
        if v:
            return str(v).strip()
    except Exception:
        pass
    return None


def _resolve_video(ref: str):
    """Convert video/animation ref to telebot-sendable: cached → file_id → local file."""
    fid = _VIDEO_FILE_IDS.get(ref)
    if fid:
        return fid
    # Telegram file_ids are long opaque strings (not paths/URLs)
    # BAAC = video, CgAC = animation/document
    if isinstance(ref, str) and (ref.startswith("BAAC") or ref.startswith("CgAC") or len(ref) > 40):
        return ref
    if isinstance(ref, str) and ref.startswith(("http://", "https://")):
        return ref
    try:
        return open(ref, "rb")
    except Exception:
        return ref


def _remember_video_file_id(ref: str, msg) -> None:
    try:
        if msg and getattr(msg, "animation", None):
            _VIDEO_FILE_IDS[ref] = msg.animation.file_id
        elif msg and getattr(msg, "video", None):
            _VIDEO_FILE_IDS[ref] = msg.video.file_id
        elif msg and getattr(msg, "document", None):
            try:
                _VIDEO_FILE_IDS[ref] = msg.document.file_id
            except Exception:
                pass
    except Exception:
        pass


# ═════════════════════════════════════════════════════════════════
#  2. STYLED TEXT HELPERS  (small-caps + serif maps)
# ═════════════════════════════════════════════════════════════════

_SC_MAP = str.maketrans(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "ᴀʙᴄᴅᴇꜰɢʜɪᴊᴋʟᴍɴᴏᴘQʀꜱᴛᴜᴠᴡxʏᴢᴀʙᴄᴅᴇꜰɢʜɪᴊᴋʟᴍɴᴏᴘQʀꜱᴛᴜᴠᴡxʏᴢ",
)


def sc(text: Any) -> str:
    """Render text in Unicode small-caps."""
    return str(text).translate(_SC_MAP)


def divider(width: int = 22, ch: str = "\u2501") -> str:
    return ch * width


def bullet(label: str, value: Any, glyph: str = G["bullet"]) -> str:
    return f"{glyph}  <b>{esc(label)}</b>: <code>{esc(value)}</code>"


# ═════════════════════════════════════════════════════════════════
#  3. JSON DB  (atomic writes, RLock-guarded)
# ═════════════════════════════════════════════════════════════════

_db_lock = threading.RLock()


def _atomic_write(path: Path, data: Any) -> None:
    """Write JSON atomically. Falls back to copy+rename if `replace` fails
    across filesystem boundaries (some Docker volume setups)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(data, indent=2, default=str, ensure_ascii=False),
        encoding="utf-8",
    )
    try:
        tmp.replace(path)
    except OSError:
        # Cross-device or permission issue — fall back to copy+unlink
        try:
            shutil.copyfile(str(tmp), str(path))
            tmp.unlink(missing_ok=True)  # type: ignore[call-arg]
        except TypeError:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        # corrupt — keep a copy and reset
        try:
            path.replace(path.with_suffix(".corrupt"))
        except Exception:
            pass
        return default


# ── in-memory cache for db / settings (mtime-invalidated) ─────────
# JSON disk reads were happening on EVERY db_load() call (3-5 times per
# button click). With many users this turns the bot into molasses.
# We cache the parsed dict and only re-read from disk when the file's
# mtime changes (i.e. someone wrote to it). Cache entries are
# `(mtime, data)`. Writes bump mtime so other readers refresh.
_DB_CACHE: Dict[str, Tuple[float, Any]] = {}


def _cached_load_ro(path: Path, default: Any) -> Any:
    """Return the cached parsed JSON at `path` WITHOUT a defensive
    copy. Caller MUST NOT mutate the result. Use for hot read-only
    paths (get_setting, is_admin, find_bot, …) — this avoids the
    enormous deepcopy cost on every callback."""
    key = str(path)
    try:
        mtime = path.stat().st_mtime
    except FileNotFoundError:
        mtime = 0.0
    cached = _DB_CACHE.get(key)
    if cached and cached[0] == mtime:
        return cached[1]
    d = _load_json(path, default)
    _DB_CACHE[key] = (mtime, d)
    return d


def _cached_load(path: Path, default: Any) -> Any:
    """Defensive variant: returns a deep copy so callers can mutate
    safely without poisoning the cache. ~5-10× faster than the old
    json round-trip."""
    return copy.deepcopy(_cached_load_ro(path, default))


def _cache_invalidate(path: Path) -> None:
    _DB_CACHE.pop(str(path), None)


# Default skeleton applied to a freshly-loaded `user_data.json`. Kept
# at module scope so we can install it once into the cached object
# (`db_load_ro`) and skip the per-call setdefault loop entirely.
_DB_DEFAULT_KEYS: Tuple[Tuple[str, Any], ...] = (
    ("users", {}),
    ("bots", {}),
    ("payments", []),
    ("admins", {}),
    ("audit", []),
    ("coupons", {}),
    ("tickets", {}),
    ("scheduled_broadcasts", []),
    ("notes", {}),
    ("rate_violations", {}),
    ("scan_log", []),        # security scan history for admin panel
)


def _ensure_db_defaults(d: Dict[str, Any]) -> Dict[str, Any]:
    for k, v in _DB_DEFAULT_KEYS:
        if k not in d:
            d[k] = copy.deepcopy(v) if isinstance(v, (dict, list)) else v
    return d


def db_load() -> Dict[str, Any]:
    """Load a MUTABLE copy of the user database. Use when you intend
    to mutate and `db_save()` back. For pure reads, use db_load_ro()
    — much faster."""
    with _db_lock:
        d = _cached_load(DB_FILE, {})
    return _ensure_db_defaults(d)


def db_load_ro() -> Dict[str, Any]:
    """Read-only DB access. NEVER mutate the result — it's the cached
    object itself. Mutation will silently corrupt every other reader
    sharing the cache."""
    with _db_lock:
        d = _cached_load_ro(DB_FILE, {})
    return _ensure_db_defaults(d)


def db_save(d: Dict[str, Any]) -> None:
    with _db_lock:
        _atomic_write(DB_FILE, d)
        _cache_invalidate(DB_FILE)


def settings_load() -> Dict[str, Any]:
    with _db_lock:
        return _cached_load(SETTINGS_FILE, {})


def settings_load_ro() -> Dict[str, Any]:
    """Read-only fast path — DO NOT mutate."""
    with _db_lock:
        return _cached_load_ro(SETTINGS_FILE, {})


def settings_save(d: Dict[str, Any]) -> None:
    with _db_lock:
        _atomic_write(SETTINGS_FILE, d)
        _cache_invalidate(SETTINGS_FILE)


def get_setting(key: str, default: Any = None) -> Any:
    # Hot path. Use the no-copy reader because we only `.get()` —
    # we never mutate the dict.
    return settings_load_ro().get(key, default)


def set_setting(key: str, value: Any) -> None:
    s = settings_load()
    s[key] = value
    settings_save(s)


def cache_clear_all() -> None:
    """Drop every cached load so the next read re-parses from disk.
    Used by the Settings → Reload button after manual file edits."""
    with _db_lock:
        _DB_CACHE.clear()


# ═════════════════════════════════════════════════════════════════
#  4. UTILITY  HELPERS
# ═════════════════════════════════════════════════════════════════

def esc(s: Any = "") -> str:
    return (
        str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def ts_iso() -> str:
    return now_utc().isoformat()


def safe_name(s: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9_-]+", "_", s or "").strip("_")
    return (s or "bot")[:48]


def fmt_bytes(n: float) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def fmt_dur(ms: int) -> str:
    if ms is None or ms < 0:
        return "—"
    s = ms // 1000
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    parts: List[str] = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


def fmt_ts(iso: Optional[str]) -> str:
    if not iso:
        return "—"
    try:
        dt = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return str(iso)


def rmrf(p: str | Path) -> None:
    try:
        shutil.rmtree(p, ignore_errors=True)
    except Exception:
        pass


def rand_token(n: int = 8) -> str:
    return "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(n))


def safe_path_join(root: Path, *parts: str) -> Path:
    """Path-traversal safe join. Raises ValueError if escape detected."""
    final = (root / Path(*parts)).resolve()
    rootp = root.resolve()
    if rootp not in final.parents and final != rootp:
        raise ValueError("path traversal detected")
    return final


def is_owner(uid: int) -> bool:
    return int(uid) == OWNER_ID


def is_admin(uid: int) -> bool:
    if is_owner(uid):
        return True
    # Read-only fast path — no deepcopy.
    return str(uid) in db_load_ro().get("admins", {})


def admin_role(uid: int) -> str:
    if is_owner(uid):
        return "owner"
    return db_load_ro().get("admins", {}).get(str(uid), {}).get("role", "")


def admin_can(uid: int, action: str) -> bool:
    """
    Permission matrix.
      owner          → everything
      full-access    → everything except adding admins
      manage-users   → ban / give-plan / view users / approve payments / reply tickets
      view-only      → view stats only
    """
    role = admin_role(uid)
    if role == "owner":
        return True
    if role == "full-access":
        return action != "manage_admins"
    if role == "manage-users":
        return action in {
            "view_stats", "view_users", "find_user", "ban_user", "give_plan",
            "approve_payment", "reply_ticket", "broadcast_view", "user_note",
        }
    if role == "view-only":
        return action in {"view_stats", "view_users", "find_user"}
    return False


# ═════════════════════════════════════════════════════════════════
#  5. AUDIT LOG  (admin actions)
# ═════════════════════════════════════════════════════════════════

def audit(uid: int, action: str, detail: str = "") -> None:
    line = f"[{ts_iso()}] uid={uid} action={action} {detail}\n"
    try:
        with AUDIT_FILE.open("a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass
    with _db_lock:
        d = db_load()
        d["audit"].append({"ts": ts_iso(), "uid": uid, "action": action, "detail": detail})
        d["audit"] = d["audit"][-500:]
        db_save(d)


# ═════════════════════════════════════════════════════════════════
#  6. ENCRYPTION   +   GITHUB-BACKED KEY RING
# ═════════════════════════════════════════════════════════════════
#
#  Every uploaded user file is encrypted with a unique Fernet key.
#  Keys live ONLY in a private GitHub key-repo (or a memory cache
#  if GitHub keyring is not configured — see warn() below).
#  Local disk only ever stores ciphertext.
# ═════════════════════════════════════════════════════════════════

class KeyRing:
    """Encryption key store. Tries GitHub first, then in-memory cache."""

    def __init__(self) -> None:
        self._mem: Dict[str, bytes] = {}
        self._lock = threading.Lock()

    # ── GitHub config ────────────────────────────────────────────
    @staticmethod
    def _gh_token() -> str:
        return (os.environ.get("GITHUB_TOKEN") or get_setting("github_token", "") or "").strip()

    @staticmethod
    def _gh_key_repo() -> str:
        # Prefer a separate repo for keys; falls back to backup repo
        return (
            os.environ.get("GITHUB_KEY_REPO")
            or get_setting("github_key_repo", "")
            or os.environ.get("GITHUB_REPO")
            or get_setting("github_repo", "")
            or ""
        ).strip()

    def gh_enabled(self) -> bool:
        return bool(self._gh_token() and "/" in self._gh_key_repo())

    def _gh_request(self, method: str, path: str, **kw) -> Optional[requests.Response]:
        if not self.gh_enabled():
            return None
        url = f"https://api.github.com/repos/{self._gh_key_repo()}/{path.lstrip('/')}"
        h = kw.pop("headers", {}) or {}
        h.setdefault("Authorization", f"token {self._gh_token()}")
        h.setdefault("Accept", "application/vnd.github+json")
        h.setdefault("User-Agent", "simran-hosting-rbot/2.1")
        try:
            return requests.request(method, url, headers=h, timeout=30, **kw)
        except Exception:
            return None

    # ── public API ───────────────────────────────────────────────
    def new_key(self) -> bytes:
        return Fernet.generate_key()

    def store(self, key_id: str, key: bytes, meta: Dict[str, Any]) -> bool:
        """Push key+meta to GitHub. Memory-cache as fallback only."""
        with self._lock:
            self._mem[key_id] = key

        body = {"key": key.decode(), "meta": meta, "ts": ts_iso()}
        payload = json.dumps(body, indent=2).encode()
        if not self.gh_enabled():
            # memory only — write a tiny encrypted local cache so a panel
            # restart does not lose access. The cache is encrypted with a
            # key derived from BOT_TOKEN+OWNER_ID, never plain text.
            self._cache_local(key_id, key)
            return True

        gh_path = f"keys/{key_id}.json"
        sha: Optional[str] = None
        r = self._gh_request("GET", f"contents/{gh_path}")
        if r is not None and r.status_code == 200:
            try:
                sha = r.json().get("sha")
            except Exception:
                pass
        put_body: Dict[str, Any] = {
            "message": f"key {key_id} stored {ts_iso()}",
            "content": base64.b64encode(payload).decode(),
        }
        if sha:
            put_body["sha"] = sha
        r2 = self._gh_request("PUT", f"contents/{gh_path}", json=put_body)
        ok = r2 is not None and r2.status_code in (200, 201)
        if not ok:
            # last-ditch local encrypted cache so we don't lose access
            self._cache_local(key_id, key)
        return ok

    def fetch(self, key_id: str) -> Optional[bytes]:
        with self._lock:
            cached = self._mem.get(key_id)
        if cached:
            return cached
        if self.gh_enabled():
            r = self._gh_request("GET", f"contents/keys/{key_id}.json")
            if r is not None and r.status_code == 200:
                try:
                    raw = base64.b64decode(r.json()["content"])
                    blob = json.loads(raw.decode())
                    key = blob["key"].encode()
                    with self._lock:
                        self._mem[key_id] = key
                    return key
                except Exception:
                    pass
        # local encrypted cache fallback
        return self._uncache_local(key_id)

    def wipe(self, key_id: str) -> None:
        with self._lock:
            self._mem.pop(key_id, None)

    def remove(self, key_id: str) -> None:
        """Delete key everywhere."""
        self.wipe(key_id)
        kp = DIRS["data"] / "keycache" / f"{key_id}.bin"
        try:
            if kp.exists():
                kp.unlink()
        except Exception:
            pass
        if self.gh_enabled():
            r = self._gh_request("GET", f"contents/keys/{key_id}.json")
            if r is not None and r.status_code == 200:
                try:
                    sha = r.json().get("sha")
                    if sha:
                        self._gh_request(
                            "DELETE",
                            f"contents/keys/{key_id}.json",
                            json={"message": f"remove {key_id}", "sha": sha},
                        )
                except Exception:
                    pass

    # ── fallback local encrypted cache ────────────────────────────
    def _local_master(self) -> bytes:
        material = f"{TOKEN}|{OWNER_ID}".encode()
        digest = hashlib.sha256(material).digest()
        return base64.urlsafe_b64encode(digest)

    def _cache_local(self, key_id: str, key: bytes) -> None:
        try:
            d = DIRS["data"] / "keycache"
            d.mkdir(parents=True, exist_ok=True)
            f = Fernet(self._local_master())
            (d / f"{key_id}.bin").write_bytes(f.encrypt(key))
        except Exception:
            pass

    def _uncache_local(self, key_id: str) -> Optional[bytes]:
        p = DIRS["data"] / "keycache" / f"{key_id}.bin"
        if not p.exists():
            return None
        try:
            f = Fernet(self._local_master())
            key = f.decrypt(p.read_bytes())
            with self._lock:
                self._mem[key_id] = key
            return key
        except Exception:
            return None


KEYRING = KeyRing()


def encrypt_file(plain: bytes) -> Tuple[str, bytes, bytes]:
    """
    Returns (key_id, key, ciphertext).
    Caller is responsible for storing key via KEYRING.store(key_id, key, meta).
    """
    key = KEYRING.new_key()
    f = Fernet(key)
    cipher = f.encrypt(plain)
    key_id = secrets.token_urlsafe(16)
    return key_id, key, cipher


def decrypt_with(key: bytes, cipher: bytes) -> bytes:
    return Fernet(key).decrypt(cipher)


def write_encrypted(path: Path, key: bytes, plain: bytes) -> None:
    f = Fernet(key)
    path.write_bytes(f.encrypt(plain))


def read_encrypted(path: Path, key: bytes) -> bytes:
    return Fernet(key).decrypt(path.read_bytes())


# ═════════════════════════════════════════════════════════════════
#  7. RATE LIMITER  +  SUSPICIOUS-ACTIVITY  WATCHDOG
# ═════════════════════════════════════════════════════════════════

class RateLimiter:
    def __init__(self, max_actions: int = 30, window_s: int = 60) -> None:
        self.max = max_actions
        self.window = window_s
        self._bucket: Dict[int, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, uid: int) -> bool:
        now = time.time()
        with self._lock:
            q = self._bucket[uid]
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.max:
                return False
            q.append(now)
            return True

    def hits(self, uid: int) -> int:
        with self._lock:
            return len(self._bucket.get(uid, []))


RATE = RateLimiter(max_actions=40, window_s=60)
UPLOAD_RATE = RateLimiter(max_actions=8, window_s=300)


def maybe_auto_ban(uid: int, reason: str) -> None:
    """If a user repeatedly trips rate limits, auto-ban them and notify owner."""
    d = db_load()
    rv = d.get("rate_violations", {})
    rv[str(uid)] = int(rv.get(str(uid), 0)) + 1
    d["rate_violations"] = rv
    db_save(d)
    if rv[str(uid)] >= 5:
        u = d["users"].get(str(uid))
        if u and not u.get("banned"):
            u["banned"] = True
            u["ban_reason"] = f"auto: {reason}"
            db_save(d)
            audit(0, "auto_ban", f"uid={uid} reason={reason}")
            notify_owner(
                f"<b>{G['warn']} sᴜsᴘɪᴄɪᴏᴜs ᴀᴄᴛɪᴠɪᴛʏ</b>\n\n"
                f"User <code>{uid}</code> auto-banned ({esc(reason)})."
            )


# ═════════════════════════════════════════════════════════════════
#  8. BOT INSTANCE  +  KEEP-ALIVE  WEB SERVER
# ═════════════════════════════════════════════════════════════════

bot = telebot.TeleBot(TOKEN, parse_mode="HTML", threaded=True, num_threads=8)

# ───────────────────────────────────────────────────────────────────
# UI style wrapper — every outgoing message/caption is rendered as a
# bold blockquote so the panel feels uniform. Only applies when the
# parse mode is HTML (the default for this bot).
# ───────────────────────────────────────────────────────────────────
_QUOTE_OPEN  = "<blockquote><b>"
_QUOTE_CLOSE = "</b></blockquote>"

def _is_html_mode(pm) -> bool:
    if pm is None:
        return True  # bot default is HTML
    try:
        return str(pm).strip().lower() == "html"
    except Exception:
        return False

def _wrap_quote_bold(text):
    if text is None:
        return text
    s = str(text)
    if not s.strip():
        return s
    if s.startswith(_QUOTE_OPEN):
        return s
    return f"{_QUOTE_OPEN}{s}{_QUOTE_CLOSE}"

def _patch_bot_styling(b):
    orig_send         = b.send_message
    orig_reply        = b.reply_to
    orig_edit_text    = b.edit_message_text
    orig_edit_caption = b.edit_message_caption
    orig_send_photo   = b.send_photo
    orig_send_video   = b.send_video
    orig_send_doc     = b.send_document
    orig_send_anim    = getattr(b, "send_animation", None)

    def send_message(chat_id, text, *args, **kwargs):
        if _is_html_mode(kwargs.get("parse_mode")):
            text = _wrap_quote_bold(text)
        return orig_send(chat_id, text, *args, **kwargs)

    def reply_to(message, text, *args, **kwargs):
        if _is_html_mode(kwargs.get("parse_mode")):
            text = _wrap_quote_bold(text)
        return orig_reply(message, text, *args, **kwargs)

    def edit_message_text(text, *args, **kwargs):
        if _is_html_mode(kwargs.get("parse_mode")):
            text = _wrap_quote_bold(text)
        return orig_edit_text(text, *args, **kwargs)

    def edit_message_caption(*args, **kwargs):
        if _is_html_mode(kwargs.get("parse_mode")):
            if "caption" in kwargs:
                kwargs["caption"] = _wrap_quote_bold(kwargs.get("caption"))
        return orig_edit_caption(*args, **kwargs)

    def send_photo(chat_id, photo, *args, **kwargs):
        if _is_html_mode(kwargs.get("parse_mode")) and kwargs.get("caption"):
            kwargs["caption"] = _wrap_quote_bold(kwargs["caption"])
        return orig_send_photo(chat_id, photo, *args, **kwargs)

    def send_video(chat_id, video, *args, **kwargs):
        if _is_html_mode(kwargs.get("parse_mode")) and kwargs.get("caption"):
            kwargs["caption"] = _wrap_quote_bold(kwargs["caption"])
        return orig_send_video(chat_id, video, *args, **kwargs)

    def send_document(chat_id, document, *args, **kwargs):
        if _is_html_mode(kwargs.get("parse_mode")) and kwargs.get("caption"):
            kwargs["caption"] = _wrap_quote_bold(kwargs["caption"])
        return orig_send_doc(chat_id, document, *args, **kwargs)

    b.send_message         = send_message
    b.reply_to             = reply_to
    b.edit_message_text    = edit_message_text
    b.edit_message_caption = edit_message_caption
    b.send_photo           = send_photo
    b.send_video           = send_video
    b.send_document        = send_document
    if orig_send_anim is not None:
        def send_animation(chat_id, animation, *args, **kwargs):
            if _is_html_mode(kwargs.get("parse_mode")) and kwargs.get("caption"):
                kwargs["caption"] = _wrap_quote_bold(kwargs["caption"])
            return orig_send_anim(chat_id, animation, *args, **kwargs)
        b.send_animation = send_animation

_patch_bot_styling(bot)
USER_STATES: Dict[int, Dict[str, Any]] = {}
START_TS = int(time.time() * 1000)

# ── Flask keep-alive ─────────────────────────────────────────────
_ka = Flask(__name__)


@_ka.route("/")
def _ka_root() -> Any:  # noqa: D401
    return jsonify(
        {
            "ok": True,
            "brand": BRAND_TAG,
            "uptime_ms": int(time.time() * 1000) - START_TS,
            "running_bots": len(RUNNING) if "RUNNING" in globals() else 0,
        }
    )


@_ka.route("/health")
def _ka_health() -> Any:
    return jsonify({"status": "alive"})


def _start_keepalive() -> None:
    def _run() -> None:
        try:
            _ka.run(host="0.0.0.0", port=KEEPALIVE_PORT, debug=False, use_reloader=False)
        except Exception as e:
            print(f"[keepalive] {e}")
    threading.Thread(target=_run, daemon=True).start()


# ═════════════════════════════════════════════════════════════════
#  9. UI HELPERS  —  show_menu (edit, never spam) + keyboards
# ═════════════════════════════════════════════════════════════════

# ── PATCHED: ghost-delete fix ─────────────────────────────────────
# Logs send/edit failures to stderr instead of swallowing them.
def _log_err(where: str, exc: BaseException) -> None:
    try:
        print(f"[show_menu:{where}] {type(exc).__name__}: {exc}",
              file=sys.stderr, flush=True)
    except Exception:
        pass


# HTML-safe truncation: never cut a message in the middle of an open tag.
_TAG_RE = re.compile(r"<(/?)([a-zA-Z][a-zA-Z0-9]*)(\s[^>]*)?>")

def _html_safe_truncate(s: str, limit: int = 1024) -> str:
    if len(s) <= limit:
        return s
    cut = s[: limit - 1]
    last_lt = cut.rfind("<")
    last_gt = cut.rfind(">")
    if last_lt > last_gt:
        cut = cut[:last_lt]
    stack: List[str] = []
    for m in _TAG_RE.finditer(cut):
        closing, name = m.group(1), m.group(2).lower()
        if closing:
            if stack and stack[-1] == name:
                stack.pop()
        else:
            stack.append(name)
    closes = "".join(f"</{t}>" for t in reversed(stack))
    return cut + "…" + closes


def show_menu(
    chat_id: int,
    photo_url: str,
    caption: str,
    kb: types.InlineKeyboardMarkup,
    call: Optional[types.CallbackQuery] = None,
) -> None:
    """Send/edit a photo + caption + buttons. Tries to edit when from a
    callback. NEVER deletes the old message until the replacement has
    been confirmed sent — prevents 'ghost delete' bug."""
    cap = _html_safe_truncate(caption, 1024)

    # Any in-flight loading animation on this message is now stale —
    # we are about to overwrite the message with the real menu.
    if call and call.message:
        _cancel_loading(call.message.chat.id, call.message.message_id)

    # ── 1. Try in-place edits when the previous message has media ──
    # Main menu is now animation/video, so admin photo must edit from those too.
    if call and call.message and call.message.content_type in ("photo", "video", "animation"):
        msg = call.message

        # 1a. Try to swap photo + caption together.
        # Use a cached file_id if we have one; otherwise resolve the
        # ref through `_resolve_photo` so local file paths are uploaded
        # as a real file handle instead of being mistaken for a URL
        # (which causes Telegram's "URL host is empty" error).
        cached_fid = _PHOTO_FILE_IDS.get(photo_url)
        media_ref = cached_fid if cached_fid else _resolve_photo(photo_url)
        try:
            bot.edit_message_media(
                media=types.InputMediaPhoto(media_ref, caption=cap, parse_mode="HTML"),
                chat_id=chat_id,
                message_id=msg.message_id,
                reply_markup=kb,
            )
            return
        except ApiTelegramException as e:
            if "message is not modified" in str(e).lower():
                return
            _log_err("edit_message_media", e)
        except Exception as e:
            _log_err("edit_message_media", e)
        finally:
            try:
                if hasattr(media_ref, "close"):
                    media_ref.close()
            except Exception:
                pass

        # 1b. Photo swap failed — keep existing photo, change only caption.
        # This is the safe path when Telegram can't fetch the new photo URL.
        try:
            bot.edit_message_caption(
                cap,
                chat_id=chat_id,
                message_id=msg.message_id,
                reply_markup=kb,
                parse_mode="HTML",
            )
            return
        except ApiTelegramException as e:
            if "message is not modified" in str(e).lower():
                return
            _log_err("edit_message_caption", e)
        except Exception as e:
            _log_err("edit_message_caption", e)

        # 1c. HTML parse blew up — retry caption WITHOUT parse_mode.
        try:
            plain = re.sub(r"<[^>]+>", "", cap)
            bot.edit_message_caption(
                plain,
                chat_id=chat_id,
                message_id=msg.message_id,
                reply_markup=kb,
            )
            return
        except Exception as e:
            _log_err("edit_message_caption(plain)", e)

    # ── 2. Send a brand-new message FIRST, then delete the old one. ──
    new_msg_id: Optional[int] = None

    try:
        m = bot.send_photo(chat_id, _resolve_photo(photo_url), caption=cap,
                           parse_mode="HTML", reply_markup=kb)
        new_msg_id = m.message_id
        _remember_file_id(photo_url, m)
    except Exception as e:
        _log_err("send_photo", e)

    if new_msg_id is None:
        try:
            m = bot.send_message(
                chat_id, cap, parse_mode="HTML", reply_markup=kb,
                disable_web_page_preview=True,
            )
            new_msg_id = m.message_id
        except Exception as e:
            _log_err("send_message(html)", e)

    if new_msg_id is None:
        try:
            plain = re.sub(r"<[^>]+>", "", cap)
            m = bot.send_message(
                chat_id, plain or "…", reply_markup=kb,
                disable_web_page_preview=True,
            )
            new_msg_id = m.message_id
        except Exception as e:
            _log_err("send_message(plain)", e)

    # Only NOW is it safe to remove the old message.
    if new_msg_id is not None and call and call.message:
        try:
            bot.delete_message(chat_id, call.message.message_id)
        except Exception as e:
            _log_err("delete_message", e)


def show_start_menu(
    chat_id: int,
    caption: str,
    kb: types.InlineKeyboardMarkup,
    call: Optional[types.CallbackQuery] = None,
    photo_fallback: str = "",
) -> None:
    """Start-menu sender: autoplay animation if configured, else photo fallback.
    Animation (muted mp4) autoplays + loops with no click, and keeps playing
    when navigating back. Uses same delete-after-send safety as show_menu."""
    vref = _get_start_video_ref()
    if not vref:
        show_menu(chat_id, photo_fallback, caption, kb, call=call)
        return
    cap = _html_safe_truncate(caption, 1024)
    if call and call.message:
        _cancel_loading(call.message.chat.id, call.message.message_id)

    # 1. Try in-place edit when previous message has media.
    # Animation type keeps autoplay on back-navigation.
    if call and call.message and call.message.content_type in ("photo", "video", "animation"):
        msg = call.message
        media_ref = _resolve_video(vref)
        try:
            bot.edit_message_media(
                media=types.InputMediaAnimation(media_ref, caption=cap, parse_mode="HTML"),
                chat_id=chat_id,
                message_id=msg.message_id,
                reply_markup=kb,
            )
            return
        except ApiTelegramException as e:
            if "message is not modified" in str(e).lower():
                return
            _log_err("edit_message_media(animation)", e)
        except Exception as e:
            _log_err("edit_message_media(animation)", e)
        finally:
            try:
                if hasattr(media_ref, "close"):
                    media_ref.close()
            except Exception:
                pass
        # video-type fallback if animation edit rejected (old video file_id)
        try:
            media_ref2 = _resolve_video(vref)
            bot.edit_message_media(
                media=types.InputMediaVideo(media_ref2, caption=cap, parse_mode="HTML"),
                chat_id=chat_id,
                message_id=msg.message_id,
                reply_markup=kb,
            )
            try:
                if hasattr(media_ref2, "close"):
                    media_ref2.close()
            except Exception:
                pass
            return
        except Exception as e:
            _log_err("edit_message_media(video-fallback)", e)
        # caption-only fallback (keeps old media, updates text+buttons)
        try:
            bot.edit_message_caption(
                cap, chat_id=chat_id, message_id=msg.message_id,
                reply_markup=kb, parse_mode="HTML",
            )
            return
        except Exception as e:
            _log_err("edit_message_caption(start)", e)

    # 2. Send new animation first (autoplay, no click), then delete old.
    new_msg_id: Optional[int] = None
    try:
        m = bot.send_animation(chat_id, _resolve_video(vref), caption=cap,
                               parse_mode="HTML", reply_markup=kb)
        new_msg_id = m.message_id
        _remember_video_file_id(vref, m)
    except Exception as e:
        _log_err("send_animation(start)", e)
    # fallback to send_video if animation send fails
    if new_msg_id is None:
        try:
            m = bot.send_video(chat_id, _resolve_video(vref), caption=cap,
                               parse_mode="HTML", reply_markup=kb)
            new_msg_id = m.message_id
            _remember_video_file_id(vref, m)
        except Exception as e:
            _log_err("send_video(start)", e)

    if new_msg_id is None and photo_fallback:
        show_menu(chat_id, photo_fallback, caption, kb, call=call)
        return
    if new_msg_id is None:
        try:
            m = bot.send_message(chat_id, cap, parse_mode="HTML",
                                 reply_markup=kb, disable_web_page_preview=True)
            new_msg_id = m.message_id
        except Exception as e:
            _log_err("send_message(start-fallback)", e)

    if new_msg_id is not None and call and call.message:
        try:
            bot.delete_message(chat_id, call.message.message_id)
        except Exception as e:
            _log_err("delete_message(start)", e)


def show_text(
    chat_id: int, text: str, kb: Optional[types.InlineKeyboardMarkup] = None,
    call: Optional[types.CallbackQuery] = None,
) -> None:
    """Send/edit a plain-text message with the same delete-after-send
    safety as show_menu."""
    text = _html_safe_truncate(text, 4096)

    if call and call.message:
        _cancel_loading(call.message.chat.id, call.message.message_id)

    if call and call.message and call.message.content_type == "text":
        try:
            bot.edit_message_text(
                text, chat_id=chat_id, message_id=call.message.message_id,
                reply_markup=kb, parse_mode="HTML", disable_web_page_preview=True,
            )
            return
        except ApiTelegramException as e:
            if "message is not modified" in str(e).lower():
                return
            _log_err("edit_message_text", e)
        except Exception as e:
            _log_err("edit_message_text", e)

        try:
            plain = re.sub(r"<[^>]+>", "", text)
            bot.edit_message_text(
                plain, chat_id=chat_id, message_id=call.message.message_id,
                reply_markup=kb, disable_web_page_preview=True,
            )
            return
        except Exception as e:
            _log_err("edit_message_text(plain)", e)

    new_msg_id: Optional[int] = None
    try:
        m = bot.send_message(chat_id, text, parse_mode="HTML", reply_markup=kb,
                             disable_web_page_preview=True)
        new_msg_id = m.message_id
    except Exception as e:
        _log_err("send_message(html)", e)

    if new_msg_id is None:
        try:
            plain = re.sub(r"<[^>]+>", "", text)
            m = bot.send_message(chat_id, plain or "…", reply_markup=kb,
                                 disable_web_page_preview=True)
            new_msg_id = m.message_id
        except Exception as e:
            _log_err("send_message(plain)", e)

    if (new_msg_id is not None and call and call.message
            and call.message.content_type != "text"):
        try:
            bot.delete_message(chat_id, call.message.message_id)
        except Exception as e:
            _log_err("delete_message", e)


_LOCALE_INDEX_DATA = ""


# ── keyboards ──────────────────────────────────────────────────
def main_menu_kb(admin: bool = False) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn(f"  Mʏ Bᴏᴛꜱ",   callback_data="menu_bots",     style="primary"),
        Btn(f" Uᴘʟᴏᴀᴅ Bᴏᴛ",   callback_data="menu_upload",   style="primary"),
    )
    kb.add(
        Btn(f"Pʟᴀɴꜱ",        callback_data="menu_plans",    style="primary"),
        Btn(f" Bᴜʏ Pʟᴀɴ",    callback_data="menu_buy",      style="primary"),
    )
    kb.add(
        Btn(f"Rᴇꜰᴇʀʀᴀʟ",    callback_data="menu_referral", style="primary"),
        Btn(f"Pʀᴏꜰɪʟᴇ",      callback_data="menu_profile",  style="primary"),
    )
    kb.add(
        Btn(f" Wᴀʟʟᴇᴛ",     callback_data="menu_wallet",   style="primary"),
        Btn(f"Tɪᴄᴋᴇᴛꜱ",    callback_data="menu_tickets",  style="primary"),
    )
    kb.add(
        Btn(f" Fʀᴇᴇ Tʀɪᴀʟ",    callback_data="menu_trial",    style="primary"),
        Btn(f" Cᴏᴜᴘᴏɴ",        callback_data="menu_coupon",   style="primary"),
    )
    kb.add(
        Btn(f"Hᴇʟᴘ",          callback_data="menu_help",     style="primary"),
        Btn(f"Sᴜᴘᴘᴏʀᴛ", callback_data="menu_support",  style="primary"),
    )
    kb.add(
        Btn(f" Mʏ Sᴛᴀᴛꜱ",    callback_data="menu_stats",    style="primary"),
    )
    if admin:
        kb.add(Btn(f"Aᴅᴍɪɴ Pᴀɴᴇʟ", callback_data="menu_admin", style="danger"))

    return kb


def back_main_kb() -> types.InlineKeyboardMarkup:
    return types.InlineKeyboardMarkup().add(
        Btn(f"{G['back']}  Mᴀɪɴ Mᴇɴᴜ", callback_data="menu_main", style="danger"))


def back_admin_kb() -> types.InlineKeyboardMarkup:
    return types.InlineKeyboardMarkup().add(
        Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))


def back_kb(target: str, label: str = "Back") -> types.InlineKeyboardMarkup:
    return types.InlineKeyboardMarkup().add(
        Btn(f"{G['back']}  {sc(label)}", callback_data=target, style="danger"))


def plans_kb() -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup()
    for k, v in PLAN_LIMITS.items():
        price = "Free" if v["price"] == 0 else f"{v['price']}\u09F3"
        style = "success" if v["price"] == 0 else "primary"
        kb.add(Btn(
            f"{G['star']}  {sc(v['name'])}  {G['bullet']}  {price}",
            callback_data=f"plan_view_{k}", style=style))
    kb.add(Btn(f"{G['back']}  Mᴀɪɴ Mᴇɴᴜ", callback_data="menu_main", style="danger"))
    return kb


def payments_kb(plan: Optional[str] = None) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=2)
    suffix = f"_{plan}" if plan else ""
    for k, v in PAYMENT_METHODS.items():
        kb.add(Btn(f"{v['tag']}  {sc(v['name'])}", callback_data=f"pay_{k}{suffix}", style="success"))
    kb.add(Btn(f"{G['back']}  Pʟᴀɴꜱ", callback_data="menu_plans", style="primary"))
    return kb


def admin_kb() -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn(f"{G['graph']}  Sᴛᴀᴛꜱ",         callback_data="adm_stats",    style="primary"),
        Btn(f"{G['users']}  Uꜱᴇʀꜱ",         callback_data="adm_users",    style="primary"),
    )
    kb.add(
        Btn(f"{G['diamond']}  Aʟʟ Bᴏᴛꜱ",    callback_data="adm_allbots",  style="primary"),
        Btn(f"{G['wallet']}  Pᴀʏᴍᴇɴᴛꜱ",     callback_data="adm_payments", style="success"),
    )
    kb.add(
        Btn(f"{G['broadcast']}  Bʀᴏᴀᴅᴄᴀꜱᴛ", callback_data="adm_broadcast",style="success"),
        Btn(f"{G['no']}  Bᴀɴ / Uɴʙᴀɴ",      callback_data="adm_ban",      style="danger"),
    )
    kb.add(
        Btn(f"{G['plus']}  Gɪᴠᴇ Pʟᴀɴ",      callback_data="adm_giveplan", style="success"),
        Btn(f"{G['ok']}  Aᴘᴘʀᴏᴠᴇ Pᴀʏ",      callback_data="adm_approve",  style="success"),
    )
    kb.add(
        Btn(f"{G['key']}  Cᴏᴜᴘᴏɴꜱ",         callback_data="adm_coupons",  style="primary"),
        Btn(f"{G['ticket']}  Tɪᴄᴋᴇᴛꜱ",      callback_data="adm_tickets",  style="primary"),
    )
    kb.add(
        Btn(f"{G['shield']}  Aᴅᴍɪɴꜱ",       callback_data="adm_admins",   style="primary"),
        Btn(f"{G['eye']}  Aᴜᴅɪᴛ Lᴏɢ",       callback_data="adm_audit",    style="primary"),
    )
    kb.add(
        Btn(f"{G['cog']}  Gɪᴛʜᴜʙ Bᴀᴄᴋᴜᴘ",   callback_data="adm_github",   style="primary"),
        Btn(f"{G['lock']}  Sᴇᴄᴜʀɪᴛʏ",       callback_data="adm_security", style="danger"),
    )
    kb.add(
        Btn(f"{G['warn']}  Mᴀɪɴᴛᴇɴᴀɴᴄᴇ",    callback_data="adm_maint",    style="danger"),
        Btn(f"{G['settings']}  Sᴇᴛᴛɪɴɢꜱ",   callback_data="adm_settings", style="primary"),
    )
    appr_on = bool(get_setting("approval_required", True))
    pend_n = len(get_setting("pending_uploads", {}) or {})
    kb.add(
        Btn(
            f"{G['ok'] if appr_on else G['no']}  Aᴘᴘʀᴏᴠᴀʟ: {'ON' if appr_on else 'OFF'}",
            callback_data="adm_approval_toggle",
            style="success" if appr_on else "danger"),
        Btn(
            f"{G['eye']}  Pᴇɴᴅɪɴɢ" + (f" ({pend_n})" if pend_n else ""),
            callback_data="adm_pending", style="primary"),
    )
    kb.add(
        Btn(f"{G['upload']}  Mᴇɴᴜ Pʜᴏᴛᴏꜱ",  callback_data="adm_photos",       style="primary"),
        Btn(f"{G['refresh']}  Fᴏʀᴄᴇ Bᴀᴄᴋᴜᴘ", callback_data="adm_force_backup", style="success"),
    )
    # ── Advanced Sub-Panels Row 1 ──────────────────────────────────────
    kb.add(
        Btn("📊  Aɴᴀʟʏᴛɪᴄꜱ",       callback_data="adm_analytics",      style="primary"),
        Btn("👥  Uꜱᴇʀ Tᴏᴏʟꜱ",      callback_data="adm_user_tools",     style="primary"),
    )
    kb.add(
        Btn("🤖  Bᴏᴛ Mᴀɴᴀɢᴇʀ",     callback_data="adm_bot_manager",    style="primary"),
        Btn("🛡️  Sᴇᴄ Cᴇɴᴛᴇʀ",      callback_data="adm_sec_center",     style="danger"),
    )
    kb.add(
        Btn("💬  Nᴏᴛɪꜰɪᴄᴀᴛɪᴏɴꜱ",   callback_data="adm_notify_center",  style="success"),
        Btn("⚙️  Sʏꜱ Tᴏᴏʟꜱ",       callback_data="adm_sys_tools",      style="primary"),
    )
    # ── MEGA ADVANCED PANELS ──────────────────────────────────────────
    kb.add(
        Btn("🐙  Gʜ Bʀᴏᴡꜱᴇʀ",      callback_data="adm_gh_browser",     style="primary"),
        Btn("💳  Pᴀʏ Cᴏɴꜰɪɢ",      callback_data="adm_pay_config",     style="success"),
    )
    kb.add(
        Btn("🔧  Bᴏᴛ Cᴏɴꜰɪɢ",      callback_data="adm_bot_cfg",        style="primary"),
        Btn("🎨  Aᴘᴘᴇᴀʀᴀɴᴄᴇ",      callback_data="adm_appearance",     style="primary"),
    )
    kb.add(
        Btn("🎫  Cᴏᴜᴘᴏɴ+",          callback_data="adm_coupon_plus",    style="primary"),
        Btn("📝  Tᴇᴍᴘʟᴀᴛᴇꜱ",        callback_data="adm_templates",      style="primary"),
    )
    kb.add(
        Btn("🔗  Rᴇꜰᴇʀʀᴀʟ Sʏꜱ",    callback_data="adm_referral_sys",   style="success"),
        Btn("🧹  Jᴀɴɪᴛᴏʀ",          callback_data="adm_janitor",        style="danger"),
    )
    kb.add(
        Btn("🌐  Wᴇʙʜᴏᴏᴋꜱ",         callback_data="adm_webhooks",       style="primary"),
        Btn("🎯  Fᴇᴀᴛᴜʀᴇ Fʟᴀɢꜱ",    callback_data="adm_feature_flags",  style="primary"),
    )
    kb.add(
        Btn("⏱️  Rᴀᴛᴇ Lɪᴍɪᴛꜱ",      callback_data="adm_rate_config",    style="danger"),
        Btn("📡  Lɪᴠᴇ Mᴏɴɪᴛᴏʀ",      callback_data="adm_live_monitor",   style="success"),
    )
    kb.add(
        Btn("💎  Rᴇᴠ Gᴏᴀʟꜱ",        callback_data="adm_rev_goals",      style="success"),
        Btn("⏰  Sᴄʜᴇᴅᴜʟᴇʀ",         callback_data="adm_scheduler",      style="primary"),
    )
    kb.add(
        Btn("📥  Iᴍᴘᴏʀᴛ/Exᴘ",       callback_data="adm_import_export",  style="primary"),
        Btn("🏆  Lᴇᴀᴅᴇʀʙᴏᴀʀᴅ",      callback_data="adm_leaderboard",    style="primary"),
    )
    kb.add(
        Btn("🌍  Lᴀɴɢᴜᴀɢᴇꜱ",         callback_data="adm_languages",      style="primary"),
        Btn("🤖  Bᴏᴛ Cᴏɴᴛʀᴏʟꜱ",     callback_data="adm_bot_controls",   style="primary"),
    )
    kb.add(
        Btn("👤  Sᴜʙꜱᴄʀɪᴘᴛɪᴏɴꜱ",    callback_data="adm_subscriptions",  style="primary"),
        Btn("🔐  Adᴍɪɴ 2FA",         callback_data="adm_admin_2fa",      style="danger"),
    )
    kb.add(
        Btn("🖥️  VM Nᴏᴅᴇꜱ",      callback_data="adm_vm_nodes", style="success"),
        Btn("🗄️  Mᴏɴɢᴏ DB",       callback_data="adm_mongo",    style="success"),
    )
    kb.add(Btn(f"{G['back']}  Mᴀɪɴ Mᴇɴᴜ", callback_data="menu_main", style="primary"))
    return kb


def github_kb(status: Dict[str, Any]) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(Btn(f"{G['plus']}  Bᴀᴄᴋᴜᴘ Nᴏᴡ",      callback_data="gh_backup_now",  style="success"))
    kb.add(Btn(f"{G['refresh']}  Rᴇꜱᴛᴏʀᴇ Lᴀᴛᴇꜱᴛ", callback_data="gh_restore_now", style="primary"))
    kb.add(Btn(
        f"{G['rec'] if status['autoEnabled'] else G['rec_off']}  "
        f"Auto Backup: {'ON' if status['autoEnabled'] else 'OFF'}",
        callback_data="gh_toggle_auto",
        style="success" if status["autoEnabled"] else "danger"))
    kb.add(
        Btn(f"{G['key']}  {sc('Change Token' if status['tokenSet'] else 'Set Token')}",
            callback_data="gh_set_token", style="primary"),
        Btn(f"{G['diamond']}  {sc('Change Repo' if status['repoSet'] else 'Set Repo')}",
            callback_data="gh_set_repo",  style="primary"),
    )
    kb.add(
        Btn(f"{G['tri']}  Sᴇᴛ Bʀᴀɴᴄʜ",  callback_data="gh_set_branch",   style="primary"),
        Btn(f"{G['cog']}  Iɴᴛᴇʀᴠᴀʟ",    callback_data="gh_set_interval", style="primary"),
    )
    kb.add(Btn(f"{G['no']}  Cʟᴇᴀʀ Cᴏɴꜰɪɢ", callback_data="gh_clear",     style="danger"))
    kb.add(Btn(f"{G['refresh']}  Rᴇꜰʀᴇꜱʜ",   callback_data="adm_github",  style="primary"))
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ",       callback_data="menu_admin",  style="primary"))
    return kb


# ═════════════════════════════════════════════════════════════════
#  VM NODES + MONGO DB MANAGER  (remote api-vm worker nodes)
#  VMs are stored in panel settings ("vm_nodes"); Mongo URIs live
#  in mongo_pool (persisted in the primary MongoDB itself).
# ═════════════════════════════════════════════════════════════════

def _vm_nodes() -> Dict[str, Any]:
    try:
        return dict(get_setting("vm_nodes", {}) or {})
    except Exception:
        return {}


def _vm_save_nodes(nodes: Dict[str, Any]) -> None:
    set_setting("vm_nodes", nodes)


def _mongo_ready() -> bool:
    """Init mongo_pool on first use (needs MONGO_URI_1 env)."""
    if not _ADDONS_OK or _mdb is None:
        return False
    try:
        _mdb.init_db()
        try:
            _mdb.set_notifier(TOKEN, [OWNER_ID])
        except Exception:
            pass
        return True
    except Exception as e:
        print(f"[mongo] init failed: {e}", file=sys.stderr, flush=True)
        return False


def render_adm_vm_nodes(call: types.CallbackQuery) -> None:
    nodes = _vm_nodes()
    if not _ADDONS_OK or _vmc is None:
        cap = (f"<b>🖥️ {sc('VM Nodes')}</b>\n{G['div_eq']}\n"
               f"{G['no']} {sc('vm_client.py missing — upload it next to bot.py')}\n{G['div']}{FOOTER}")
        kb = types.InlineKeyboardMarkup()
        kb.add(Btn(f"{G['back']}  {sc('Admin')}", callback_data="menu_admin", style="primary"))
        show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)
        return
    rows = [f"<b>🖥️ {sc('VM Nodes')} ({len(nodes)})</b>\n{G['div_eq']}"]
    kb = types.InlineKeyboardMarkup(row_width=1)
    for vm_id, vm in nodes.items():
        icon = "🟢" if vm.get("enabled", True) else "🔴"
        rows.append(f"{icon} <code>{esc(vm_id)}</code> — <code>{esc(vm.get('url', ''))}</code>")
        kb.add(Btn(f"{icon} {vm_id}", callback_data=f"adm_vm_info:{vm_id}"))
    if not nodes:
        rows.append(f"<i>{sc('No VMs yet — tap Add VM')}</i>")
    kb2 = types.InlineKeyboardMarkup(row_width=2)
    kb2.add(
        Btn(f"{G['plus']}  {sc('Add VM')}", callback_data="adm_vm_add", style="success"),
        Btn(f"{G['refresh']}  {sc('Test All')}", callback_data="adm_vm_testall", style="primary"),
    )
    for r in kb.keyboard:
        kb2.keyboard.append(r)
    kb2.add(Btn(f"{G['back']}  {sc('Admin')}", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS["admin"], "\n".join(rows) + f"\n{G['div']}{FOOTER}", kb2, call=call)


def render_adm_vm_info(call: types.CallbackQuery, vm_id: str) -> None:
    nodes = _vm_nodes()
    vm = nodes.get(vm_id)
    if not vm:
        ack(call, "VM not found"); return
    if _vmc is not None:
        try:
            st = _vmc.get_status(vm["url"], vm.get("secret", ""))
        except Exception:
            st = None
    else:
        st = None
    if st:
        online = "🟢 Online"
        ram = (f"{bullet('RAM', str(st.get('used_ram_mb', '?')) + ' / ' + str(st.get('total_ram_mb', '?')) + ' MB')}\n"
               f"{bullet('Free', str(st.get('free_ram_mb', '?')) + ' MB')}\n"
               f"{bullet('Bots', str(st.get('running_bots', '?')) + ' / ' + str(st.get('max_bots', '?')))}")
    else:
        online = "🔴 Offline"
        ram = bullet('Error', (st.get('error', 'unreachable') if isinstance(st, dict) else 'unreachable'))
    tog = "🔴 Disable" if vm.get("enabled", True) else "🟢 Enable"
    cap = (f"<b>🖥️ {esc(vm_id)}</b>\n{G['div_eq']}\n"
           f"{bullet('Status', online)}\n"
           f"{bullet('URL', vm.get('url', ''))}\n"
           f"{ram}\n{G['div']}{FOOTER}")
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn(f"{G['refresh']}  {sc('Refresh')}", callback_data=f"adm_vm_info:{vm_id}", style="primary"),
        Btn(f"{G['bolt']}  {sc('Test')}", callback_data=f"adm_vm_test:{vm_id}", style="primary"),
    )
    kb.add(
        Btn(tog, callback_data=f"adm_vm_toggle:{vm_id}", style="danger" if vm.get("enabled", True) else "success"),
        Btn(f"{G['trash']}  {sc('Remove')}", callback_data=f"adm_vm_remove:{vm_id}", style="danger"),
    )
    kb.add(Btn(f"{G['back']}  {sc('VM Nodes')}", callback_data="adm_vm_nodes", style="primary"))
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


def render_adm_mongo(call: types.CallbackQuery) -> None:
    if not _mongo_ready():
        cap = (f"<b>🗄️ {sc('Mongo DB')}</b>\n{G['div_eq']}\n"
               f"{G['no']} {sc('Not configured')} — {sc('set MONGO_URI_1 env and redeploy')}\n{G['div']}{FOOTER}")
        kb = types.InlineKeyboardMarkup()
        kb.add(Btn(f"{G['back']}  {sc('Admin')}", callback_data="menu_admin", style="primary"))
        show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)
        return
    try:
        uris = _mdb.list_uris()
        tot = _mdb.totals()
    except Exception as e:
        ack(call, f"DB error: {e}"); return
    rows = [f"<b>🗄️ {sc('Mongo Connections')} ({len(uris)})</b>\n{G['div_eq']}",
            f"{bullet('Total Free', str(tot.get('free_mb', 0)) + ' MB')}",
            f"{bullet('Total Used', str(tot.get('used_mb', 0)) + ' MB')}",
            f"{bullet('Online', str(tot.get('online', 0)) + ' / ' + str(tot.get('uris', 0)))}"]
    kb = types.InlineKeyboardMarkup(row_width=1)
    for u in uris:
        icon = "🟢" if u.get("online") else "🔴"
        rows.append(f"{icon} <code>{esc(u.get('masked', ''))}</code> [{u.get('state', '?')}] "
                    f"{u.get('used_mb', 0)}MB / {512}MB — free {u.get('free_mb', 0)}MB")
        kb.add(Btn(f"{icon} URI #{u.get('index')} — free {u.get('free_mb', 0)}MB", callback_data=f"adm_mongo_info:{u.get('index')}"))
        if not u.get("primary"):
            kb.add(Btn(f"{G['trash']}  {sc('Remove')} #{u.get('index')}", callback_data=f"adm_mongo_remove:{u.get('index')}"))
    kb2 = types.InlineKeyboardMarkup(row_width=2)
    kb2.add(
        Btn(f"{G['plus']}  {sc('Add URI')}", callback_data="adm_mongo_add", style="success"),
        Btn(f"{G['refresh']}  {sc('Refresh')}", callback_data="adm_mongo", style="primary"),
    )
    for r in kb.keyboard:
        kb2.keyboard.append(r)
    kb2.add(Btn(f"{G['back']}  {sc('Admin')}", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS["admin"], "\n".join(rows) + f"\n{G['div']}{FOOTER}", kb2, call=call)


def render_adm_mongo_info(call: types.CallbackQuery, idx: str) -> None:
    """Fetch all details from one Mongo URI."""
    if not _mongo_ready():
        ack(call, "Mongo not configured"); return
    try:
        det = _mdb.uri_details(int(idx))
    except Exception as e:
        ack(call, f"DB error: {e}"); return
    if not det.get("ok"):
        ack(call, det.get("error", "URI error")); return
    icon = "🟢" if det.get("online") else "🔴"
    cols = det.get("collections", {}) or {}
    col_lines = "\n".join(f"{bullet(k, v)}" for k, v in cols.items())
    cap = (f"<b>🗄️ {sc('Mongo URI')} #{det.get('index')} {icon}</b>\n{G['div_eq']}\n"
           f"{bullet('State', det.get('state', '?'))}\n"
           f"{bullet('Used', str(det.get('used_mb', 0)) + ' MB')}\n"
           f"{bullet('Free', str(det.get('free_mb', 0)) + ' MB')}\n"
           f"{bullet('Storage', str(det.get('storage_mb', 0)) + ' MB')}\n"
           f"{bullet('Data', str(det.get('data_mb', 0)) + ' MB')}\n"
           f"{bullet('Indexes', str(det.get('indexes_mb', 0)) + ' MB')}\n"
           f"{bullet('Running Bots', det.get('running_bots', '?'))}\n"
           f"{G['div']}\n<b>{sc('Collections')}</b>\n{col_lines}\n{G['div']}{FOOTER}")
    kb = types.InlineKeyboardMarkup()
    kb.add(Btn(f"{G['refresh']}  {sc('Refresh')}", callback_data=f"adm_mongo_info:{det.get('index')}", style="primary"))
    kb.add(Btn(f"{G['back']}  {sc('Mongo')}", callback_data="adm_mongo", style="primary"))
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


def _vm_toggle(call: types.CallbackQuery, vm_id: str) -> None:
    nodes = _vm_nodes()
    vm = nodes.get(vm_id)
    if not vm:
        ack(call, "VM not found"); return
    vm["enabled"] = not vm.get("enabled", True)
    _vm_save_nodes(nodes)
    audit(call.from_user.id, "vm_toggle", f"{vm_id} enabled={vm['enabled']}")
    ack(call, f"{vm_id}: {'ON' if vm['enabled'] else 'OFF'}")


def _vm_remove(call: types.CallbackQuery, vm_id: str) -> None:
    nodes = _vm_nodes()
    if vm_id in nodes:
        del nodes[vm_id]
        _vm_save_nodes(nodes)
        audit(call.from_user.id, "vm_remove", vm_id)
        ack(call, f"{G['trash']} {vm_id} removed")
    else:
        ack(call, "VM not found")


def _vm_test_one(call: types.CallbackQuery, vm_id: str) -> None:
    nodes = _vm_nodes()
    vm = nodes.get(vm_id)
    if not vm or _vmc is None:
        ack(call, "VM not found"); return
    ack(call, "Testing…")
    def _bg() -> None:
        try:
            ok = _vmc.ping(vm["url"])
            st = _vmc.get_status(vm["url"], vm.get("secret", "")) if ok else None
            msg = (f"🟢 <b>{esc(vm_id)}</b> OK — free {st.get('free_ram_mb')}MB" if st
                   else f"🔴 <b>{esc(vm_id)}</b> unreachable")
            bot.send_message(call.message.chat.id, msg, parse_mode="HTML")
        except Exception as e:
            try:
                bot.send_message(call.message.chat.id, f"🔴 {esc(vm_id)}: <code>{esc(e)}</code>", parse_mode="HTML")
            except Exception:
                pass
    threading.Thread(target=_bg, daemon=True).start()


def _bg_vm_testall(call: types.CallbackQuery) -> None:
    ack(call, "Testing all…")
    nodes = _vm_nodes()
    if not nodes:
        ack(call, "No VMs"); return
    def _bg() -> None:
        lines = ["<b>🔍 VM Health</b>"]
        for vm_id, vm in nodes.items():
            try:
                ok = _vmc.ping(vm["url"]) if _vmc else False
                st = _vmc.get_status(vm["url"], vm.get("secret", "")) if ok else None
                lines.append(f"🟢 <code>{esc(vm_id)}</code> free {st.get('free_ram_mb')}MB" if st else f"🔴 <code>{esc(vm_id)}</code> offline")
            except Exception as e:
                lines.append(f"🔴 <code>{esc(vm_id)}</code>: {esc(e)}")
        try:
            bot.send_message(call.message.chat.id, "\n".join(lines), parse_mode="HTML")
        except Exception:
            pass
    threading.Thread(target=_bg, daemon=True).start()


def _mongo_remove_idx(call: types.CallbackQuery, idx: str) -> None:
    if not _mongo_ready():
        ack(call, "Mongo not configured"); return
    try:
        want = int(idx)
        uris = _mdb.list_uris()
        target = next((u for u in uris if u.get("index") == want), None)
        if not target:
            ack(call, "Not found"); return
        res = _mdb.remove_uri(target["uri"])
        audit(call.from_user.id, "mongo_remove", f"idx={want}")
        ack(call, "Removed" if res.get("ok") else res.get("error", "Failed"))
    except Exception as e:
        ack(call, f"Error: {e}")


def bot_actions_kb(bot_id: str, running: bool, premium: bool = False) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=2)
    if running:
        kb.add(
            Btn(f"{G['stop']}  Sᴛᴏᴘ",       callback_data=f"bot_stop_{bot_id}",    style="danger"),
            Btn(f"{G['refresh']}  Rᴇꜱᴛᴀʀᴛ", callback_data=f"bot_restart_{bot_id}", style="success"),
        )
    else:
        kb.add(
            Btn(f"{G['play']}  Sᴛᴀʀᴛ",      callback_data=f"bot_start_{bot_id}",   style="success"),
            Btn(f"{G['refresh']}  Rᴇꜱᴛᴀʀᴛ", callback_data=f"bot_restart_{bot_id}", style="primary"),
        )
    kb.add(
        Btn(f"{G['bolt']}  Lɪᴠᴇ Lᴏɢꜱ", callback_data=f"bot_logs_{bot_id}", style="primary"),
        Btn(f"{G['eye']}  Iɴꜰᴏ",       callback_data=f"bot_info_{bot_id}", style="primary"),
    )
    kb.add(
        Btn(f"{G['settings']}  Eɴᴠ Vᴀʀꜱ", callback_data=f"bot_env_{bot_id}",  style="primary"),
        Btn(f"{G['cog']}  Cʀᴏɴ",          callback_data=f"bot_cron_{bot_id}", style="primary"),
    )
    kb.add(
        Btn(f"{G['download']}  Iɴꜱᴛᴀʟʟ Pᴋɢ", callback_data=f"bot_pip_{bot_id}",   style="primary"),
        Btn(f"{G['plus']}  Cʟᴏɴᴇ",           callback_data=f"bot_clone_{bot_id}", style="primary"),
    )
    if premium:
        is_open = bot_id in TUNNELS and TUNNELS[bot_id].get("proc") and TUNNELS[bot_id]["proc"].poll() is None
        label = "Stop Public URL" if is_open else "Public URL"
        glyph = G['no'] if is_open else G['cloud']
        kb.add(Btn(f"{glyph}  {label}", callback_data=f"bot_tunnel_{bot_id}",
                   style="danger" if is_open else "success"))
    kb.add(Btn(f"{G['arrow']}  Dᴏᴡɴʟᴏᴀᴅ", callback_data=f"bot_dl_{bot_id}", style="primary"))
    kb.add(Btn(f"{G['no']}  Dᴇʟᴇᴛᴇ",       callback_data=f"bot_delete_{bot_id}", style="danger"))
    kb.add(Btn(f"{G['back']}  Mʏ Bᴏᴛꜱ",    callback_data="menu_bots",            style="primary"))
    return kb


def confirm_kb(yes_cb: str, no_cb: str = "menu_main", yes_label: str = "Confirm",
               no_label: str = "Cancel") -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn(f"{G['ok']}  {sc(yes_label)}", callback_data=yes_cb, style="success"),
        Btn(f"{G['no']}  {sc(no_label)}",  callback_data=no_cb,  style="danger"),
    )
    return kb


# ═════════════════════════════════════════════════════════════════
# 10. SANDBOX RUNNER  (subprocess pool, secret-stripped env)
# ═════════════════════════════════════════════════════════════════

RUNNING: Dict[str, Dict[str, Any]] = {}    # bot_id -> {proc, kind, started, log, ...}
START_TIME: float = time.time()            # panel boot time, for uptime card
_LOCK_FH_KEEPALIVE: Any = None             # singleton-lock fd, kept alive for the process lifetime
_runner_lock = threading.Lock()


_SKIP_DIR_PARTS = {".deps", "node_modules", ".tmp_run", "__pycache__",
                   ".git", "venv", ".venv", "env"}


def _iter_user_files(bot_dir: Path, suffix: str) -> List[Path]:
    """Recursive scan that skips dependency / cache / VCS folders."""
    out: List[Path] = []
    for p in bot_dir.rglob(f"*{suffix}"):
        if any(part in _SKIP_DIR_PARTS for part in p.parts):
            continue
        out.append(p)
    return sorted(out, key=lambda x: (len(x.parts), str(x)))


def detect_entry(bot_dir: Path) -> Tuple[Optional[str], Optional[str]]:
    """Find the entry file. Returns (kind, relative_path_from_bot_dir).
    Searches the bot dir recursively — many users zip their bot inside
    a wrapper folder (e.g. `MyBot/bot.py`), and the old shallow `glob`
    missed those."""
    # 1. Standard entry names — check shallow first, then recursive
    for n in ENTRY_NODE:
        p = bot_dir / n
        if p.exists():
            return ("node", n)
    for n in ENTRY_PY:
        p = bot_dir / n
        if p.exists():
            return ("python", n)
    # Recursive: prefer files closer to the root (shorter path)
    for n in ENTRY_PY:
        for p in _iter_user_files(bot_dir, ".py"):
            if p.name == n:
                return ("python", str(p.relative_to(bot_dir)))
    for n in ENTRY_NODE:
        for p in _iter_user_files(bot_dir, ".js"):
            if p.name == n:
                return ("node", str(p.relative_to(bot_dir)))
    # 2. Any .py file (recursive, skipping deps)
    py_files = _iter_user_files(bot_dir, ".py")
    if py_files:
        return ("python", str(py_files[0].relative_to(bot_dir)))
    # 3. Any .js file (recursive)
    js_files = _iter_user_files(bot_dir, ".js")
    if js_files:
        return ("node", str(js_files[0].relative_to(bot_dir)))
    # 4. Inner .zip — extract once then re-scan
    zip_files = [p for p in bot_dir.rglob("*.zip")
                 if not any(part in _SKIP_DIR_PARTS for part in p.parts)]
    if zip_files:
        import zipfile as _zf
        try:
            with _zf.ZipFile(zip_files[0], "r") as z:
                z.extractall(bot_dir)
        except Exception:
            return (None, None)
        # recursive re-check
        py_files = _iter_user_files(bot_dir, ".py")
        if py_files:
            return ("python", str(py_files[0].relative_to(bot_dir)))
        js_files = _iter_user_files(bot_dir, ".js")
        if js_files:
            return ("node", str(js_files[0].relative_to(bot_dir)))
    return (None, None)


def safe_env(bot_dir: Path, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in SECRET_ENV_NAMES}
    env["HOME"]    = str(bot_dir)
    env["TMPDIR"]  = str(bot_dir / ".tmp_run")
    env["PATH"]    = "/usr/local/bin:/usr/bin:/bin"
    env.setdefault("NODE_ENV", "production")
    deps_dir = str(bot_dir / ".deps")
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{deps_dir}:{existing_pp}" if existing_pp else deps_dir
    Path(env["TMPDIR"]).mkdir(parents=True, exist_ok=True)
    Path(deps_dir).mkdir(parents=True, exist_ok=True)
    if extra:
        for k, v in extra.items():
            if k in SECRET_ENV_NAMES:
                continue
            env[str(k)] = str(v)
    return env


# ── module-name → PyPI package-name mapping ───────────────────────
# Many third-party libs are imported under a name that differs from
# their pip package. Without this mapping pip would 404 (e.g. `cv2` is
# really `opencv-python`). This is the most common reason "auto-install
# nahi chala" — and why uploaded bots crashed at import time.
_PYPI_ALIAS: Dict[str, str] = {
    "telebot":       "pyTelegramBotAPI",
    # `from telegram import Update` belongs to python-telegram-bot.
    # The bare `telegram` package on PyPI is an unrelated tiny shim
    # that does NOT expose Update / Bot — installing it by accident
    # is the most common source of the
    #   ImportError: cannot import name 'Update' from 'telegram'
    # crash. We map it to the real package and additionally validate
    # the installed copy in `_filter_third_party`.
    "telegram":      "python-telegram-bot",
    "telethon":      "Telethon",
    "pyrogram":      "Pyrogram",
    "pyromod":       "pyromod",
    "tgcrypto":      "TgCrypto",
    "PIL":           "Pillow",
    "cv2":           "opencv-python",
    "bs4":           "beautifulsoup4",
    "yaml":          "PyYAML",
    "dotenv":        "python-dotenv",
    "Crypto":        "pycryptodome",
    "Cryptodome":    "pycryptodomex",
    "dateutil":      "python-dateutil",
    "magic":         "python-magic",
    "skimage":       "scikit-image",
    "sklearn":       "scikit-learn",
    "google":        "google-api-python-client",
    "googletrans":   "googletrans",
    "OpenSSL":       "pyOpenSSL",
    "wx":            "wxPython",
    "psycopg2":      "psycopg2-binary",
    "MySQLdb":       "mysqlclient",
    "serial":        "pyserial",
    "win32api":      "pywin32",
    "ujson":         "ujson",
    "uvloop":        "uvloop",
    "discord":       "discord.py",
    "httpx":         "httpx",
    "aiohttp":       "aiohttp",
    "aiogram":       "aiogram",
    "fastapi":       "fastapi",
    "flask":         "flask",
    "starlette":     "starlette",
    "redis":         "redis",
    "pymongo":       "pymongo",
    "motor":         "motor",
    "psutil":        "psutil",
    "schedule":      "schedule",
    "apscheduler":   "APScheduler",
    "cryptography":  "cryptography",
    "github":        "PyGithub",
    "requests":      "requests",
    # extra safety net — pip name ≠ import name
    "nacl":          "PyNaCl",
    "git":           "GitPython",
    "jose":          "python-jose",
    "pkg_resources": "setuptools",
    "lxml":          "lxml",
    "chardet":       "chardet",
}


# Modules whose installed copy must expose specific symbols to be
# considered "really installed". Catches the wrong-package-on-PyPI trap
# (e.g. the `telegram` shim that lacks `Update`).
_VALIDATE_SYMBOLS: Dict[str, List[str]] = {
    "telegram": ["Update", "Bot"],
}


def _purge_bad_install(deps_dir: Path, mod_name: str) -> None:
    """Remove a wrong-package install (and its dist-info) from a bot's
    `.deps` so the next pip install can put the correct one in its
    place. Used when `_VALIDATE_SYMBOLS` says the cached package is
    not the one we actually need."""
    try:
        if not deps_dir.exists():
            return
        target = deps_dir / mod_name
        if target.exists():
            try:
                shutil.rmtree(str(target), ignore_errors=True)
            except Exception:
                pass
        for child in list(deps_dir.iterdir()):
            n = child.name.lower()
            if n.endswith((".dist-info", ".egg-info")) and \
                    n.startswith(mod_name.lower()):
                try:
                    shutil.rmtree(str(child), ignore_errors=True)
                except Exception:
                    try:
                        child.unlink()
                    except Exception:
                        pass
    except Exception as e:
        print(f"[purge_bad_install] {mod_name}: {e}", file=sys.stderr)


def _scan_imports(bot_dir: Path) -> List[str]:
    """Recursively scan every .py file for top-level module imports."""
    import ast as _ast
    found: set = set()
    for pyfile in bot_dir.rglob("*.py"):
        # Skip our own .deps cache so we don't mistake installed libs
        # for the bot's own imports.
        if ".deps" in pyfile.parts:
            continue
        try:
            tree = _ast.parse(pyfile.read_text(errors="ignore"))
        except Exception:
            continue
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                for n in node.names:
                    if n.name:
                        found.add(n.name.split(".")[0])
            elif isinstance(node, _ast.ImportFrom):
                if node.level and node.level > 0:
                    continue  # relative import — local package
                if node.module:
                    found.add(node.module.split(".")[0])
    return sorted(found)


def _filter_third_party(modules: List[str], bot_dir: Path) -> List[str]:
    """Drop stdlib, local module names, and modules already importable
    from the bot's .deps cache. Returns only installable PyPI names that
    are still missing."""
    import importlib.util as _ilu
    stdlib = set(getattr(sys, "stdlib_module_names", set()))
    skip = stdlib | {"__future__", ""}
    # local modules (any .py file or package dir at the top level OR
    # any subdir — covers zipped wrappers like `MyBot/utils.py`)
    deps_dir = bot_dir / ".deps"
    for child in bot_dir.iterdir():
        if child == deps_dir:
            continue
        if child.suffix == ".py":
            skip.add(child.stem)
        elif child.is_dir() and (child / "__init__.py").exists():
            skip.add(child.name)
    # Make .deps importable for the find_spec check below so we don't
    # re-install something that's already cached locally.
    deps_str = str(deps_dir)
    deps_in_path = deps_str in sys.path
    if deps_dir.exists() and not deps_in_path:
        sys.path.insert(0, deps_str)

    out: List[str] = []
    seen: set = set()
    try:
        for m in modules:
            if not m or m in skip:
                continue
            # Already importable (stdlib was caught above; this catches
            # things like cv2 already installed in .deps/).
            try:
                if _ilu.find_spec(m) is not None:
                    # Even if importable, validate that the installed
                    # copy is the RIGHT package (not the wrong-name
                    # PyPI shim). If it isn't, nuke it so pip can
                    # reinstall the correct one below.
                    needed = _VALIDATE_SYMBOLS.get(m)
                    if needed:
                        try:
                            _real = importlib.import_module(m)
                            if all(hasattr(_real, s) for s in needed):
                                continue
                        except Exception:
                            pass
                        # Wrong package — purge and force a reinstall.
                        try:
                            del sys.modules[m]
                        except KeyError:
                            pass
                        _purge_bad_install(deps_dir, m)
                    else:
                        continue
            except (ImportError, ValueError):
                pass
            pip_name = _PYPI_ALIAS.get(m, m)
            if pip_name in seen:
                continue
            seen.add(pip_name)
            out.append(pip_name)
    finally:
        if deps_dir.exists() and not deps_in_path:
            try:
                sys.path.remove(deps_str)
            except ValueError:
                pass
    return out


def _pip_env(deps_dir: Path) -> Dict[str, str]:
    """Env for pip subprocesses: silence root warnings, keep installs
    confined to the bot's `.deps/` so we never trip on permissions.

    NOTE: We intentionally do NOT set PYTHONUSERBASE — that conflicts
    with `--target` and pip refuses to combine them ("Can not combine
    '--user' and '--target'"). We rely on `--target` alone."""
    env = {**os.environ,
           "PIP_DISABLE_PIP_VERSION_CHECK": "1",
           "PIP_NO_INPUT": "1",
           "PIP_ROOT_USER_ACTION": "ignore"}
    env.pop("PYTHONUSERBASE", None)
    env.pop("PIP_USER", None)
    return env


_PIP_BASE_FLAGS = ["--upgrade", "--no-input", "--no-warn-script-location",
                   "--disable-pip-version-check"]


def install_deps(bot_dir: Path, kind: str, log: List[str]) -> bool:
    try:
        if kind == "python":
            deps_dir = bot_dir / ".deps"
            deps_dir.mkdir(parents=True, exist_ok=True)
            req = bot_dir / "requirements.txt"
            pip_env = _pip_env(deps_dir)

            # 1) requirements.txt (if present)
            if req.exists():
                log.append(f"{G['div']} pip install (requirements.txt) {G['div']}")
                r = subprocess.run(
                    [sys.executable, "-m", "pip", "install",
                     "--target", str(deps_dir), *_PIP_BASE_FLAGS,
                     "-r", str(req)],
                    cwd=str(bot_dir), timeout=600, capture_output=True, text=True,
                    env=pip_env,
                )
                for line in (r.stdout or "").splitlines()[-15:]:
                    log.append(line)
                for line in (r.stderr or "").splitlines()[-10:]:
                    log.append(line)
                log.append(f"[{G['ok']}] requirements.txt done (rc={r.returncode})")

            # 2) AST-scan imports and install anything still missing.
            #    We always do this so a bot that adds a new `import foo`
            #    after upload doesn't crash on next start.
            try:
                modules = _scan_imports(bot_dir)
                third_party = _filter_third_party(modules, bot_dir)
                if third_party:
                    log.append(f"{G['div']} auto-install (scanned imports) {G['div']}")
                    log.append(f"📦 packages: {', '.join(third_party)}")
                    r2 = subprocess.run(
                        [sys.executable, "-m", "pip", "install",
                         "--target", str(deps_dir), *_PIP_BASE_FLAGS,
                         *third_party],
                        cwd=str(bot_dir), timeout=600, capture_output=True, text=True,
                        env=pip_env,
                    )
                    for line in (r2.stdout or "").splitlines()[-15:]:
                        log.append(line)
                    for line in (r2.stderr or "").splitlines()[-10:]:
                        log.append(line)
                    log.append(f"[{G['ok']}] auto-install done (rc={r2.returncode})")
            except Exception as e:
                log.append(f"[{G['warn']}] auto-install scan error: {e}")
            return True
        if kind == "node":
            pkg = bot_dir / "package.json"
            if not pkg.exists():
                return False
            if (bot_dir / "node_modules").exists():
                log.append(f"[{G['ok']}] node_modules cached, skipping npm install")
                return False
            log.append(f"{G['div']} npm install {G['div']}")
            r = subprocess.run(
                ["npm", "install", "--omit=dev", "--no-audit", "--no-fund"],
                cwd=str(bot_dir), timeout=300, capture_output=True, text=True,
            )
            for line in (r.stdout or "").splitlines()[-15:]:
                log.append(line)
            for line in (r.stderr or "").splitlines()[-10:]:
                log.append(line)
            log.append(f"[{G['ok']}] npm done (rc={r.returncode})")
            return True
    except subprocess.TimeoutExpired:
        log.append(f"[{G['warn']}] dependency install timeout (>5min)")
    except FileNotFoundError as e:
        log.append(f"[{G['warn']}] tool not found: {e}")
    except Exception as e:
        log.append(f"[{G['warn']}] install error: {e}")
    return False


def _drain_proc(bot_id: str, proc: subprocess.Popen, log: List[str]) -> None:
    try:
        if not proc.stdout:
            return
        for line in iter(proc.stdout.readline, b""):
            try:
                txt = line.decode("utf-8", "replace").rstrip()
            except Exception:
                txt = repr(line)
            log.append(txt)
            if len(log) > LOG_RING:
                del log[: len(log) - LOG_RING]
    except Exception:
        pass
    # crash-watch — auto-restart if plan supports it
    try:
        rc = proc.wait()
        log.append(f"{G['div']} process exited rc={rc} {G['div']}")
        info = RUNNING.get(bot_id)
        was_manual = (info is None) or info.get("manual_stop", False)
        b_doc = find_bot(bot_id)

        # capture last error lines so the bot view can surface them
        if b_doc is not None:
            tail = [ln for ln in log[-15:] if ln and not ln.startswith(G["div"])]
            err_text = "\n".join(tail[-8:])[:1500]
            b_doc["last_error"] = err_text
            b_doc["last_exit_code"] = int(rc) if rc is not None else None
            b_doc["last_exit_at"] = ts_iso()
            if rc not in (0, None) and not was_manual:
                b_doc["status"] = "crashed"
            try:
                save_bot(b_doc)
            except Exception:
                pass

        if not info:
            return
        if not b_doc:
            return
        owner = db_load()["users"].get(str(b_doc["owner"]))
        plan = (owner or {}).get("plan", "free")
        if PLAN_LIMITS.get(plan, {}).get("auto_restart") and not was_manual:
            log.append(f"[{G['refresh']}] auto-restart in 3s...")
            time.sleep(3)
            start_child(b_doc)
    except Exception:
        pass


def _start_child_local(b: Dict[str, Any]) -> Dict[str, Any]:
    bid = b["_id"]
    # Approval gate — never start a bot still waiting for admin review.
    if (b or {}).get("approval_status") == "pending":
        return {"ok": False, "error": "Bot is waiting for admin approval."}
    if (b or {}).get("approval_status") == "rejected":
        return {"ok": False, "error": "Bot was rejected by admin."}
    with _runner_lock:
        existing = RUNNING.get(bid)
        if existing and existing["proc"].poll() is None:
            return {"ok": False, "error": "Already running."}
    bot_dir = Path(b["dir"])
    if not bot_dir.exists():
        return {"ok": False, "error": "Bot folder missing."}

    # decrypt encrypted source files into bot_dir at run time
    try:
        materialize_bot_files(b)
    except Exception as e:
        return {"ok": False, "error": f"decrypt failed: {e}"}

    kind, entry = detect_entry(bot_dir)
    if not kind:
        return {"ok": False, "error": "No entry file (index.js / bot.py)."}

    log: List[str] = [f"{G['div_eq']} START {ts_iso()} {G['div_eq']}"]
    install_deps(bot_dir, kind, log)
    cmd = ["node", entry] if kind == "node" else [sys.executable, "-u", entry]

    extra_env = b.get("env") or {}
    try:
        proc = subprocess.Popen(
            cmd, cwd=str(bot_dir), env=safe_env(bot_dir, extra_env),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            preexec_fn=os.setsid if os.name == "posix" else None,
        )
    except Exception as e:
        return {"ok": False, "error": f"spawn: {e}"}

    info = {
        "proc": proc, "kind": kind, "started": time.time() * 1000,
        "log": log, "dir": str(bot_dir), "name": b["name"],
        "owner": b["owner"], "manual_stop": False,
    }
    with _runner_lock:
        RUNNING[bid] = info
    threading.Thread(target=_drain_proc, args=(bid, proc, log), daemon=True).start()

    # ── File-access sandbox ───────────────────────────────────────────────
    # After the process has loaded its source into memory we wipe the
    # plain-text .py / .js files from disk.  The bot keeps running because
    # Python/Node already have the bytecode in RAM, but a malicious script
    # that tries to open(__file__), walk the directory, or read its own
    # source to discover server paths will find nothing.
    def _wipe_source_files(bot_path: Path, wait_sec: float = 6.0) -> None:
        time.sleep(wait_sec)
        _ext = (".py", ".js", ".ts") if kind == "node" else (".py",)
        for _f in bot_path.iterdir():
            try:
                if _f.is_file() and _f.suffix in _ext and _f.name != "__init__.py":
                    _f.write_bytes(b"# sandboxed\n")   # overwrite content, keep inode
            except Exception:
                pass

    threading.Thread(
        target=_wipe_source_files, args=(bot_dir,), daemon=True
    ).start()
    # ─────────────────────────────────────────────────────────────────────

    # update doc — clear any prior crash so bot view shows clean state
    b["status"] = "running"
    b["last_started"] = ts_iso()
    b["last_error"] = ""
    b["last_exit_code"] = None
    save_bot(b)
    return {"ok": True, "pid": proc.pid, "kind": kind}


def _stop_child_local(bot_id: str, manual: bool = True) -> Dict[str, Any]:
    with _runner_lock:
        info = RUNNING.get(bot_id)
    if not info:
        # Even if we don't have it tracked, make sure DB says stopped
        b = find_bot(bot_id)
        if b and b.get("status") != "stopped":
            b["status"] = "stopped"
            save_bot(b)
        return {"ok": True}
    info["manual_stop"] = manual
    proc = info["proc"]

    # Collect every descendant PID *before* we start signalling so a
    # double-fork bot can't escape us.
    child_pids: List[int] = []
    if psutil is not None:
        try:
            parent = psutil.Process(proc.pid)
            for ch in parent.children(recursive=True):
                child_pids.append(ch.pid)
        except Exception:
            pass

    def _kill_pid(pid: int, sig: int) -> None:
        try:
            os.kill(pid, sig)
        except (ProcessLookupError, PermissionError):
            pass
        except Exception:
            pass

    try:
        # 1) polite SIGTERM to the whole process group
        if os.name == "posix":
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            for pid in child_pids:
                _kill_pid(pid, signal.SIGTERM)
        else:
            proc.terminate()

        # 2) wait briefly — most well-behaved bots exit here
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            # 3) hard SIGKILL the group + every descendant we noted
            if os.name == "posix":
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                for pid in child_pids:
                    _kill_pid(pid, signal.SIGKILL)
                # one more sweep for any new grand-children spawned
                # between our snapshot and the kill signal
                if psutil is not None:
                    try:
                        for ch in psutil.Process(proc.pid).children(recursive=True):
                            _kill_pid(ch.pid, signal.SIGKILL)
                    except Exception:
                        pass
            else:
                proc.kill()
            try:
                proc.wait(timeout=3)
            except Exception:
                pass
    except ProcessLookupError:
        pass
    except Exception as e:
        # Even on partial failure, drop our handle so the user can
        # try again instead of being stuck "running".
        with _runner_lock:
            RUNNING.pop(bot_id, None)
        b = find_bot(bot_id)
        if b:
            b["status"] = "stopped"
            save_bot(b)
        return {"ok": False, "error": str(e)}

    # Tear down any cloudflared tunnel we opened for this bot
    try:
        _stop_tunnel(bot_id)
    except Exception:
        pass

    with _runner_lock:
        RUNNING.pop(bot_id, None)
    b = find_bot(bot_id)
    if b:
        b["status"] = "stopped"
        save_bot(b)
    return {"ok": True}


# ────────────────────────────── Cloudflared "trycloudflare" tunnels ─
# Premium-only feature: gives a user a public URL like
# https://random-words-1234.trycloudflare.com that proxies straight to
# their bot's local port. We download the official cloudflared binary on
# first use and cache it under ~/.cache/cloudflared so this works on any
# host without the user needing root.

TUNNELS: Dict[str, Dict[str, Any]] = {}     # bot_id -> {proc, port, url, started}
_tunnel_lock = threading.Lock()

CLOUDFLARED_CACHE = Path.home() / ".cache" / "cloudflared"
CLOUDFLARED_BIN   = CLOUDFLARED_CACHE / "cloudflared"

_CF_DOWNLOAD = {
    ("linux",  "x86_64"):  "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64",
    ("linux",  "aarch64"): "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64",
    ("linux",  "armv7l"):  "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm",
    ("darwin", "x86_64"):  "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64.tgz",
    ("darwin", "arm64"):   "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64.tgz",
}


def _ensure_cloudflared() -> Optional[Path]:
    """Return path to a working cloudflared binary, downloading once."""
    # Already cached?
    if CLOUDFLARED_BIN.exists() and os.access(CLOUDFLARED_BIN, os.X_OK):
        return CLOUDFLARED_BIN
    # Already on PATH?
    on_path = shutil.which("cloudflared")
    if on_path:
        return Path(on_path)
    # Download a fresh copy
    try:
        import platform
        sysname = platform.system().lower()
        machine = platform.machine().lower()
        url = _CF_DOWNLOAD.get((sysname, machine))
        if not url:
            return None
        CLOUDFLARED_CACHE.mkdir(parents=True, exist_ok=True)
        tmp = CLOUDFLARED_BIN.with_suffix(".part")
        with requests.get(url, stream=True, timeout=120) as r:
            r.raise_for_status()
            with open(tmp, "wb") as f:
                for chunk in r.iter_content(chunk_size=1 << 16):
                    if chunk:
                        f.write(chunk)
        tmp.chmod(0o755)
        tmp.rename(CLOUDFLARED_BIN)
        return CLOUDFLARED_BIN
    except Exception:
        return None


def _port_in_use(port: int) -> bool:
    """True if *something* is already listening on this TCP port."""
    import socket as _s
    for fam, typ, addr in (
        (_s.AF_INET,  _s.SOCK_STREAM, ("127.0.0.1", port)),
        (_s.AF_INET6, _s.SOCK_STREAM, ("::1",       port)),
    ):
        try:
            with _s.socket(fam, typ) as sk:
                sk.settimeout(0.4)
                if sk.connect_ex(addr) == 0:
                    return True
        except Exception:
            continue
    return False


_TRYCLOUDFLARE_RE = re.compile(r"https?://[a-z0-9-]+\.trycloudflare\.com", re.I)


def _start_tunnel(bot_id: str, port: int) -> Dict[str, Any]:
    """Spin up `cloudflared tunnel --url http://localhost:<port>` and
    capture the public trycloudflare URL from its stderr."""
    if not (1 <= port <= 65535):
        return {"ok": False, "error": "Port must be between 1 and 65535"}

    with _tunnel_lock:
        existing = TUNNELS.get(bot_id)
        if existing and existing.get("proc") and existing["proc"].poll() is None:
            return {"ok": False, "error": "Tunnel already running for this bot. Stop it first."}

    if not _port_in_use(port):
        return {"ok": False,
                "error": f"Nothing is listening on port {port}. "
                         f"Start your bot's web server on that port first, "
                         f"or pick another port."}

    bin_path = _ensure_cloudflared()
    if not bin_path:
        return {"ok": False,
                "error": "Could not download cloudflared binary on this host. "
                         "Please install cloudflared manually."}

    log_buf: Deque[str] = deque(maxlen=200)
    try:
        proc = subprocess.Popen(
            [str(bin_path), "tunnel", "--no-autoupdate",
             "--url", f"http://localhost:{port}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            preexec_fn=os.setsid if os.name == "posix" else None,
        )
    except Exception as e:
        return {"ok": False, "error": f"Failed to launch cloudflared: {e}"}

    rec: Dict[str, Any] = {
        "proc":    proc,
        "port":    port,
        "url":     None,
        "started": int(time.time()),
        "log":     log_buf,
    }
    with _tunnel_lock:
        TUNNELS[bot_id] = rec

    def _drain() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip()
            log_buf.append(line)
            if rec["url"] is None:
                m = _TRYCLOUDFLARE_RE.search(line)
                if m:
                    rec["url"] = m.group(0)

    threading.Thread(target=_drain, daemon=True, name=f"cf-{bot_id}").start()

    # Wait up to ~15s for the URL to appear
    deadline = time.time() + 15
    while time.time() < deadline and rec["url"] is None and proc.poll() is None:
        time.sleep(0.3)

    if proc.poll() is not None and rec["url"] is None:
        # process died early — usually port issue or network
        tail = "\n".join(list(log_buf)[-6:]) or "(no output)"
        with _tunnel_lock:
            TUNNELS.pop(bot_id, None)
        return {"ok": False, "error": f"cloudflared exited early.\n{tail}"}

    if rec["url"] is None:
        # No URL within 15s and process still alive — kill it so we don't
        # leave an orphan cloudflared process running forever.
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            else:
                proc.terminate()
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()
        except Exception:
            pass
        with _tunnel_lock:
            TUNNELS.pop(bot_id, None)
        tail = "\n".join(list(log_buf)[-6:]) or "(no output)"
        return {"ok": False,
                "error": f"Tunnel timed out — no URL after 15s.\n{tail}"}

    return {"ok": True, "url": rec["url"], "port": port}


def _stop_tunnel(bot_id: str) -> bool:
    with _tunnel_lock:
        rec = TUNNELS.pop(bot_id, None)
    if not rec:
        return False
    proc = rec.get("proc")
    if not proc:
        return True
    try:
        if os.name == "posix":
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
        else:
            proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            try:
                if os.name == "posix":
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                else:
                    proc.kill()
            except Exception:
                pass
    except Exception:
        pass
    return True


def restart_child(b: Dict[str, Any]) -> Dict[str, Any]:
    stop_child(b["_id"], manual=False)
    time.sleep(1)
    return start_child(b)


# ═════════════════════════════════════════════════════════════════
#  VM RUNTIME  (PID-only, no local hosting)
#  Rules: max 1 bot per PID; pick the PID with most free RAM.
#  No local fallback — all start/stop/logs/delete via PID + MongoDB.
_VM_MAX_BOTS   = 1
_VM_RAM_LIMIT  = 500
_VM_RESERVE_MB = 80
_VM_LIGHT_MB   = 80


def _vm_get(vm_id: str) -> Optional[Dict[str, Any]]:
    return _vm_nodes().get(vm_id)


def _vm_count_on(vm_id: str) -> int:
    try:
        return sum(1 for x in db_load().get("bots", {}).values()
                   if x.get("vm_id") == vm_id and x.get("status") == "running")
    except Exception:
        return 0


def _vm_all_light(vm: Dict[str, Any]) -> bool:
    """True if every running bot on this PID uses < _VM_LIGHT_MB."""
    if _vmc is None:
        return False
    try:
        bots = [x for x in db_load().get("bots", {}).values()
                if x.get("vm_id") == vm.get("vm_id") and x.get("status") == "running"]
    except Exception:
        return False
    for x in bots:
        try:
            st = _vmc.get_bot_stats(vm["url"], vm.get("secret", ""), x["_id"])
        except Exception:
            return False
        if not st or not st.get("ok"):
            return False
        try:
            if float(st.get("ram_mb", 999)) > _VM_LIGHT_MB:
                return False
        except Exception:
            return False
    return True


def _vm_pick_best() -> Optional[Dict[str, Any]]:
    """Cheapest eligible PID: <1 bot, enough free RAM."""
    if not _ADDONS_OK or _vmc is None:
        return None
    cands = []
    for vm_id, vm in _vm_nodes().items():
        if not vm.get("enabled", True):
            continue
        try:
            if not _vmc.ping(vm["url"]):
                continue
            st = _vmc.get_status(vm["url"], vm.get("secret", ""))
        except Exception:
            continue
        if not st:
            continue
        n = _vm_count_on(vm_id)
        if n >= _VM_MAX_BOTS:
            continue
        try:
            free_mb = float(st.get("free_ram_mb", 0))
        except Exception:
            free_mb = 0
        if free_mb < _VM_RESERVE_MB:
            continue
        if not st.get("can_accept", True):
            continue
        if n == _VM_MAX_BOTS - 1 and not _vm_all_light(vm):
            continue
        cands.append((free_mb, vm))
    if not cands:
        return None
    cands.sort(key=lambda x: x[0], reverse=True)
    return cands[0][1]


def _pid_fetch_all_bots() -> Dict[str, Dict[str, Any]]:
    """Aggregate live bots from ALL PIDs. Returns bot_id -> {vm_id, live, record}.
    No local fallback — PIDs + DB are the only source of truth."""
    out: Dict[str, Dict[str, Any]] = {}
    if not _ADDONS_OK or _vmc is None:
        return out
    try:
        db_bots = db_load_ro().get("bots", {}) or {}
    except Exception:
        db_bots = {}
    for b in db_bots.values():
        try:
            out[b["_id"]] = {"vm_id": b.get("vm_id"), "live": None, "record": b}
        except Exception:
            pass
    for vm_id, vm in _vm_nodes().items():
        if not vm.get("enabled", True):
            continue
        try:
            res = _vmc.list_bots(vm["url"], vm.get("secret", ""))
        except Exception:
            continue
        bots = res.get("bots") if isinstance(res, dict) else None
        if not isinstance(bots, list):
            continue
        for rb in bots:
            try:
                bid = rb.get("bot_id")
                if not bid:
                    continue
                cur = out.get(bid) or {"vm_id": vm_id, "live": None, "record": None}
                cur["vm_id"] = vm_id
                cur["live"] = rb
                if cur.get("record") is None:
                    try:
                        cur["record"] = find_bot(bid)
                    except Exception:
                        cur["record"] = None
                out[bid] = cur
            except Exception:
                pass
    return out


def _pid_live_status(bot_id: str, b_doc: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Live status from PID only. Never uses local RUNNING for remote bots."""
    try:
        vm_id = (b_doc or {}).get("vm_id")
    except Exception:
        vm_id = None
    if vm_id and _ADDONS_OK and _vmc is not None:
        vm = _vm_get(vm_id)
        if vm:
            try:
                st = _vmc.get_bot_stats(vm["url"], vm.get("secret", ""), bot_id)
            except Exception:
                st = None
            if st and st.get("ok"):
                return {"running": st.get("status") == "running", "live": st, "vm": vm_id}
            return {"running": False, "live": st, "vm": vm_id}
    return {"running": False, "live": None, "vm": vm_id}


def _vm_deploy_bot(b: Dict[str, Any], vm: Dict[str, Any]) -> Dict[str, Any]:
    """Zip decrypted bot files and upload to the PID. Sets vm_id on success."""
    bid = b["_id"]
    bot_dir = Path(b.get("dir") or "")
    if not bot_dir.exists():
        return {"ok": False, "error": "Bot folder missing."}
    try:
        materialize_bot_files(b)
    except Exception as e:
        return {"ok": False, "error": f"decrypt failed: {e}"}
    tmp = tempfile.mkdtemp()
    try:
        zpath = str(Path(tmp) / f"{bid}.zip")
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
            for root, _, files in os.walk(bot_dir):
                for f in files:
                    fp = Path(root) / f
                    try:
                        if fp.stat().st_size > 20 * 1024 * 1024:
                            continue
                    except OSError:
                        continue
                    z.write(str(fp), str(fp.relative_to(bot_dir)))
        r = _vmc.deploy(vm["url"], vm.get("secret", ""), bid, zpath, _VM_RAM_LIMIT)
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if r.get("ok"):
        b["vm_id"] = vm["vm_id"]
        b["status"] = "running"
        try:
            b["last_started"] = ts_iso()
        except Exception:
            pass
        try:
            save_bot(b)
        except Exception:
            pass
        # ── auto-install requirements on the PID ─────────────────
        # If requirements.txt uploaded → install through it.
        # Else → analyze files, scan imports, auto-install missing.
        # api-vm already installs requirements.txt from the zip, but we
        # run an explicit install too so user requirements are guaranteed.
        try:
            req = Path(b.get("dir") or "") / "requirements.txt"
            if req.exists():
                pkgs = []
                for line in req.read_text(errors="ignore").splitlines():
                    line = line.strip()
                    if line and not line.startswith(("#", "-")):
                        pkgs.append(line.split()[0])
                if pkgs:
                    _vmc.pip_install(vm["url"], vm.get("secret", ""), bid, pkgs)
            else:
                try:
                    bot_dir2 = Path(b.get("dir") or "")
                    if bot_dir2.exists():
                        mods = _scan_imports(bot_dir2)
                        # PID has a FRESH venv — do NOT filter by main-bot
                        # importability. Only drop stdlib + local names.
                        stdlib = set(getattr(sys, "stdlib_module_names", set())) | {"__future__", ""}
                        local = set()
                        try:
                            for child in bot_dir2.iterdir():
                                if child.suffix == ".py":
                                    local.add(child.stem)
                                elif child.is_dir() and (child / "__init__.py").exists():
                                    local.add(child.name)
                        except Exception:
                            pass
                        pkgs2 = []
                        seen2 = set()
                        for m in mods:
                            if not m or m in stdlib or m in local:
                                continue
                            pip_name = _PYPI_ALIAS.get(m, m)
                            if pip_name in seen2:
                                continue
                            seen2.add(pip_name)
                            pkgs2.append(pip_name)
                        if pkgs2:
                            _vmc.pip_install(vm["url"], vm.get("secret", ""), bid, pkgs2[:20])
                except Exception:
                    pass
        except Exception:
            pass
        try:
            audit(b.get("owner", 0), "vm_deploy", f"{bid} -> {vm['vm_id']}")
        except Exception:
            pass
        return {"ok": True, "vm": vm["vm_id"]}
    return {"ok": False, "error": "FULL: " + str(r.get("error", "deploy failed"))}


def _is_full_error(res: Dict[str, Any]) -> bool:
    try:
        return str((res or {}).get("error", "")).startswith("FULL")
    except Exception:
        return False


def _notify_pid_full(owner_id: int, bot_name: str, detail: str = "") -> None:
    """User says VMs (not PIDs). Tell user VMs full + alert admins."""
    try:
        bot.send_message(
            owner_id,
            f"<b>⏳ {sc('Current all VMs are full')}</b>\n"
            f"{G['div']}\n"
            f"{bullet('Bot', bot_name)}\n"
            f"{G['div']}\n"
            f"{sc('Check back later, we will add new VMs within 24 hours')}.",
            parse_mode="HTML",
        )
    except Exception:
        pass
    targets: List[int] = []
    try:
        if OWNER_ID:
            targets.append(OWNER_ID)
        for uid_str in (db_load().get("admins") or {}).keys():
            try:
                uid_i = int(uid_str)
                if uid_i not in targets:
                    targets.append(uid_i)
            except Exception:
                pass
    except Exception:
        pass
    for tgt in targets:
        try:
            bot.send_message(
                tgt,
                f"<b>🚨 {sc('All VMs Full')}</b>\n"
                f"{G['div']}\n"
                f"{bullet('User ID', owner_id)}\n"
                f"{bullet('Bot', bot_name)}\n"
                f"{bullet('Detail', detail or '—')}\n"
                f"{bullet('Action', sc('Add new VMs within 24 hours'))}\n"
                f"{G['div']}",
                parse_mode="HTML",
            )
        except Exception:
            pass


def start_child(b: Dict[str, Any]) -> Dict[str, Any]:
    """PID-only start: deploy to a free PID. NEVER runs locally.
    On failure returns error starting with FULL (user-facing)."""
    if (b or {}).get("approval_status") == "pending":
        return {"ok": False, "error": "Bot is waiting for admin approval."}
    if (b or {}).get("approval_status") == "rejected":
        return {"ok": False, "error": "Bot was rejected by admin."}
    try:
        with _runner_lock:
            existing = RUNNING.get(b["_id"])
            if existing and existing["proc"].poll() is None:
                return {"ok": False, "error": "Already running."}
    except Exception:
        pass
    if _ADDONS_OK and _vmc is not None:
        vm_id = (b or {}).get("vm_id")
        if vm_id:
            vm = _vm_get(vm_id)
            if vm and vm.get("enabled", True):
                try:
                    r = _vmc.start(vm["url"], vm.get("secret", ""), b["_id"])
                    if r.get("ok"):
                        b["status"] = "running"
                        try:
                            save_bot(b)
                        except Exception:
                            pass
                        return {"ok": True, "vm": vm_id}
                except Exception:
                    pass
        else:
            try:
                best = _vm_pick_best()
            except Exception:
                best = None
            if best is not None:
                res = _vm_deploy_bot(b, best)
                if res.get("ok"):
                    return res
                return {"ok": False, "error": str(res.get("error", "FULL: deploy failed"))}
            return {"ok": False, "error": "FULL: Current all VMs are full. Check back later, we will add new VMs within 24 hours."}
    return {"ok": False, "error": "FULL: VMs not configured. Contact admin."}


def stop_child(bot_id: str, manual: bool = True) -> Dict[str, Any]:
    """PID-only stop: stop on PID, sync DB + Mongo. No local hosting."""
    try:
        b = find_bot(bot_id)
    except Exception:
        b = None
    if b and b.get("vm_id") and _ADDONS_OK and _vmc is not None:
        vm = _vm_get(b["vm_id"])
        if vm:
            try:
                _vmc.stop(vm["url"], vm.get("secret", ""), b["_id"])
            except Exception:
                pass
            try:
                b["status"] = "stopped"
                save_bot(b)
            except Exception:
                pass
            try:
                if _mdb is not None:
                    _mdb.save_bot({"bot_id": b["_id"], "vm_id": b.get("vm_id", ""), "owner_id": b.get("owner", 0), "status": "stopped"})
            except Exception:
                pass
    return _stop_child_local(bot_id, manual=manual)


def delete_bot_doc(bot_id: str) -> None:
    """Delete from PID + MongoDB + local record. PID is source of truth."""
    try:
        b = find_bot(bot_id)
        if b and b.get("vm_id") and _ADDONS_OK and _vmc is not None:
            vm = _vm_get(b["vm_id"])
            if vm:
                try:
                    _vmc.delete(vm["url"], vm.get("secret", ""), b["_id"])
                except Exception:
                    pass
    except Exception:
        pass
    try:
        if _ADDONS_OK and _mdb is not None:
            try:
                _mdb.delete_bot_record(bot_id)
            except Exception:
                pass
            try:
                _mdb.delete_bot_file(bot_id)
            except Exception:
                pass
    except Exception:
        pass
    return _delete_bot_doc_local(bot_id)


def tail_log(bot_id: str, lines: int = 60) -> str:
    """PID-only logs. No local fallback for remote bots (no main-bot load)."""
    try:
        b = find_bot(bot_id)
    except Exception:
        b = None
    if b and b.get("vm_id"):
        if _ADDONS_OK and _vmc is not None:
            vm = _vm_get(b["vm_id"])
            if vm:
                try:
                    r = _vmc.get_logs(vm["url"], vm.get("secret", ""), b["_id"], lines=lines)
                    if r.get("ok"):
                        return "\n".join(r.get("lines", []))
                except Exception:
                    pass
        return ""
    try:
        info = RUNNING.get(bot_id)
    except Exception:
        info = None
    log = (info["log"] if info else []) or []
    return "\n".join(log[-lines:])


def child_status(bot_id: str, b_doc: Dict[str, Any]) -> Dict[str, Any]:
    try:
        vm_id = (b_doc or {}).get("vm_id")
    except Exception:
        vm_id = None
    if vm_id:
        if _ADDONS_OK and _vmc is not None:
            vm = _vm_get(vm_id)
            if vm:
                try:
                    st = _vmc.get_bot_stats(vm["url"], vm.get("secret", ""), bot_id)
                except Exception:
                    st = None
                if st and st.get("ok"):
                    return {
                        "running":   st.get("status") == "running",
                        "pid":       st.get("pid"),
                        "kind":      "remote-vm",
                        "uptimeMs":  int(st.get("uptime_s", 0)) * 1000,
                        "sizeBytes": 0,
                        "logs":      [],
                        "cpuPct":    0.0,
                        "memBytes":  float(st.get("ram_mb", 0)) * 1024 * 1024,
                        "sandboxed": False,
                        "vm":        vm_id,
                    }
        # Remote bot but PID unreachable — report stopped, never local.
        return {"running": False, "pid": None, "kind": "remote-vm", "uptimeMs": 0,
                "sizeBytes": 0, "logs": [], "cpuPct": 0.0, "memBytes": 0.0,
                "sandboxed": False, "vm": vm_id}
    info = RUNNING.get(bot_id)
    running = bool(info and info["proc"].poll() is None)
    bot_dir = Path(b_doc.get("dir") or "")
    kind, _ = detect_entry(bot_dir) if bot_dir.exists() else (None, None)
    sz = 0
    try:
        for root, _, files in os.walk(bot_dir):
            for f in files:
                try:
                    sz += (Path(root) / f).stat().st_size
                except OSError:
                    pass
    except Exception:
        pass
    cpu = mem = 0.0
    if running and psutil is not None:
        try:
            p = psutil.Process(info["proc"].pid)
            cpu = p.cpu_percent(interval=0.05)
            mem = p.memory_info().rss
        except Exception:
            pass
    return {
        "running":   running,
        "pid":       info["proc"].pid if running else None,
        "kind":      (info["kind"] if info else kind) or "—",
        "uptimeMs":  int(time.time() * 1000 - info["started"]) if running else 0,
        "sizeBytes": sz,
        "logs":      info["log"] if info else [],
        "cpuPct":    cpu,
        "memBytes":  mem,
        "sandboxed": True,
    }


# ════════════════════════════════════════════════
# 11. ENCRYPTED  BOT  STORAGE
# ═════════════════════════════════════════════════════

def store_uploaded_file(uploader: types.User, filename: str, plain: bytes) -> Dict[str, Any]:
    """
    Encrypt + persist an uploaded file. Returns metadata describing
    where the encrypted blob lives and which key_id unlocks it.
    """
    safe = safe_name(filename)
    key_id, key, cipher = encrypt_file(plain)
    rel = f"{uploader.id}/{int(time.time())}_{safe}.enc"
    out = DIRS["encfiles"] / rel
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(cipher)

    meta = {
        "filename": filename,
        "uploader_id": uploader.id,
        "uploader_username": uploader.username or "",
        "size": len(plain),
        "uploaded": ts_iso(),
        "stored_at": str(out),
    }
    KEYRING.store(key_id, key, meta)

    # notify_owner HATA DIYA — ab upload handler mein sirf ek summary msg aayega
    return {"key_id": key_id, "path": str(out), "size": len(plain)}


def materialize_bot_files(b: Dict[str, Any]) -> None:
    """Decrypt every encrypted file for this bot into its sandbox dir."""
    bot_dir = Path(b["dir"])
    bot_dir.mkdir(parents=True, exist_ok=True)
    files = b.get("enc_files") or []
    for f in files:
        key = KEYRING.fetch(f["key_id"])
        if not key:
            raise RuntimeError(f"missing key {f['key_id']}")
        try:
            plain = read_encrypted(Path(f["enc_path"]), key)
        except InvalidToken:
            raise RuntimeError(f"key mismatch for {f.get('filename')}")
        # write into bot_dir
        rel = f.get("rel_path") or f["filename"]
        rel = rel.lstrip("/")
        try:
            tgt = safe_path_join(bot_dir, rel)
        except ValueError:
            continue
        tgt.parent.mkdir(parents=True, exist_ok=True)
        tgt.write_bytes(plain)
        # wipe key from memory after using it
        plain = b""
    # KEYRING memory wipe (re-fetched on next run)
    for f in files:
        KEYRING.wipe(f["key_id"])


def encrypted_dump_for_download(b: Dict[str, Any]) -> Optional[Path]:
    """Build a zip of the *encrypted* blobs for this bot. Useless without keys."""
    files = b.get("enc_files") or []
    if not files:
        return None
    out = Path(tempfile.gettempdir()) / f"enc_{b['_id']}.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for f in files:
            p = Path(f["enc_path"])
            if p.exists():
                z.write(p, arcname=f.get("rel_path") or f["filename"])
        z.writestr(
            "_README.txt",
            f"These files are encrypted with Fernet/AES-128.\n"
            f"They cannot be read without the per-file key, which is\n"
            f"stored in a private GitHub repository owned by {BRAND_TAG}.\n",
        )
    return out



# 12. GITHUB  BACKUP / RESTORE  (panel state)

GH = {
    "token": "", "repo": "", "branch": "main",
    "intervalMin": 360,
    "lastBackup": None, "lastError": None,
    "inProgress": False, "autoEnabled": True,
}


def gh_load_config() -> None:
    GH["token"]  = os.environ.get("GITHUB_TOKEN")  or get_setting("github_token", "")  or ""
    GH["repo"]   = os.environ.get("GITHUB_REPO")   or get_setting("github_repo", "")   or ""
    GH["branch"] = os.environ.get("GITHUB_BRANCH") or get_setting("github_branch", "main") or "main"
    try:
        ivl = int(os.environ.get("GITHUB_AUTO_INTERVAL_MIN") or get_setting("github_interval_min", 360))
    except Exception:
        ivl = 360
    GH["intervalMin"] = ivl if ivl > 0 else 360


def gh_set_config(patch: Dict[str, Any]) -> None:
    keymap = {"token": "github_token", "repo": "github_repo",
              "branch": "github_branch", "intervalMin": "github_interval_min"}
    for k, v in patch.items():
        if k not in keymap:
            continue
        if k == "intervalMin":
            try:
                v = int(v)
            except Exception:
                v = 360
        GH[k] = v
        set_setting(keymap[k], v)


def gh_enabled() -> bool:
    return bool(GH["token"] and GH["repo"] and "/" in GH["repo"])


def gh_status() -> Dict[str, Any]:
    return {
        "enabled":     gh_enabled(),
        "repo":        GH["repo"], "branch": GH["branch"],
        "intervalMin": GH["intervalMin"],
        "autoEnabled": GH["autoEnabled"],
        "lastBackup":  GH["lastBackup"],
        "lastError":   GH["lastError"],
        "inProgress":  GH["inProgress"],
        "tokenSet":    bool(GH["token"]),
        "repoSet":     bool(GH["repo"]),
    }


def _gh(method: str, url: str, **kw) -> requests.Response:
    h = kw.pop("headers", {}) or {}
    h.setdefault("Authorization", f"token {GH['token']}")
    h.setdefault("Accept", "application/vnd.github+json")
    h.setdefault("User-Agent", "simran-hosting-rbot/2.1")
    return requests.request(method, url, headers=h, timeout=60, **kw)


def _gh_repo_url(p: str = "") -> str:
    return f"https://api.github.com/repos/{GH['repo']}/{p.lstrip('/')}"


def _gh_ensure_branch() -> bool:
    r = _gh("GET", _gh_repo_url(f"branches/{GH['branch']}"))
    if r.status_code == 200:
        return True
    if r.status_code != 404:
        return False
    info = _gh("GET", _gh_repo_url())
    if info.status_code != 200:
        return False
    default = info.json().get("default_branch", "main")
    ref = _gh("GET", _gh_repo_url(f"git/ref/heads/{default}"))
    if ref.status_code != 200:
        return False
    sha = ref.json()["object"]["sha"]
    _gh("POST", _gh_repo_url("git/refs"),
        json={"ref": f"refs/heads/{GH['branch']}", "sha": sha})
    return True


def _gh_put_file(path: str, content: bytes, message: str) -> bool:
    sha: Optional[str] = None
    g = _gh("GET", _gh_repo_url(f"contents/{path}"), params={"ref": GH["branch"]})
    if g.status_code == 200:
        sha = g.json().get("sha")
    elif g.status_code != 404:
        return False
    body: Dict[str, Any] = {
        "message": message, "branch": GH["branch"],
        "content": base64.b64encode(content).decode(),
    }
    if sha:
        body["sha"] = sha
    r = _gh("PUT", _gh_repo_url(f"contents/{path}"), json=body)
    return r.status_code in (200, 201)


def _make_tarball() -> Path:
    tmp = Path(tempfile.gettempdir()) / f"panel-backup-{int(time.time())}.tar.gz"
    excludes = ("node_modules", ".deps", ".tmp_run", "__pycache__")

    def _filter(ti: tarfile.TarInfo) -> Optional[tarfile.TarInfo]:
        if any(x in ti.name.split("/") for x in excludes):
            return None
        if ti.name.endswith(".log"):
            return None
        return ti

    with tarfile.open(tmp, "w:gz") as tf:
        # Backup storage/ — users, bots DB, encrypted files, keys, tickets
        storage_dir = BASE_DIR / "storage"
        if storage_dir.exists():
            tf.add(str(storage_dir), arcname="storage", filter=_filter)
        # Backup sandbox/ — bot env vars, cron config (not .deps to save space)
        sandbox_dir = BASE_DIR / "sandbox"
        if sandbox_dir.exists():
            tf.add(str(sandbox_dir), arcname="sandbox", filter=_filter)
    return tmp


def gh_backup_now() -> Dict[str, Any]:
    if not gh_enabled():
        return {"ok": False, "error": "Not configured."}
    if GH["inProgress"]:
        return {"ok": False, "error": "Backup already running."}
    GH["inProgress"] = True
    tar: Optional[Path] = None
    try:
        if not _gh_ensure_branch():
            raise RuntimeError(f"Branch {GH['branch']} unavailable")
        tar = _make_tarball()
        buf = tar.read_bytes()
        size_mb = len(buf) / 1024 / 1024
        if size_mb > 95:
            raise RuntimeError(f"Backup {size_mb:.1f} MB > 95 MB GitHub limit")
        ts = ts_iso().replace(":", "-").replace(".", "-")
        ok1 = _gh_put_file("backups/latest.tar.gz", buf, f"chore(panel): backup {ts}")
        ok2 = _gh_put_file(f"backups/{ts}.tar.gz", buf, f"chore(panel): snapshot {ts}")
        manifest = json.dumps({"lastBackup": ts, "sizeBytes": len(buf)}, indent=2)
        _gh_put_file("backups/manifest.json", manifest.encode(), f"chore(panel): manifest {ts}")
        if not (ok1 and ok2):
            raise RuntimeError("upload failed")
        GH["lastBackup"] = ts
        GH["lastError"] = None
        return {"ok": True, "sizeMB": f"{size_mb:.2f}", "ts": ts}
    except Exception as e:
        GH["lastError"] = str(e)
        return {"ok": False, "error": str(e)}
    finally:
        if tar and tar.exists():
            try:
                tar.unlink()
            except Exception:
                pass
        GH["inProgress"] = False


def gh_restore_now(overwrite: bool = True) -> Dict[str, Any]:
    if not gh_enabled():
        return {"ok": False, "error": "Not configured."}
    r = _gh("GET", _gh_repo_url("contents/backups/latest.tar.gz"),
            params={"ref": GH["branch"]})
    if r.status_code == 404:
        return {"ok": False, "error": "No backup found yet."}
    if r.status_code != 200:
        return {"ok": False, "error": f"GitHub HTTP {r.status_code}"}
    buf = base64.b64decode(r.json()["content"])
    tmp = Path(tempfile.gettempdir()) / f"panel-restore-{int(time.time())}.tar.gz"
    tmp.write_bytes(buf)
    try:
        if overwrite:
            # Wipe both storage and sandbox before restoring
            for folder in ("storage", "sandbox"):
                d = BASE_DIR / folder
                if d.exists():
                    for sub in d.iterdir():
                        rmrf(sub)
        with tarfile.open(tmp, "r:gz") as tf:
            tf.extractall(str(BASE_DIR))
        # Re-create required dirs in case they were missing in backup
        for _p in DIRS.values():
            _p.mkdir(parents=True, exist_ok=True)
        return {"ok": True, "sizeBytes": len(buf)}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        try:
            tmp.unlink()
        except Exception:
            pass


def gh_auto_loop() -> None:
    while True:
        try:
            time.sleep(max(60, GH["intervalMin"] * 60))
            if gh_enabled() and GH["autoEnabled"]:
                res = gh_backup_now()
                if not res.get("ok"):
                    err = res.get("error", "unknown")
                    print(f"[gh_auto_loop] backup failed: {err}", flush=True)
                    try:
                        notify_owner(
                            f"<b>{G['warn']} {sc('GitHub auto-backup failed')}</b>\n"
                            f"{bullet('Error', esc(err))}"
                        )
                    except Exception:
                        pass
                else:
                    print(f"[gh_auto_loop] backup ok ({res.get('sizeMB')} MB)",
                          flush=True)
        except Exception as e:
            print(f"[gh_auto_loop] loop error: {e}", flush=True)
            traceback.print_exc()


_GH_UPTIME_BACKUP_THRESHOLD = 10 * 60  # seconds — only back up bots running >=10 min


_GH_USER_DATA_LAST_PUSH = [0.0]


def gh_uptime_backup_loop() -> None:
    """Per-bot GitHub backup that fires only after a bot has been
    running uninterrupted for >=10 minutes. This avoids polluting the
    backup repo with broken uploads / quick test runs.

    Re-syncs a bot only when its encrypted files have been modified
    since the last successful sync (so editing env vars or restarting
    doesn't spam GitHub)."""
    while True:
        try:
            time.sleep(60)
            if not (gh_enabled() and GH.get("autoEnabled", True)):
                continue
            now = time.time()
            # Refresh the master DB index every 5 minutes so plan
            # changes / new users / approval toggles get backed up
            # even if no bot files changed.
            if now - _GH_USER_DATA_LAST_PUSH[0] > 5 * 60:
                try:
                    if gh_sync_user_data():
                        _GH_USER_DATA_LAST_PUSH[0] = now
                except Exception:
                    pass
            with _runner_lock:
                items = list(RUNNING.items())
            for bot_id, info in items:
                proc = info.get("proc")
                if not proc or proc.poll() is not None:
                    continue
                started = info.get("started", now)
                if (now - started) < _GH_UPTIME_BACKUP_THRESHOLD:
                    continue
                b = find_bot(bot_id)
                if not b:
                    continue
                last = float(b.get("gh_synced_at") or 0)
                # Latest mtime across all encrypted files
                file_mtime = 0.0
                for f in b.get("enc_files") or []:
                    p = Path(f.get("enc_path", ""))
                    try:
                        if p.exists():
                            file_mtime = max(file_mtime, p.stat().st_mtime)
                    except Exception:
                        pass
                if last and file_mtime and file_mtime <= last:
                    continue   # nothing new since last successful sync
                try:
                    _gh_sync_bot_files(b)
                    b["gh_synced_at"] = int(now)
                    save_bot(b)
                    print(f"[gh_uptime_backup] synced bot={bot_id} "
                          f"(uptime={int(now - started)}s)", flush=True)
                except Exception as e:
                    print(f"[gh_uptime_backup] {bot_id} failed: {e}", flush=True)
                # Pace the loop: GitHub's contents API rate-limits at
                # ~5000 req/hr per token. With many bots running, hammering
                # the API back-to-back risks 403s. A small inter-bot sleep
                # spreads the load and gives other threads CPU room.
                time.sleep(1.5)
        except Exception as e:
            print(f"[gh_uptime_backup] loop error: {e}", flush=True)
            traceback.print_exc()


def gh_auto_restore_on_boot() -> Optional[Dict[str, Any]]:
    """Restore from GitHub on boot ONLY when local storage is empty.

    Order of preference:
      1) New per-file layout (user_data.json + user_uploads/<uid>/<bid>/...)
      2) Legacy tarball at backups/latest.tar.gz  (full overwrite)

    We never overwrite a non-empty local DB — that would clobber any
    changes the user made between the last sync and this restart.

    Custom admin banner photos (storage/photos/custom_*.png) are ALWAYS
    pulled from GitHub on boot when missing locally — independent of the
    DB-empty check — so a wiped photos folder is rebuilt on restart."""
    if not gh_enabled():
        return None
    if not GH.get("autoEnabled", False):
        return None
    # Always try to repopulate admin-set banner photos first; this is safe
    # because gh_restore_custom_photos() never overwrites an existing local
    # file and only ever touches storage/photos/.
    try:
        photos_res = gh_restore_custom_photos()
        if photos_res.get("ok") and photos_res.get("restored", 0):
            print(f"[gh_restore] photos: {photos_res['restored']} banners restored",
                  flush=True)
    except Exception as _pe:
        print(f"[gh_restore] photos failed: {_pe}", flush=True)
    try:
        if DB_FILE.exists():
            data = json.loads(DB_FILE.read_text(encoding="utf-8") or "{}")
            users = data.get("users") or {}
            bots = data.get("bots") or {}
            if users or bots:
                return {"ok": False, "skip": True,
                        "reason": "local data present, not restoring"}
    except Exception:
        pass
    # Try new layout first
    res = gh_restore_user_uploads()
    if res.get("ok"):
        try:
            print(f"[gh_restore] new-layout: {res.get('bots',0)} bots, "
                  f"{res.get('files',0)} files restored", flush=True)
        except Exception:
            pass
        return res
    # Fallback: legacy tarball
    return gh_restore_now(overwrite=True)

def _gh_bot_dir(b: Dict[str, Any]) -> str:
    """Per-bot folder layout requested by the user:
       user_uploads/<user_id>/<bot_id>/..."""
    return f"user_uploads/{b.get('owner', 0)}/{b['_id']}"


def _gh_get_file(path: str) -> Optional[bytes]:
    if not gh_enabled():
        return None
    try:
        r = _gh("GET", _gh_repo_url(f"contents/{path}"),
                params={"ref": GH["branch"]})
        if r.status_code != 200:
            return None
        return base64.b64decode(r.json()["content"])
    except Exception:
        return None


def _gh_delete_path(path: str, message: str) -> bool:
    """Best-effort delete of a single file path."""
    try:
        r = _gh("GET", _gh_repo_url(f"contents/{path}"),
                params={"ref": GH["branch"]})
        if r.status_code != 200:
            return False
        sha = r.json().get("sha")
        if not sha:
            return False
        d = _gh("DELETE", _gh_repo_url(f"contents/{path}"),
                json={"message": message, "sha": sha, "branch": GH["branch"]})
        return d.status_code in (200, 204)
    except Exception:
        return False


def gh_sync_user_data() -> bool:
    """Push the master DB (user_data.json) to the backup repo. This is
    the single source of truth for users + bot metadata, and is small
    enough that we can re-upload it whenever something stable changes."""
    if not gh_enabled():
        return False
    try:
        if not _gh_ensure_branch():
            return False
        if not DB_FILE.exists():
            return False
        buf = DB_FILE.read_bytes()
        ok = _gh_put_file("user_data.json", buf,
                          f"sync: user_data {ts_iso()}")
        # Also push settings (photos config, approval flag, etc.)
        if SETTINGS_FILE.exists():
            try:
                _gh_put_file("settings.json", SETTINGS_FILE.read_bytes(),
                             f"sync: settings {ts_iso()}")
            except Exception:
                pass
        return ok
    except Exception as e:
        print(f"[gh_sync_user_data] {e}")
        return False


def _gh_sync_bot_files(b: Dict[str, Any]) -> None:
    """Per-bot file sync to user_uploads/<owner>/<bot_id>/.
    Triggered from the uptime loop only AFTER the bot has been running
    for >=10 min — so broken/test uploads never reach GitHub."""
    if not gh_enabled():
        return
    try:
        _gh_ensure_branch()
        bot_dir = _gh_bot_dir(b)
        for f in b.get("enc_files") or []:
            p = Path(f["enc_path"])
            if not p.exists():
                continue
            # Use the on-disk filename (already includes timestamp suffix
            # via store_uploaded_file -> "<ts>_<name>.enc")
            gh_path = f"{bot_dir}/{p.name}"
            _gh_put_file(gh_path, p.read_bytes(),
                         f"upload: bot={b['_id']} file={p.name}")
        meta = json.dumps({
            "bot_id":    b["_id"],
            "owner":     b.get("owner"),
            "name":      b.get("name"),
            "enc_files": b.get("enc_files", []),
            "env":       b.get("env", {}),
            "cron":      b.get("cron", {}),
            "status":    b.get("status"),
            "created":   b.get("created"),
            "synced":    ts_iso(),
        }, indent=2).encode()
        _gh_put_file(f"{bot_dir}/bot_meta.json", meta,
                     f"meta: bot={b['_id']}")
        # Each successful per-bot sync also pushes the latest user_data.json
        # so that on a full restore we get an up-to-date users + bots index.
        gh_sync_user_data()
    except Exception as e:
        print(f"[gh_sync] {e}")


def _gh_delete_bot_files(b: Dict[str, Any]) -> None:
    if not gh_enabled():
        return
    try:
        bot_dir = _gh_bot_dir(b)
        for f in b.get("enc_files") or []:
            p = Path(f["enc_path"])
            _gh_delete_path(f"{bot_dir}/{p.name}",
                            f"delete: bot={b['_id']} file={p.name}")
        _gh_delete_path(f"{bot_dir}/bot_meta.json",
                        f"delete: bot={b['_id']} meta")
    except Exception as e:
        print(f"[gh_delete] {e}")


def _gh_list_dir(path: str) -> List[Dict[str, Any]]:
    """List immediate children of a directory in the repo."""
    if not gh_enabled():
        return []
    try:
        r = _gh("GET", _gh_repo_url(f"contents/{path}"),
                params={"ref": GH["branch"]})
        if r.status_code != 200:
            return []
        data = r.json()
        return data if isinstance(data, list) else []
    except Exception:
        return []


def gh_restore_user_uploads() -> Dict[str, Any]:
    """Restore the new-style backup: user_data.json + the per-bot
    encrypted files under user_uploads/<uid>/<bot_id>/*.

    Falls back gracefully if the layout isn't present (e.g. a fresh
    repo) — caller can then try the legacy tarball restore."""
    if not gh_enabled():
        return {"ok": False, "error": "Not configured."}
    user_data = _gh_get_file("user_data.json")
    if user_data is None:
        return {"ok": False, "error": "No user_data.json in repo (new-style backup not found)."}
    files_restored = 0
    bots_restored = 0
    try:
        # 1) Restore the master DB first so we know which bots/owners exist.
        DB_FILE.parent.mkdir(parents=True, exist_ok=True)
        DB_FILE.write_bytes(user_data)
        _cache_invalidate(DB_FILE)
        # Restore settings if present
        s_buf = _gh_get_file("settings.json")
        if s_buf is not None:
            SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
            SETTINGS_FILE.write_bytes(s_buf)
            _cache_invalidate(SETTINGS_FILE)
        # 2) Walk every bot in the DB and pull its encrypted files back.
        db = db_load()
        for bot_id, b in (db.get("bots") or {}).items():
            owner = b.get("owner") or 0
            bot_dir_local = Path(b.get("dir") or (DIRS["sandbox"] / f"{owner}_{bot_id}"))
            bot_dir_local.mkdir(parents=True, exist_ok=True)
            gh_dir = f"user_uploads/{owner}/{bot_id}"
            entries = _gh_list_dir(gh_dir)
            for ent in entries:
                name = ent.get("name") or ""
                if not name.endswith(".enc"):
                    continue  # bot_meta.json etc. handled separately
                buf = _gh_get_file(f"{gh_dir}/{name}")
                if buf is None:
                    continue
                # Restore encrypted blob to its original location
                # (DIRS["encfiles"]/<owner>/<filename>.enc) so that the
                # paths stored inside enc_files[].enc_path keep working.
                target_dir = DIRS["encfiles"] / str(owner)
                target_dir.mkdir(parents=True, exist_ok=True)
                (target_dir / name).write_bytes(buf)
                files_restored += 1
            bots_restored += 1
        return {"ok": True, "bots": bots_restored, "files": files_restored}
    except Exception as e:
        return {"ok": False, "error": f"restore error: {e}"}


# 13. NOTIFY OWNER  /  ANNOUNCEMENTS

def notify_owner(html: str) -> None:
    if not OWNER_ID:
        return
    try:
        bot.send_message(OWNER_ID, html, parse_mode="HTML")
    except Exception as e:
        print(f"[notify_owner] {e}")


def post_announcement(html: str) -> None:
    if not ANNOUNCE_CHANNEL:
        return
    try:
        bot.send_message(ANNOUNCE_CHANNEL, html, parse_mode="HTML")
    except Exception as e:
        print(f"[announce] {e}")



# 14. USER  MANAGEMENT

def get_or_create_user(u: types.User, ref: Optional[int] = None) -> Tuple[Dict[str, Any], bool]:
    db = db_load()
    key = str(u.id)
    is_new = key not in db["users"]
    if is_new:
        db["users"][key] = {
            "_id": u.id, "name": u.first_name or "", "username": u.username or "",
            "plan": "free", "plan_expires": None,
            "joined": ts_iso(), "last_seen": ts_iso(),
            "banned": False, "ban_reason": "",
            "wallet": 0, "kyc": False,
            "verified": False, "verified_at": None,
            "ref_by": ref if ref and ref != u.id else None,
            "ref_count": 0, "ref_credit": 0, "trial_used": False,
            "bot_slots_bonus": 0,
            "stats": {"commands": 0, "bots_uploaded": 0, "logins": 1},
        }
        db_save(db)
        if ref and ref != u.id and str(ref) in db["users"]:
            db["users"][str(ref)]["ref_count"] = int(db["users"][str(ref)].get("ref_count", 0)) + 1
            db["users"][str(ref)]["ref_credit"] = int(db["users"][str(ref)].get("ref_credit", 0)) + 1
            db["users"][str(ref)]["bot_slots_bonus"] = int(
                db["users"][str(ref)].get("bot_slots_bonus", 0)) + 1
            db_save(db)
            try:
                bot.send_message(
                    ref,
                    f"<b>{G['plus']} {sc('You earned a referral bonus')}</b>\n"
                    f"{bullet('From', f'@{u.username or u.first_name}')}\n"
                    f"{bullet('Bonus', '+1 bot slot, +1 wallet credit')}",
                )
            except Exception:
                pass
        notify_owner(
            f"<b>{G['plus']} {sc('New user joined')}</b>\n"
            f"{bullet('Name', u.first_name)}\n"
            f"{bullet('Username', '@' + (u.username or '—'))}\n"
            f"{bullet('User ID', u.id)}"
        )
    else:
        db["users"][key]["last_seen"] = ts_iso()
        db["users"][key]["stats"]["logins"] = int(
            db["users"][key]["stats"].get("logins", 0)) + 1
        db_save(db)
    return db["users"][key], is_new


def list_user_bots(uid: int) -> List[Dict[str, Any]]:
    # Return deep-copies so callers can mutate without corrupting the
    # shared cache.
    return [copy.deepcopy(b) for b in db_load_ro()["bots"].values()
            if b.get("owner") == uid]


def find_bot(bot_id: str) -> Optional[Dict[str, Any]]:
    b = db_load_ro()["bots"].get(bot_id)
    return copy.deepcopy(b) if b is not None else None


def save_bot(doc: Dict[str, Any]) -> Dict[str, Any]:
    d = db_load()
    d["bots"][doc["_id"]] = doc
    db_save(d)
    # Per-bot JSON backup
    try:
        bot_json = DIRS["bot_data"] / f"{doc['_id']}.json"
        _atomic_write(bot_json, {
            "bot_id":    doc["_id"],
            "owner":     doc.get("owner"),
            "name":      doc.get("name"),
            "status":    doc.get("status"),
            "env":       doc.get("env", {}),
            "cron":      doc.get("cron", {}),
            "enc_files": doc.get("enc_files", []),
            "dir":       doc.get("dir"),
            "created":   doc.get("created"),
            "last_started": doc.get("last_started"),
            "updated":   ts_iso(),
        })
    except Exception:
        pass
    return doc


def _delete_bot_doc_local(bot_id: str) -> None:
    d = db_load()
    d["bots"].pop(bot_id, None)
    db_save(d)
    # Per-bot JSON bhi delete karo
    try:
        (DIRS["bot_data"] / f"{bot_id}.json").unlink(missing_ok=True)
    except Exception:
        pass


def user_max_bots(u: Dict[str, Any]) -> int:
    plan = u.get("plan", "free")
    default = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])["max_bots"]
    # Honor admin override from Settings → Plans Editor.
    base = int(get_setting(f"plan_max_bots_{plan}", default))
    return base + int(u.get("bot_slots_bonus", 0))


def user_plan_active(u: Dict[str, Any]) -> bool:
    if u.get("plan") == "free":
        return True
    exp = u.get("plan_expires")
    if not exp:
        return False
    try:
        return datetime.fromisoformat(str(exp).replace("Z", "+00:00")) > now_utc()
    except Exception:
        return False


def downgrade_expired_users() -> None:
    d = db_load()
    changed = False
    for uid, u in d["users"].items():
        if u.get("plan") == "free":
            continue
        if not user_plan_active(u):
            u["plan"] = "free"
            u["plan_expires"] = None
            changed = True
            try:
                bot.send_message(
                    int(uid),
                    f"<b>{G['warn']} {sc('Plan expired')}</b>\n\n"
                    f"Your plan has expired. You have been downgraded to <b>Free</b>.\n"
                    f"Renew anytime from the Buy Plan menu.{FOOTER}",
                )
            except Exception:
                pass
    if changed:
        db_save(d)


def expiry_reminders() -> None:
    d = db_load()
    today = now_utc()
    for uid, u in d["users"].items():
        if u.get("plan") == "free":
            continue
        exp = u.get("plan_expires")
        if not exp:
            continue
        try:
            ed = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
        except Exception:
            continue
        days_left = (ed - today).days
        last_warn = u.get("last_expiry_warn", -1)
        for threshold in (7, 3, 1):
            if days_left == threshold and last_warn != threshold:
                try:
                    bot.send_message(
                        int(uid),
                        f"<b>{G['warn']} {sc('Plan ending soon')}</b>\n\n"
                        f"Your <b>{esc(PLAN_LIMITS.get(u['plan'], {}).get('name'))}</b> plan "
                        f"expires in <b>{days_left} day(s)</b>.\n"
                        f"Renew now to avoid downgrade.{FOOTER}",
                    )
                    u["last_expiry_warn"] = threshold
                    db_save(d)
                except Exception:
                    pass


def grant_plan(uid: int, plan: str, days: Optional[int] = None) -> bool:
    d = db_load()
    key = str(uid)
    if key not in d["users"] or plan not in PLAN_LIMITS:
        return False
    u = d["users"][key]
    pl = PLAN_LIMITS[plan]
    days = days if days is not None else pl["days"]
    if plan == "free":
        u["plan"] = "free"
        u["plan_expires"] = None
    else:
        u["plan"] = plan
        # extend if same plan; else set fresh
        try:
            cur_exp = datetime.fromisoformat(str(u.get("plan_expires") or "").replace("Z", "+00:00"))
        except Exception:
            cur_exp = now_utc()
        if cur_exp < now_utc() or u.get("plan") != plan:
            cur_exp = now_utc()
        u["plan_expires"] = (cur_exp + timedelta(days=days)).isoformat()
        u["last_expiry_warn"] = -1
    db_save(d)
    try:
        bot.send_message(
            uid,
            f"<b>{G['ok']} {sc('Plan activated')}</b>\n\n"
            f"{bullet('Plan', pl['name'])}\n"
            f"{bullet('Bots',  pl['max_bots'])}\n"
            f"{bullet('RAM',   '{} MB'.format(pl['ram']))}\n"
            f"{bullet('Until', fmt_ts(u.get('plan_expires')) if u.get('plan_expires') else 'Lifetime')}"
            f"{FOOTER}",
        )
    except Exception:
        pass
    return True


# ═════════════════════════════════════════════════════════════════
# 15. CALLBACK / HANDLER  COMMON HELPERS
# ═════════════════════════════════════════════════════════════════

def ack(call: types.CallbackQuery, text: str = "") -> None:
    try:
        bot.answer_callback_query(call.id, text=text)
    except Exception:
        pass


# ── Animated progress-bar loading indicator ──────────────────────
# Active per-message animations live here so we can stop them when the
# real menu re-renders. Key: (chat_id, message_id) → threading.Event.
_LOADING_STOPS: Dict[Tuple[int, int], "threading.Event"] = {}
_LOADING_LOCK = threading.Lock()


def _progress_bar(pct: int, width: int = 20) -> str:
    """`▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░ 70%` style bar."""
    pct = max(0, min(100, int(pct)))
    filled = int(round(width * pct / 100))
    return "▓" * filled + "░" * (width - filled) + f" {pct:>3}%"


def _cancel_loading(chat_id: int, message_id: int) -> None:
    """Stop any animation thread attached to this message."""
    with _LOADING_LOCK:
        evt = _LOADING_STOPS.pop((chat_id, message_id), None)
    if evt:
        evt.set()


def loading(call: types.CallbackQuery, label: str = "Loading") -> None:
    """Show an animated progress bar (▓▓▓░░░ 45 %) the instant a slow
    callback starts, so the user sees their tap was received.

    The bar is rendered into the same message that triggered the
    callback (caption-edit for photo menus, text-edit for plain
    messages) and is then advanced by a daemon thread until the
    handler finishes. The next show_menu / show_text call on that
    message stops the animation automatically — handlers do not need
    to call anything to clean up.
    """
    if not (call and call.message):
        try:
            bot.answer_callback_query(call.id, text=f"⏳ {label}…")
        except Exception:
            pass
        return

    chat_id = call.message.chat.id
    msg_id = call.message.message_id
    is_photo = call.message.content_type == "photo"
    label_safe = esc(label)

    # Cancel any previous animation on this message before starting a
    # new one (defensive — show_menu also cancels on re-render).
    _cancel_loading(chat_id, msg_id)

    # Toast on the button itself.
    try:
        bot.answer_callback_query(call.id, text=f"↻ {label}…")
    except Exception:
        pass

    def _render(pct: int) -> bool:
        """Push the current bar to Telegram. Returns False if the
        message can no longer be edited (deleted, replaced, etc.) so
        the caller can stop the animation early."""
        body = (
            f"<b>↻ {label_safe}…</b>\n"
            f"{G['div']}\n"
            f"<code>{_progress_bar(pct)}</code>\n"
            f"<i>{sc('Please wait')}</i>{FOOTER}"
        )
        try:
            if is_photo:
                bot.edit_message_caption(
                    body, chat_id=chat_id, message_id=msg_id,
                    parse_mode="HTML",
                )
            else:
                bot.edit_message_text(
                    body, chat_id=chat_id, message_id=msg_id,
                    parse_mode="HTML", disable_web_page_preview=True,
                )
            return True
        except ApiTelegramException as e:
            s = str(e).lower()
            if "message is not modified" in s:
                return True
            if "message to edit not found" in s or "message can't be edited" in s:
                return False
            return True
        except Exception:
            return True

    # Initial frame: visible feedback within ~1 telegram round-trip.
    _render(15)

    stop_evt = threading.Event()
    with _LOADING_LOCK:
        _LOADING_STOPS[(chat_id, msg_id)] = stop_evt

    def _animate() -> None:
        # Advance from 15% → ~92% over a few seconds. We never reach
        # 100% on our own — the handler completing and re-rendering is
        # the real "done" signal.
        steps = [25, 38, 52, 65, 78, 88, 92]
        for pct in steps:
            if stop_evt.wait(0.7):
                return
            if not _render(pct):
                return
        # Hold at 92% until cancelled.
        while not stop_evt.wait(1.5):
            pass

    threading.Thread(target=_animate, daemon=True).start()


def admin_only_call(call: types.CallbackQuery, action: str = "view_stats") -> bool:
    if not is_admin(call.from_user.id):
        ack(call, "Owner / admin only.")
        return False
    if not admin_can(call.from_user.id, action):
        ack(call, "Insufficient permission.")
        return False
    return True


_THEME_INDEX_DATA = ""


def maintenance_block(uid: int) -> bool:
    """Return True if user is blocked by maintenance mode."""
    if get_setting("maintenance", False) and not is_admin(uid):
        return True
    return False


def banned_block(call_or_msg: Any) -> bool:
    uid = call_or_msg.from_user.id
    u = db_load_ro()["users"].get(str(uid))
    if u and u.get("banned"):
        try:
            chat = call_or_msg.message.chat.id if hasattr(call_or_msg, "message") else call_or_msg.chat.id
            bot.send_message(
                chat,
                f"<b>{G['no']} {sc('You are banned')}</b>\n"
                f"{bullet('Reason', u.get('ban_reason') or '—')}\n"
                f"Contact {SUPPORT_USR} to appeal.",
            )
        except Exception:
            pass
        return True
    return False


# ═════════════════════════════════════════════════════════════════
# 15.5  HUMAN VERIFICATION  (captcha + animated progress bar)
# ═════════════════════════════════════════════════════════════════
#
# Flow on a brand-new user's first /start:
#   1. an "loading 10% → 100%" progress bar (one message, edited live)
#   2. a CAPTCHA photo: 4 random characters, ONE has a red circle on it
#   3. inline buttons (the 4 chars + 2 distractors, shuffled) — user
#      must tap the *circled* one
#   4. on success → user.verified = True, main menu shown
# After verification the captcha is never shown again for that user.

VERIFY_STATES: Dict[int, Dict[str, Any]] = {}
_verify_lock = threading.Lock()

# Visually unambiguous alphanumeric pool (no I/O/0/1, no Q vs O confusion)
_CAPTCHA_POOL = "ABCDEFGHJKLMNPRSTUVWXYZ23456789"

# Try a few well-known TTF locations; fall back to PIL's default bitmap
_CAPTCHA_FONT_PATHS = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
)


def _captcha_font(size: int):
    if not _PIL_OK:
        return None
    for fp in _CAPTCHA_FONT_PATHS:
        try:
            if os.path.exists(fp):
                return ImageFont.truetype(fp, size)
        except Exception:
            continue
    try:
        return ImageFont.load_default()
    except Exception:
        return None


def _gen_captcha_image() -> Tuple[Optional[bytes], str, List[str]]:
    """Generate captcha PNG bytes + the correct (circled) character +
    the 6 button options (shuffled, includes correct + 3 captcha chars
    + 2 distractors)."""
    text = "".join(random.choice(_CAPTCHA_POOL) for _ in range(4))
    correct_idx = random.randrange(4)
    correct_ch = text[correct_idx]

    options = list(set(text))
    while len(options) < 6:
        c = random.choice(_CAPTCHA_POOL)
        if c not in options:
            options.append(c)
    random.shuffle(options)

    if not _PIL_OK:
        return None, correct_ch, options

    W, H = 720, 320
    bg = (15, 23, 42)  # slate-900
    img = Image.new("RGB", (W, H), bg)
    draw = ImageDraw.Draw(img)

    # background noise — diagonal bands
    for _ in range(10):
        x1, y1 = random.randint(-50, W), random.randint(-50, H)
        x2, y2 = x1 + random.randint(150, 400), y1 + random.randint(-80, 80)
        draw.line([(x1, y1), (x2, y2)],
                  fill=(40, 50, 70), width=random.randint(2, 4))
    # speckle noise
    for _ in range(450):
        x, y = random.randint(0, W - 1), random.randint(0, H - 1)
        v = random.randint(80, 200)
        draw.point((x, y), fill=(v, v, v))

    font = _captcha_font(140)

    # draw each char on its own RGBA tile, rotate, paste
    char_centers: List[Tuple[int, int]] = []
    slot_w = W // 4
    palette = [
        (250, 204, 21),   # amber
        (96, 165, 250),   # blue
        (236, 72, 153),   # pink
        (52, 211, 153),   # green
        (244, 114, 182),  # rose
        (251, 146, 60),   # orange
    ]
    for i, ch in enumerate(text):
        tile = Image.new("RGBA", (200, 240), (0, 0, 0, 0))
        td = ImageDraw.Draw(tile)
        col = random.choice(palette)
        try:
            td.text((30, 30), ch, font=font, fill=col + (255,))
        except Exception:
            td.text((30, 30), ch, fill=col + (255,))
        tile = tile.rotate(random.randint(-22, 22),
                           resample=Image.BILINEAR)
        cx = slot_w * i + slot_w // 2 - 100 + random.randint(-10, 10)
        cy = (H - 240) // 2 + random.randint(-15, 15)
        img.paste(tile, (cx, cy), tile)
        char_centers.append((cx + 100, cy + 120))

    # red circle on the chosen char
    cx, cy = char_centers[correct_idx]
    r = 90
    for dr in range(0, 5):
        draw.ellipse(
            [cx - r - dr, cy - r - dr, cx + r + dr, cy + r + dr],
            outline=(239, 68, 68),
        )

    # bottom hint strip
    hint_font = _captcha_font(28)
    hint = "tap the circled character"
    try:
        bbox = draw.textbbox((0, 0), hint, font=hint_font)
        tw = bbox[2] - bbox[0]
    except Exception:
        tw = len(hint) * 10
    draw.rectangle([0, H - 44, W, H], fill=(30, 41, 59))
    try:
        draw.text(((W - tw) // 2, H - 38), hint,
                  font=hint_font, fill=(226, 232, 240))
    except Exception:
        pass

    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue(), correct_ch, options


def _progress_bar_text(pct: int) -> str:
    pct = max(0, min(100, pct))
    filled = pct // 10
    bar = "▰" * filled + "▱" * (10 - filled)
    return (
        f"<b>{G['shield']} {sc('Verifying you')}…</b>\n"
        f"{G['div']}\n"
        f"<b><code>[{bar}] {pct:3d}%</code></b>"
    )


def _send_progress_then_captcha(chat_id: int, uid: int) -> None:
    """Phase 1: animated progress bar (one message, edited).
       Phase 2: same message edited to 'solve captcha' — no delete."""
    msg_id: Optional[int] = None
    try:
        m = bot.send_message(chat_id, _progress_bar_text(10),
                             parse_mode="HTML")
        msg_id = m.message_id
    except Exception:
        pass

    for pct in (25, 45, 65, 85, 100):
        time.sleep(0.45)
        if msg_id is None:
            break
        try:
            bot.edit_message_text(
                _progress_bar_text(pct), chat_id, msg_id,
                parse_mode="HTML",
            )
        except Exception:
            pass

    # Delete NAHI — edit karo
    if msg_id is not None:
        try:
            bot.edit_message_text(
                f"<b>{G['shield']} {sc('Verification loading')}… {sc('solve captcha below')} ↓</b>",
                chat_id, msg_id,
                parse_mode="HTML",
            )
        except Exception:
            pass

    _send_captcha(chat_id, uid)


def _send_captcha(chat_id: int, uid: int) -> None:
    png, correct, opts = _gen_captcha_image()
    kb = types.InlineKeyboardMarkup()
    btns = [Btn(c, callback_data=f"verify_{c}")
            for c in opts]
    for i in range(0, len(btns), 3):
        kb.row(*btns[i:i + 3])
    kb.row(
        Btn(
            f"{G.get('refresh', '↻')} {sc('New captcha')}",
            callback_data="verify_new",
        )
    )

    cap = (
        f"<b>{G['shield']} {sc('Human verification')}</b>\n"
        f"{G['div']}\n"
        f"{sc('Look at the image above')}.\n"
        f"{sc('One character has a red circle around it')}.\n"
        f"<b>{sc('Tap that exact character below')}.</b>\n"
        f"{G['div']}\n"
        f"{bullet('Tries', '3')}\n"
        f"{bullet('Tip', sc('use New captcha if unreadable'))}"
        f"{FOOTER}"
    )

    sent_id: Optional[int] = None
    try:
        if png is not None:
            m = bot.send_photo(
                chat_id, png, caption=cap,
                parse_mode="HTML", reply_markup=kb,
            )
            sent_id = m.message_id
        else:
            # PIL unavailable — text-only fallback
            text_cap = (
                f"<b>{G['shield']} {sc('Human verification')}</b>\n"
                f"{G['div']}\n"
                f"{sc('Tap this exact character')}: <b><code>{esc(correct)}</code></b>"
                f"{FOOTER}"
            )
            m = bot.send_message(
                chat_id, text_cap, parse_mode="HTML", reply_markup=kb,
            )
            sent_id = m.message_id
    except Exception as e:
        print(f"[verify] send failed: {e}", flush=True)
        return

    with _verify_lock:
        prev = VERIFY_STATES.get(uid) or {}
        VERIFY_STATES[uid] = {
            "answer": correct,
            "options": opts,
            "msg_id": sent_id,
            "chat_id": chat_id,
            "tries": 0,
            # carry regens forward so the regen rate-limit isn't reset
            "regens": int(prev.get("regens", 0)),
            "ts": time.time(),
        }


def _verify_state_janitor() -> None:
    """Drop captcha sessions older than 10 minutes — prevents
    VERIFY_STATES from growing unbounded if users abandon."""
    while True:
        try:
            time.sleep(120)
            cutoff = time.time() - 600
            with _verify_lock:
                stale = [u for u, s in VERIFY_STATES.items()
                         if s.get("ts", 0) < cutoff]
                for u in stale:
                    VERIFY_STATES.pop(u, None)
            if stale:
                print(f"[verify] cleaned {len(stale)} stale captcha state(s)",
                      flush=True)
        except Exception as e:
            print(f"[verify] janitor error: {e}", flush=True)


# ─── Group Join Verification ─────────────────────────────────────
REQUIRED_GROUPS = [
    {"id": -1004291513010, "link": "https://t.me/+5SeRihnZMstjMmM9", "name": "Group 1"},
    {"id": -1004453615236, "link": "https://t.me/+KNfok9dQm5EwYWVl", "name": "Group 2"},
]

def _check_group_membership(uid: int) -> List[Dict]:
    """Returns list of groups the user has NOT joined yet."""
    not_joined = []
    for grp in REQUIRED_GROUPS:
        try:
            member = bot.get_chat_member(grp["id"], uid)
            if member.status in ("left", "kicked", "banned"):
                not_joined.append(grp)
        except Exception:
            not_joined.append(grp)
    return not_joined

def _send_join_verification(chat_id: int, uid: int, not_joined: List[Dict]) -> None:
    """Send group join buttons to user."""
    kb = types.InlineKeyboardMarkup(row_width=2)
    for grp in not_joined:
        kb.add(Btn(
            f"{G['fwd']}  Jᴏɪɴ {grp['name']}", url=grp["link"]))
    kb.add(Btn(
        f"{G['ok']}  Vᴇʀɪꜰɪᴄᴀᴛɪᴏɴ", callback_data="group_verify_check"))
    cap = (
        f"<b>{G['shield']} {sc('Group Join Required')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('You must join the following groups to use this bot')}:\n"
        f"{G['div']}\n"
        + "\n".join(f"{G['bullet']} <a href='{g['link']}'>{esc(g['name'])}</a>" for g in not_joined)
        + f"\n{G['div']}\n"
        f"{sc('After joining, tap')} <b>{sc('Verification')}</b> {sc('below')}."
        f"{FOOTER}"
    )
    try:
        bot.send_message(chat_id, cap, parse_mode="HTML", reply_markup=kb,
                         disable_web_page_preview=True)
    except Exception as e:
        print(f"[group_verify] send failed: {e}", flush=True)

def require_group_membership(chat_id: int, uid: int) -> bool:
    """Returns True if user has joined all required groups.
    Otherwise sends join prompt and returns False."""
    if uid == OWNER_ID and OWNER_ID > 0:
        return True
    if is_admin(uid):
        return True
    not_joined = _check_group_membership(uid)
    if not not_joined:
        return True
    _send_join_verification(chat_id, uid, not_joined)
    return False
# ─────────────────────────────────────────────────────────────────

def _is_verified(uid: int) -> bool:
    if uid == OWNER_ID and OWNER_ID > 0:
        return True
    u = db_load_ro()["users"].get(str(uid)) or {}
    return bool(u.get("verified"))


def _mark_verified(uid: int) -> None:
    db = db_load()
    if str(uid) in db["users"]:
        db["users"][str(uid)]["verified"] = True
        db["users"][str(uid)]["verified_at"] = ts_iso()
        db_save(db)


def require_verified(chat_id: int, uid: int) -> bool:
    """Returns True if the user is already verified.
    Otherwise launches the progress-bar + captcha flow and returns False.
    Callers should `return` immediately on False.

    Anti-spam: if a captcha session is already pending for this user
    (progress bar still animating or buttons still on screen) we silently
    drop the duplicate /start instead of stacking another progress bar."""
    if _is_verified(uid):
        return True
    with _verify_lock:
        st = VERIFY_STATES.get(uid)
        now = time.time()
        # Active session = either started in last 6s (progress bar phase)
        # or has a captcha message id (buttons still up).
        if st and (st.get("msg_id") or now - st.get("ts", 0) < 6):
            return False
        # Reserve the slot so the second /start lands in the branch above.
        VERIFY_STATES[uid] = {
            "answer": "", "options": [], "msg_id": None,
            "chat_id": chat_id, "tries": 0, "regens": 0,
            "ts": now, "starting": True,
        }
    threading.Thread(
        target=_send_progress_then_captcha,
        args=(chat_id, uid),
        daemon=True,
    ).start()
    return False


@bot.callback_query_handler(func=lambda c: c.data == "group_verify_check")
def cb_group_verify(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    chat_id = call.message.chat.id
    not_joined = _check_group_membership(uid)
    if not_joined:
        ack(call, "You have not joined all groups yet!")
        try:
            bot.delete_message(chat_id, call.message.message_id)
        except Exception:
            pass
        _send_join_verification(chat_id, uid, not_joined)
    else:
        ack(call, "✓ Verified! Welcome.")
        try:
            bot.delete_message(chat_id, call.message.message_id)
        except Exception:
            pass
        render_main_menu(chat_id, uid)


@bot.callback_query_handler(func=lambda c: bool(c.data) and c.data.startswith("verify_"))
def cb_verify(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    chat_id = call.message.chat.id
    data = call.data[len("verify_"):]

    # NEW captcha (regen)
    if data == "new":
        with _verify_lock:
            st = VERIFY_STATES.get(uid)
            if st and st.get("regens", 0) >= 5:
                ack(call, "Too many regenerations.")
                return
        try:
            bot.delete_message(chat_id, call.message.message_id)
        except Exception:
            pass
        ack(call, "New captcha…")
        _send_captcha(chat_id, uid)
        with _verify_lock:
            if uid in VERIFY_STATES:
                VERIFY_STATES[uid]["regens"] = (
                    VERIFY_STATES[uid].get("regens", 0) + 1
                )
        return

    with _verify_lock:
        state = VERIFY_STATES.get(uid)

    if not state:
        ack(call, "Session expired — send /start again.")
        return

    if data == state["answer"]:
        with _verify_lock:
            VERIFY_STATES.pop(uid, None)
        _mark_verified(uid)
        ack(call, "✓ Verified")
        try:
            bot.delete_message(chat_id, state["msg_id"])
        except Exception:
            pass
        intro = (
            f"<b>{G['ok']} {sc('Verification complete')}</b> — "
            f"{sc('welcome')}, <b>{esc(call.from_user.first_name or 'friend')}</b>!"
        )
        try:
            audit(uid, "captcha_pass",
                  f"verified after {state.get('tries', 0)} try(s)")
        except Exception:
            pass
        render_main_menu(chat_id, uid, intro=intro)
        return

    # wrong answer
    state["tries"] = state.get("tries", 0) + 1
    left = max(0, 3 - state["tries"])
    if state["tries"] >= 3:
        with _verify_lock:
            VERIFY_STATES.pop(uid, None)
        try:
            bot.delete_message(chat_id, state["msg_id"])
        except Exception:
            pass
        ack(call, "Wrong 3 times — new captcha.")
        _send_captcha(chat_id, uid)
    else:
        ack(call, f"Wrong character. {left} try(s) left.")


# ═════════════════════════════════════════════════════════════════
# 16. /start  AND  MAIN MENU
# ═════════════════════════════════════════════════════════════════

def render_main_menu(chat_id: int, uid: int,
                     call: Optional[types.CallbackQuery] = None,
                     intro: Optional[str] = None) -> None:
    u = db_load()["users"].get(str(uid)) or {}
    plan = PLAN_LIMITS.get(u.get("plan", "free"), PLAN_LIMITS["free"])
    bots = list_user_bots(uid)
    running = sum(1 for b in bots if b.get("status") == "running")
    intro_block = f"{intro}\n{G['div']}\n" if intro else ""
    cap = (
        f"<b>{esc(BRAND)} {esc(BRAND_VER)}</b>\n"
        f"{G['div_eq']}\n"
        f"{intro_block}"
        f"<b>{sc('Welcome')}</b>, {esc(u.get('name') or 'friend')}\n"
        f"{bullet('Plan',  plan['name'])}\n"
        f"{bullet('Until', fmt_ts(u.get('plan_expires')) if u.get('plan_expires') else 'Forever' if plan['price'] == 0 else '—')}\n"
        f"{bullet('Bots',  f'{len(bots)} / {user_max_bots(u)}  (running {running})')}\n"
        f"{bullet('Wallet', '{}$'.format(u.get('wallet', 0)))}\n"
        f"{G['div']}\n"
        f"Choose an option below.{FOOTER}"
    )
    show_start_menu(chat_id, cap, main_menu_kb(is_admin(uid)), call=call,
                    photo_fallback=PHOTOS.get("main", ""))


# ─── Silent mode in groups — bot will not respond in any group/channel ───────
def _is_private(m) -> bool:
    """Returns True only for private chats."""
    try:
        return m.chat.type == "private"
    except Exception:
        return True
# ─────────────────────────────────────────────────────────────────────────────

@bot.message_handler(commands=["start"])
def cmd_start(m: types.Message) -> None:
    if not _is_private(m):
        return  # silent in groups
    uid = m.from_user.id
    if not RATE.allow(uid):
        maybe_auto_ban(uid, "rate")
        return
    if banned_block(m):
        return
    # ── auto-claim ownership: first /start with no OWNER_ID env wins ──
    global OWNER_ID
    if OWNER_ID <= 0:
        stored = int(get_setting("owner_id", 0) or 0)
        if stored > 0:
            OWNER_ID = stored
        else:
            OWNER_ID = uid
            set_setting("owner_id", uid)
            audit(uid, "owner_claim", f"first /start, uid={uid}")
            try:
                bot.send_message(
                    m.chat.id,
                    f"<b>{G['crown']} {sc('You are now the panel owner')}</b>\n"
                    f"{G['div']}\n"
                    f"{bullet('Owner ID', uid)}\n"
                    f"{sc('Set OWNER_ID env var to lock ownership permanently')}.",
                    parse_mode="HTML",
                )
            except Exception:
                pass
    ref: Optional[int] = None
    parts = (m.text or "").split(maxsplit=1)
    if len(parts) == 2 and parts[1].isdigit():
        ref = int(parts[1])
    u, is_new = get_or_create_user(m.from_user, ref=ref)
    if maintenance_block(uid):
        bot.send_message(
            m.chat.id,
            f"<b>{G['warn']} {sc('Panel under maintenance')}</b>\n\n"
            f"We will be back shortly. {SUPPORT_USR} for urgent issues.",
        )
        return
    # Human verification — first /start ever for this user shows a
    # progress bar (10% → 100%) followed by a captcha photo. Once the
    # captcha is solved, render_main_menu is called from cb_verify.
    if not require_verified(m.chat.id, uid):
        return

    # Group join verification — user must join required groups
    if not require_group_membership(m.chat.id, uid):
        return

    # Single message: welcome line is folded into the main-menu caption,
    # so /start always sends exactly ONE photo + menu.
    intro = (
        f"{sc('You are now registered')}. "
        f"Tap <b>{sc('Plans')}</b> or <b>{sc('Upload Bot')}</b> to begin."
        if is_new else
        f"{sc('Welcome back')}, <b>{esc(m.from_user.first_name or 'friend')}</b>!"
    )
    render_main_menu(m.chat.id, uid, intro=intro)


@bot.message_handler(commands=["help"])
def cmd_help(m: types.Message) -> None:
    if not _is_private(m):
        return
    if banned_block(m):
        return
    if not require_verified(m.chat.id, m.from_user.id):
        return
    txt = (
        f"<b>{esc(BRAND_TAG)} — {sc('Quick Help')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Upload',  'Send a .py / .js / .zip file or use Upload Bot menu.')}\n"
        f"{bullet('Manage',  'My Bots → pick a bot → Start / Stop / Logs.')}\n"
        f"{bullet('Plans',   'Plans → Buy Plan → choose method → send proof.')}\n"
        f"{bullet('Wallet',  'Top-up via admin, then spend on plans.')}\n"
        f"{bullet('Refer',   'Invite friends with your /start link to earn slots.')}\n"
        f"{bullet('Trial',   'One-time 48-hour Pro trial in the Trial menu.')}\n"
        f"{bullet('Support', f'Open a ticket from the Tickets menu, or DM {SUPPORT_USR}.')}\n"
        f"{G['div']}{FOOTER}"
    )
    bot.send_message(m.chat.id, txt, parse_mode="HTML",
                     reply_markup=back_main_kb(), disable_web_page_preview=True)


@bot.message_handler(commands=["menu"])
def cmd_menu(m: types.Message) -> None:
    if not _is_private(m):
        return
    if banned_block(m):
        return
    get_or_create_user(m.from_user)
    if not require_verified(m.chat.id, m.from_user.id):
        return
    render_main_menu(m.chat.id, m.from_user.id)


@bot.message_handler(commands=["id"])
def cmd_id(m: types.Message) -> None:
    if not _is_private(m):
        return
    bot.reply_to(m, f"<code>{m.from_user.id}</code>")


@bot.message_handler(commands=["cancel"])
def cmd_cancel(m: types.Message) -> None:
    if not _is_private(m):
        return
    USER_STATES.pop(m.from_user.id, None)
    bot.reply_to(m, f"{G['ok']} {sc('Cancelled')}")


# ═════════════════════════════════════════════════════════════════
# 17. CALLBACK ROUTER  (top level)
# ═════════════════════════════════════════════════════════════════

# ─── callback de-duplication ─────────────────────────────────────
# Telegram occasionally re-delivers the same callback (rapid double-clicks,
# leftover webhook still active alongside polling, two bot instances polling
# the same token, etc.). We keep a tiny in-memory cache of recently-seen
# callback IDs and silently drop duplicates so the user only ever sees a
# single response per button press.
_CB_SEEN: "deque[Tuple[str, float]]" = deque(maxlen=512)
_CB_SEEN_LOCK = threading.Lock()
_CB_DEDUP_WINDOW = 12.0  # seconds


def _is_duplicate_callback(call_id: str) -> bool:
    if not call_id:
        return False
    now = time.time()
    with _CB_SEEN_LOCK:
        # purge expired entries
        while _CB_SEEN and now - _CB_SEEN[0][1] > _CB_DEDUP_WINDOW:
            _CB_SEEN.popleft()
        for cid, _ in _CB_SEEN:
            if cid == call_id:
                return True
        _CB_SEEN.append((call_id, now))
    return False


@bot.callback_query_handler(func=lambda c: True)
def cb_root(call: types.CallbackQuery) -> None:
    # silently drop duplicate deliveries of the same callback
    if _is_duplicate_callback(getattr(call, "id", "")):
        try:
            bot.answer_callback_query(call.id)
        except Exception:
            pass
        return

    uid = call.from_user.id
    if not RATE.allow(uid):
        ack(call, "Slow down.")
        maybe_auto_ban(uid, "callback rate")
        return
    if banned_block(call):
        ack(call)
        return
    get_or_create_user(call.from_user)
    if maintenance_block(uid):
        ack(call, "Maintenance mode")
        return
    # Block menu navigation for unverified users — they must solve the
    # captcha first. The verify_* callbacks are handled by an earlier
    # registered handler so they bypass this gate.
    if not _is_verified(uid):
        ack(call, "Please solve the captcha first — send /start.")
        return
    data = call.data or ""
    try:
        _route_callback(call, data)
    except Exception as e:
        traceback.print_exc()
        try:
            bot.send_message(call.message.chat.id, f"<b>{G['no']}</b> Eʀʀᴏʀ: <code>{esc(e)}</code>")
        except Exception:
            pass


def _route_callback(call: types.CallbackQuery, data: str) -> None:
    # ─── core menu navigation ──────────────────────────────────
    if data == "menu_main":
        ack(call); render_main_menu(call.message.chat.id, call.from_user.id, call); return
    if data == "menu_bots":
        ack(call); render_bots_menu(call); return
    if data == "menu_upload":
        ack(call); render_upload_menu(call); return
    if data == "menu_plans":
        ack(call); render_plans_menu(call); return
    if data == "menu_buy":
        ack(call); render_buy_menu(call); return
    if data == "menu_profile":
        ack(call); render_profile(call); return
    if data == "menu_referral":
        ack(call); render_referral(call); return
    if data == "menu_wallet":
        ack(call); render_wallet(call); return
    if data == "menu_help":
        ack(call); render_help(call); return
    if data == "menu_support":
        ack(call); render_support(call); return
    if data == "menu_tickets":
        ack(call); render_user_tickets(call); return
    if data == "menu_trial":
        ack(call); render_trial(call); return
    if data == "menu_coupon":
        ack(call); render_coupon(call); return
    if data == "menu_stats":
        ack(call); render_user_stats(call); return
    if data == "menu_admin":
        ack(call); render_admin(call); return

    # ─── plan view + buy ───────────────────────────────────────
    if data.startswith("plan_view_"):
        ack(call); render_plan_detail(call, data.split("_", 2)[2]); return
    if data.startswith("plan_buy_"):
        ack(call); render_payment_methods_for(call, data.split("_", 2)[2]); return

    # ─── pay methods ───────────────────────────────────────────
    if data.startswith("pay_"):
        ack(call); render_payment_screen(call, data); return
    if data == "pay_proof":
        ack(call); start_proof_flow(call); return

    # ─── bot actions ───────────────────────────────────────────
    if data.startswith("bot_view_"):
        ack(call); render_bot_view(call, data.split("_", 2)[2]); return
    if data.startswith("bot_start_"):
        ack(call); action_bot_start(call, data.split("_", 2)[2]); return
    if data.startswith("bot_stop_"):
        ack(call); action_bot_stop(call, data.split("_", 2)[2]); return
    if data.startswith("bot_restart_"):
        ack(call); action_bot_restart(call, data.split("_", 2)[2]); return
    if data.startswith("bot_logs_"):
        ack(call); action_bot_logs(call, data.split("_", 2)[2]); return
    if data.startswith("bot_info_"):
        ack(call); action_bot_info(call, data.split("_", 2)[2]); return
    if data.startswith("bot_env_"):
        ack(call); render_env_menu(call, data.split("_", 2)[2]); return
    if data.startswith("env_add_"):
        ack(call); start_env_add(call, data.split("_", 2)[2]); return
    if data.startswith("env_del_"):
        parts = data.split("_", 3)
        if len(parts) >= 4:
            ack(call); action_env_delete(call, parts[2], parts[3]); return
    if data.startswith("bot_cron_"):
        ack(call); render_cron(call, data.split("_", 2)[2]); return
    if data.startswith("bot_clone_"):
        ack(call); action_bot_clone(call, data.split("_", 2)[2]); return
    if data.startswith("bot_dl_"):
        ack(call); action_bot_download(call, data.split("_", 2)[2]); return
    if data.startswith("bot_pip_"):
        ack(call); start_pip_install_flow(call, data.split("_", 2)[2]); return
    if data.startswith("bot_tunnel_"):
        ack(call); start_tunnel_flow(call, data.split("_", 2)[2]); return
    if data.startswith("bot_delete_"):
        ack(call); render_bot_delete_confirm(call, data.split("_", 2)[2]); return
    if data.startswith("bot_delyes_"):
        ack(call); action_bot_delete(call, data.split("_", 2)[2]); return
    if data.startswith("bot_delfiles_"):
        ack(call); render_bot_delfiles_confirm(call, data.split("_", 2)[2]); return
    if data.startswith("bot_delall_"):
        ack(call); render_bot_delall_confirm(call, data.split("_", 2)[2]); return
    if data.startswith("bot_delfilesyes_"):
        ack(call); action_bot_delfiles(call, data.split("_", 2)[2]); return
    if data.startswith("bot_delalyes_"):
        ack(call); action_bot_delall(call, data.split("_", 2)[2]); return

    # ─── approval system (admin only) ──────────────────────────
    if data.startswith("appr_ok_"):
        if not admin_only_call(call, "approve_payment"):
            return
        bid = data[len("appr_ok_"):]
        res = approve_bot(bid, call.from_user.id)
        ack(call, "Approved" if res.get("ok") else f"Err: {res.get('error')}")
        try:
            bot.edit_message_reply_markup(call.message.chat.id,
                                          call.message.message_id, reply_markup=None)
        except Exception:
            pass
        try:
            bot.send_message(
                call.message.chat.id,
                f"<b>{G['ok']} {sc('Bot approved')}</b>\n"
                f"{bullet('Bot ID', bid)}",
                parse_mode="HTML",
            )
        except Exception:
            pass
        return
    if data.startswith("appr_no_"):
        if not admin_only_call(call, "approve_payment"):
            return
        bid = data[len("appr_no_"):]
        res = reject_bot(bid, call.from_user.id, reason="rejected by admin")
        ack(call, "Rejected" if res.get("ok") else f"Err: {res.get('error')}")
        try:
            bot.edit_message_reply_markup(call.message.chat.id,
                                          call.message.message_id, reply_markup=None)
        except Exception:
            pass
        try:
            bot.send_message(
                call.message.chat.id,
                f"<b>{G['no']} {sc('Bot rejected')}</b>\n"
                f"{bullet('Bot ID', bid)}",
                parse_mode="HTML",
            )
        except Exception:
            pass
        return

    # ─── admin sub-actions ─────────────────────────────────────
    if data.startswith("adm_"):
        if not admin_only_call(call, "view_stats"):
            return
        ack(call); render_admin_subroute(call, data); return
    if data.startswith("gh_"):
        if not admin_only_call(call, "view_stats"):
            return
        ack(call); render_github_subroute(call, data); return

    # ─── trial ────────────────────────────────────────────────
    if data == "trial_claim":
        ack(call); action_trial_claim(call); return

    # ─── coupon redeem ─────────────────────────────────────────
    if data == "coupon_redeem":
        ack(call); start_coupon_flow(call); return

    # ─── tickets ──────────────────────────────────────────────
    if data == "ticket_open":
        ack(call); start_ticket_flow(call); return
    if data.startswith("ticket_view_"):
        ack(call); render_ticket_view(call, data.split("_", 2)[2]); return
    if data.startswith("ticket_close_"):
        ack(call); action_ticket_close(call, data.split("_", 2)[2]); return
    if data.startswith("ticket_reply_"):
        ack(call); start_ticket_reply(call, data.split("_", 2)[2]); return

    # ─── wallet top-up request ────────────────────────────────
    if data == "wallet_topup":
        ack(call); start_wallet_topup(call); return
    if data == "wallet_gift":
        ack(call); start_wallet_gift(call); return

    # ─── admin payment approve/reject ─────────────────────────
    if data.startswith("payapprove_"):
        ack(call); action_payment_approve(call, data.split("_", 1)[1]); return
    if data.startswith("payreject_"):
        ack(call); action_payment_reject(call, data.split("_", 1)[1]); return

    # ─── unknown ──────────────────────────────────────────────
    ack(call, "?")


# ═════════════════════════════════════════════════════════════════
# 18. MENU RENDERS
# ═════════════════════════════════════════════════════════════════

def render_bots_menu(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    bots = list_user_bots(uid)
    u = db_load()["users"][str(uid)]
    cap = (
        f"<b>{G['diamond']} {sc('Your Bots')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Slots', f'{len(bots)} / {user_max_bots(u)}')}\n"
    )
    kb = types.InlineKeyboardMarkup()
    if not bots:
        cap += f"\n{sc('You have not deployed any bots yet')}.\n{sc('Tap upload bot to begin')}."
    else:
        for b in sorted(bots, key=lambda x: x.get("name", "")):
            running = b.get("status") == "running"
            mark = G["play"] if running else G["stop"]
            kb.add(Btn(
                f"{mark}  {sc(b['name'])[:30]}",
                callback_data=f"bot_view_{b['_id']}"))
    kb.add(
        Btn(f"{G['plus']}  {sc('Upload')}",   callback_data="menu_upload", style="success"),
        Btn(f"{G['back']}  {sc('Main Menu')}", callback_data="menu_main", style="primary"),
    )
    show_menu(call.message.chat.id, PHOTOS["bots"], cap + FOOTER, kb, call=call)


def render_upload_menu(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    u = db_load()["users"][str(uid)]
    used = len(list_user_bots(uid))
    cap = (
        f"<b>{G['plus']} {sc('Upload Bot')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Plan',  PLAN_LIMITS[u['plan']]['name'])}\n"
        f"{bullet('Slots', f'{used} / {user_max_bots(u)}')}\n"
        f"{G['div']}\n"
        f"<b>{sc('Send your bot file as a document')}.</b>\n"
        f"Accepted: <code>.zip  .py  .js</code>\n"
        f"Entry detection: <code>bot.py</code>, <code>main.py</code>, "
        f"<code>app.py</code>, <code>index.js</code>, <code>bot.js</code>.\n"
        f"All files are <b>encrypted at rest</b> with Fernet/AES-128 — keys live in our private key vault."
    )
    USER_STATES[uid] = {"flow": "await_upload"}
    show_menu(call.message.chat.id, PHOTOS["upload"], cap + FOOTER,
              back_main_kb(), call=call)


def render_plans_menu(call: types.CallbackQuery) -> None:
    lines = []
    for v in PLAN_LIMITS.values():
        price_txt = "Free" if v["price"] == 0 else f"{v['price']}\u09F3"
        detail = f"{v['max_bots']} bots {G['bullet']} {v['ram']} MB RAM {G['bullet']} {price_txt}"
        lines.append(bullet(v['name'], detail))
    cap = (
        f"<b>{G['star']} {sc('Plans')}</b>\n"
        f"{G['div_eq']}\n"
        + "\n".join(lines)
        + f"\n{G['div']}\nTap a plan for full details.{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["plans"], cap, plans_kb(), call=call)


def render_plan_detail(call: types.CallbackQuery, plan: str) -> None:
    p = PLAN_LIMITS.get(plan)
    if not p:
        ack(call, "Unknown plan"); return
    cap = (
        f"<b>{G['star']} {esc(p['name'])} {sc('Plan')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Max bots',     p['max_bots'])}\n"
        f"{bullet('RAM per bot',  '{} MB'.format(p['ram']))}\n"
        f"{bullet('Auto-restart', 'Yes' if p['auto_restart'] else 'No')}\n"
        f"{bullet('Duration',     'Lifetime' if plan == 'lifetime' else '{} days'.format(p['days']))}\n"
        f"{bullet('Price',        'Free' if p['price'] == 0 else '{}$'.format(p['price']))}\n"
        f"{G['div']}\n"
        f"{sc('Tap buy to choose a payment method')}.{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup()
    if plan != "free":
        kb.add(Btn(
            f"{G['spark']}  {sc('Buy')} {p['name']}",
            callback_data=f"plan_buy_{plan}"))
    kb.add(Btn(
        f"{G['back']}  {sc('Plans')}", callback_data="menu_plans"))
    show_menu(call.message.chat.id, PHOTOS["buy"], cap, kb, call=call)


def render_buy_menu(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>{G['spark']} {sc('Buy a Plan')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Pick a plan first')}.{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["buy"], cap, plans_kb(), call=call)


def render_payment_methods_for(call: types.CallbackQuery, plan: str) -> None:
    p = PLAN_LIMITS.get(plan)
    if not p:
        ack(call, "Unknown plan"); return
    cap = (
        f"<b>{G['wallet']} {sc('Choose Payment Method')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Plan',  p['name'])}\n"
        f"{bullet('Price', '{}$'.format(p['price']))}\n"
        f"{G['div']}\n"
        f"{sc('Pick the method you will pay with')}.{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["pay"], cap, payments_kb(plan), call=call)


def render_payment_screen(call: types.CallbackQuery, data: str) -> None:
    # data is pay_<method> or pay_<method>_<plan>
    parts = data.split("_")
    method = parts[1]
    plan = parts[2] if len(parts) >= 3 else None
    pm = PAYMENT_METHODS.get(method)
    if not pm:
        ack(call, "Unknown method"); return
    p = PLAN_LIMITS.get(plan or "")
    cap = (
        f"<b>{pm['tag']} {esc(pm['name'])} — {sc('Payment')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Number', pm['number'])}\n"
        f"{bullet('Type',   pm['type'])}\n"
    )
    if p:
        cap += f"{bullet('Plan', p['name'])}\n{bullet('Amount', '{}$'.format(p['price']))}\n"
    cap += (
        f"{G['div']}\n"
        f"<b>{sc('How to pay')}:</b>\n"
        f"1. {sc('Send the exact amount to the number above')}.\n"
        f"2. {sc('Tap send proof and forward your receipt screenshot')}.\n"
        f"3. {sc('Wait for admin approval')} ({sc('usually within 1 hour')}).\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup()
    USER_STATES[call.from_user.id] = {
        "flow": "await_payment_proof", "method": method, "plan": plan,
    }
    kb.add(Btn(
        f"{G['plus']}  {sc('Send Proof')}", callback_data="pay_proof"))
    kb.add(Btn(
        f"{G['back']}  {sc('Methods')}",
        callback_data=f"plan_buy_{plan}" if plan else "menu_buy"))
    show_menu(call.message.chat.id, PHOTOS["pay"], cap, kb, call=call)


def start_proof_flow(call: types.CallbackQuery) -> None:
    st = USER_STATES.get(call.from_user.id) or {}
    if st.get("flow") != "await_payment_proof":
        st = {"flow": "await_payment_proof"}
        USER_STATES[call.from_user.id] = st
    bot.send_message(
        call.message.chat.id,
        f"{G['plus']} {sc('Send your payment screenshot or transaction id text now')}.\n"
        f"{sc('Use')} /cancel {sc('to abort')}.",
    )


def render_profile(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    u = db_load()["users"][str(uid)]
    p = PLAN_LIMITS.get(u["plan"], PLAN_LIMITS["free"])
    bots = list_user_bots(uid)
    cap = (
        f"<b>{G['user']} {sc('Profile')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Name',     u.get('name'))}\n"
        f"{bullet('Username', '@' + (u.get('username') or '—'))}\n"
        f"{bullet('User ID',  uid)}\n"
        f"{bullet('Plan',     p['name'])}\n"
        f"{bullet('Until',    fmt_ts(u.get('plan_expires')) if u.get('plan_expires') else ('Forever' if p['price'] == 0 else '—'))}\n"
        f"{bullet('Wallet',   '{}$'.format(u.get('wallet', 0)))}\n"
        f"{bullet('Bots',     f'{len(bots)} / {user_max_bots(u)}')}\n"
        f"{bullet('Joined',   fmt_ts(u.get('joined')))}\n"
        f"{bullet('KYC',      'Verified' if u.get('kyc') else 'No')}\n"
        f"{bullet('Referrals', u.get('ref_count', 0))}\n"
        f"{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["profile"], cap, back_main_kb(), call=call)


def render_referral(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    u = db_load()["users"][str(uid)]
    me = bot.get_me()
    link = f"https://t.me/{me.username}?start={uid}"
    cap = (
        f"<b>{G['users']} {sc('Referral')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Your link', link)}\n"
        f"{bullet('Referrals', u.get('ref_count', 0))}\n"
        f"{bullet('Bonus slots', u.get('bot_slots_bonus', 0))}\n"
        f"{G['div']}\n"
        f"{sc('Each friend who joins via your link gives you')} +1 {sc('bot slot and')} +1\u09F3 {sc('credit')}.\n"
        f"{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["referral"], cap, back_main_kb(), call=call)


def render_wallet(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    u = db_load()["users"][str(uid)]
    cap = (
        f"<b>{G['wallet']} {sc('Wallet')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Balance', '{}$'.format(u.get('wallet', 0)))}\n"
        f"{G['div']}\n"
        f"{sc('Top up by sending payment proof. Admin will credit your wallet')}.\n"
        f"{sc('You can also gift your active plan to another user')}.{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup()
    kb.add(Btn(
        f"{G['plus']}  {sc('Top Up')}", callback_data="wallet_topup"))
    if u.get("plan") not in ("free",):
        kb.add(Btn(
            f"{G['spark']}  {sc('Gift Plan')}", callback_data="wallet_gift"))
    kb.add(Btn(
        f"{G['back']}  {sc('Main Menu')}", callback_data="menu_main"))
    show_menu(call.message.chat.id, PHOTOS["wallet"], cap, kb, call=call)


def render_help(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>{G['rec']} {sc('Help')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Upload',  'Send a .py / .js / .zip file')}\n"
        f"{bullet('Run',     'My Bots → pick → Start')}\n"
        f"{bullet('Logs',    'My Bots → pick → Live Logs')}\n"
        f"{bullet('Env',     'My Bots → pick → Env Vars')}\n"
        f"{bullet('Plans',   'Plans → Buy Plan → method')}\n"
        f"{bullet('Coupon',  'Coupon menu → Redeem')}\n"
        f"{bullet('Trial',   'One-time 48h Pro trial')}\n"
        f"{bullet('Refer',   'Earn slots by inviting friends')}\n"
        f"{bullet('Tickets', 'Open a private support ticket')}\n"
        f"{G['div']}\n"
        f"Updates channel: {UPDATE_CH}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["help"], cap, back_main_kb(), call=call)


def render_support(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>{G['broadcast']} {sc('Support')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('DM',      SUPPORT_USR)}\n"
        f"{bullet('Channel', UPDATE_CH)}\n"
        f"{G['div']}\n"
        f"{sc('Or open a ticket from the Tickets menu for tracked help')}.{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["support"], cap, back_main_kb(), call=call)


def render_trial(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    u = db_load()["users"][str(uid)]
    cap = (
        f"<b>{G['eye']} {sc('Free Trial')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Get a free 48-hour Pro trial — one time per account')}.\n"
        f"{bullet('Status', 'Already used' if u.get('trial_used') else 'Available')}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup()
    if not u.get("trial_used"):
        kb.add(Btn(
            f"{G['ok']}  {sc('Claim 48h Pro Trial')}", callback_data="trial_claim"))
    kb.add(Btn(
        f"{G['back']}  {sc('Main Menu')}", callback_data="menu_main"))
    show_menu(call.message.chat.id, PHOTOS["trial"], cap, kb, call=call)


def action_trial_claim(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    d = db_load()
    u = d["users"][str(uid)]
    if u.get("trial_used"):
        ack(call, "Already used"); return
    u["trial_used"] = True
    db_save(d)
    grant_plan(uid, "pro", days=2)
    audit(0, "trial_grant", f"uid={uid}")
    ack(call, "Trial activated")
    render_main_menu(call.message.chat.id, uid, call)


def render_coupon(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>{G['key']} {sc('Coupon')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Have a discount code? Tap redeem and send the code')}.{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup()
    kb.add(Btn(
        f"{G['plus']}  {sc('Redeem Code')}", callback_data="coupon_redeem"))
    kb.add(Btn(
        f"{G['back']}  {sc('Main Menu')}", callback_data="menu_main"))
    show_menu(call.message.chat.id, PHOTOS["coupon"], cap, kb, call=call)


def render_user_stats(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    d = db_load()
    u = d["users"][str(uid)]
    p = PLAN_LIMITS.get(u.get("plan", "free"), PLAN_LIMITS["free"])
    bots = list_user_bots(uid)
    running = sum(1 for b in bots if b.get("status") == "running")
    stopped = len(bots) - running

    # payments
    pays = [x for x in d.get("payments", []) if x.get("uid") == uid and x.get("status") == "approved"]
    last_pay = max((x.get("at", "") for x in pays), default=None)

    # tickets
    tickets = d.get("tickets", {})
    my_tickets = [t for t in tickets.values() if t.get("uid") == uid]
    open_tickets   = sum(1 for t in my_tickets if t.get("status") == "open")
    closed_tickets = sum(1 for t in my_tickets if t.get("status") != "open")

    # storage
    storage_size = 0
    for b in bots:
        bot_dir = BASE_DIR / "storage" / "uploads" / str(b["_id"])
        if bot_dir.exists():
            for root, _, files in os.walk(bot_dir):
                for f in files:
                    try:
                        storage_size += (Path(root) / f).stat().st_size
                    except OSError:
                        pass

    plan_expires = u.get("plan_expires")
    if plan_expires:
        expires_txt = fmt_ts(plan_expires)
    elif p["price"] == 0:
        expires_txt = "Forever"
    else:
        expires_txt = "—"

    cap = (
        f"<b>{G['graph']} {sc('My Stats')}</b>\n"
        f"{G['div_eq']}\n"
        f"<b>{sc('Account')}</b>\n"
        f"{bullet('Name',       u.get('name', '—'))}\n"
        f"{bullet('User ID',    uid)}\n"
        f"{bullet('Joined',     fmt_ts(u.get('joined')))}\n"
        f"{bullet('KYC',        'Verified' if u.get('kyc') else 'No')}\n"
        f"{G['div']}\n"
        f"<b>{sc('Plan')}</b>\n"
        f"{bullet('Current Plan',  p['name'])}\n"
        f"{bullet('Plan Expires',  expires_txt)}\n"
        f"{bullet('RAM Limit',     str(p['ram']) + ' MB')}\n"
        f"{bullet('Auto Restart',  'Yes' if p['auto_restart'] else 'No')}\n"
        f"{G['div']}\n"
        f"<b>{sc('Bots')}</b>\n"
        f"{bullet('Total Bots',    len(bots))}\n"
        f"{bullet('Running',       running)}\n"
        f"{bullet('Stopped',       stopped)}\n"
        f"{bullet('Slots Used',    str(len(bots)) + ' / ' + str(user_max_bots(u)))}\n"
        f"{bullet('Storage Used',  fmt_bytes(storage_size))}\n"
        f"{G['div']}\n"
        f"<b>{sc('Payments')}</b>\n"
        f"{bullet('Total Payments', len(pays))}\n"
        f"{bullet('Last Payment',   fmt_ts(last_pay) if last_pay else '—')}\n"
        f"{bullet('Wallet Balance', '{}$'.format(u.get('wallet', 0)))}\n"
        f"{G['div']}\n"
        f"<b>{sc('Other')}</b>\n"
        f"{bullet('Referrals',     u.get('ref_count', 0))}\n"
        f"{bullet('Bonus Slots',   u.get('bot_slots_bonus', 0))}\n"
        f"{bullet('Free Trial',    'Used' if u.get('trial_used') else 'Available')}\n"
        f"{bullet('Open Tickets',  open_tickets)}\n"
        f"{bullet('Closed Tickets', closed_tickets)}\n"
        f"{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["stats"], cap, back_main_kb(), call=call)


def start_coupon_flow(call: types.CallbackQuery) -> None:
    USER_STATES[call.from_user.id] = {"flow": "await_coupon"}
    bot.send_message(
        call.message.chat.id,
        f"{G['key']} {sc('Send your coupon code')} (Tᴇxᴛ Oɴʟʏ). /cancel {sc('to abort')}.",
    )


def start_wallet_topup(call: types.CallbackQuery) -> None:
    USER_STATES[call.from_user.id] = {"flow": "await_topup_proof"}
    bot.send_message(
        call.message.chat.id,
        f"{G['plus']} {sc('Send a screenshot of your top-up payment')}.\n"
        f"{sc('Include the amount in the caption')}, e.g.  <code>200</code>.",
        parse_mode="HTML",
    )


def start_wallet_gift(call: types.CallbackQuery) -> None:
    USER_STATES[call.from_user.id] = {"flow": "await_gift_target"}
    bot.send_message(
        call.message.chat.id,
        f"{G['spark']} {sc('Send the user id of the person you want to gift your plan to')}.",
    )


# ═════════════════════════════════════════════════════════════════
# 19. BOT MANAGEMENT VIEWS
# ═════════════════════════════════════════════════════════════════

def render_bot_view(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    if b["owner"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    st = child_status(bot_id, b)
    # surface the most recent crash if the bot is stopped
    err_block = ""
    if not st["running"]:
        rc = b.get("last_exit_code")
        last_err = (b.get("last_error") or "").strip()
        if last_err or (rc not in (None, 0)):
            head = f"{G['no']} {sc('Last error')}"
            if rc not in (None, 0):
                head += f"  (exit {rc})"
            err_block = (
                f"\n{G['div']}\n"
                f"<b>{head}</b>\n"
                f"<pre>{esc(last_err or '(no log captured)')[:900]}</pre>"
            )
    appr = (b.get("approval_status") or "").lower()
    if appr == "pending":
        status_lbl = "Pending approval"
    elif appr == "rejected":
        status_lbl = "Rejected"
    elif st["running"]:
        status_lbl = "Running"
    elif b.get("status") == "crashed":
        status_lbl = "Crashed"
    else:
        status_lbl = "Stopped"
    cap = (
        f"<b>{G['diamond']} {esc(b['name'])}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Status',  status_lbl)}\n"
        f"{bullet('Kind',    st['kind'] or '—')}\n"
        f"{bullet('PID',     '••••' if st['pid'] else '—')}\n"
        f"{bullet('Uptime',  fmt_dur(st['uptimeMs']))}\n"
        f"{bullet('Size',    fmt_bytes(st['sizeBytes']))}\n"
        f"{bullet('CPU',     '{:.1f}%'.format(st['cpuPct']))}\n"
        f"{bullet('Memory',  fmt_bytes(st['memBytes']))}\n"
        f"{bullet('Created', fmt_ts(b.get('created')))}"
        f"{err_block}\n"
        f"{G['div']}{FOOTER}"
    )
    owner_doc = db_load()["users"].get(str(b["owner"])) or {}
    is_premium = owner_doc.get("plan", "free") != "free" and user_plan_active(owner_doc)
    # Surface the active tunnel URL in the caption when one is open
    tun = TUNNELS.get(bot_id)
    if tun and tun.get("proc") and tun["proc"].poll() is None and tun.get("url"):
        cap = (
            cap[: -len(FOOTER)]
            + f"\n{G['div']}\n"
            + f"{bullet('Public URL', tun['url'])}\n"
            + f"{bullet('Port',       tun.get('port', '—'))}"
            + FOOTER
        )
    show_menu(call.message.chat.id, PHOTOS["bot"], cap,
              bot_actions_kb(bot_id, st["running"], premium=is_premium), call=call)


def action_bot_start(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    if b["owner"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    loading(call, "Starting bot")
    res = start_child(b)
    ack(call, "Started" if res["ok"] else f"Err: {res.get('error')}")
    render_bot_view(call, bot_id)


def action_bot_stop(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    if b["owner"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    loading(call, "Stopping bot")
    stop_child(bot_id, manual=True)
    ack(call, "Stopped")
    render_bot_view(call, bot_id)


def action_bot_restart(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    if b["owner"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    loading(call, "Restarting bot")
    res = restart_child(b)
    ack(call, "Restarted" if res["ok"] else f"Err: {res.get('error')}")
    render_bot_view(call, bot_id)


def action_bot_logs(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    if b["owner"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    ack(call, "Fetching logs…")
    logs = tail_log(bot_id, lines=60)
    if not logs:
        logs = "(no output yet)"
    txt = (
        f"<b>{G['bolt']} {sc('Live Logs')} — {esc(b['name'])}</b>\n"
        f"{G['div_eq']}\n<pre>"
        + esc(logs[-3500:])
        + f"</pre>\n{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(
        Btn(
            f"{G['refresh']}  {sc('Refresh Logs')}",
            callback_data=f"bot_logs_{bot_id}",
        ),
        Btn(
            f"{G['back']}  {sc('Back')}",
            callback_data=f"bot_view_{bot_id}",
        ),
    )
    show_text(call.message.chat.id, txt, kb, call=call)


def action_bot_info(call: types.CallbackQuery, bot_id: str) -> None:
    render_bot_view(call, bot_id)


def render_bot_delete_confirm(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    if b["owner"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    cap = (
        f"<b>{G['no']} {sc('Delete Bot')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Bot', b['name'])}\n\n"
        f"{G['warn']}  <b>{sc('Choose delete type')}:</b>\n\n"
        f"{G['bullet']} <b>{sc('Delete Bot Files')}</b> — {sc('removes files and keys only')}\n"
        f"{G['bullet']} <b>{sc('Delete All Data')}</b> — {sc('removes files keys AND GitHub backup')}\n\n"
        f"{sc('This cannot be undone')}.{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(
        Btn(
            f"{G['trash']}  {sc('Delete Bot Files')}",
            callback_data=f"bot_delfiles_{bot_id}"),
        Btn(
            f"{G['no']}  {sc('Delete All Data')}",
            callback_data=f"bot_delall_{bot_id}"),
        Btn(
            f"{G['back']}  {sc('Cancel')}",
            callback_data=f"bot_view_{bot_id}"),
    )
    show_menu(call.message.chat.id, PHOTOS["bot"], cap, kb, call=call)


def render_bot_delfiles_confirm(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    cap = (
        f"<b>{G['trash']} {sc('Delete Bot Files')} — {esc(b['name'])}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Removes encrypted files and keys only.')}\n"
        f"{sc('GitHub backup will NOT be deleted.')}\n\n"
        f"{sc('Are you sure?')}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["bot"], cap,
              confirm_kb(f"bot_delfilesyes_{bot_id}", f"bot_view_{bot_id}", "Yes Delete", "Cancel"),
              call=call)


def render_bot_delall_confirm(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    cap = (
        f"<b>{G['no']} {sc('Delete All Data')} — {esc(b['name'])}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Removes files, keys AND deletes from GitHub.')}\n"
        f"{G['warn']} <b>{sc('Everything will be permanently gone.')}</b>\n\n"
        f"{sc('Are you sure?')}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["bot"], cap,
              confirm_kb(f"bot_delalyes_{bot_id}", f"bot_view_{bot_id}", "Yes Delete All", "Cancel"),
              call=call)


def action_bot_delete(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    if b["owner"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    loading(call, "Deleting bot")
    stop_child(bot_id, manual=True)
    for f in b.get("enc_files") or []:
        try:
            Path(f["enc_path"]).unlink(missing_ok=True)
        except Exception:
            pass
        KEYRING.remove(f["key_id"])
    rmrf(b.get("dir") or "")
    delete_bot_doc(bot_id)
    ack(call, "Deleted")
    audit(call.from_user.id, "bot_delete", f"bot={bot_id}")
    render_bots_menu(call)


def action_bot_delfiles(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    if b["owner"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    loading(call, "Deleting bot files")
    stop_child(bot_id, manual=True)
    for f in b.get("enc_files") or []:
        try:
            Path(f["enc_path"]).unlink(missing_ok=True)
        except Exception:
            pass
        KEYRING.remove(f["key_id"])
    rmrf(b.get("dir") or "")
    delete_bot_doc(bot_id)
    ack(call, "Bot files deleted")
    audit(call.from_user.id, "bot_delfiles", f"bot={bot_id}")
    render_bots_menu(call)


def action_bot_delall(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    if b["owner"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    loading(call, "Deleting all data")
    stop_child(bot_id, manual=True)
    for f in b.get("enc_files") or []:
        try:
            Path(f["enc_path"]).unlink(missing_ok=True)
        except Exception:
            pass
        KEYRING.remove(f["key_id"])
    rmrf(b.get("dir") or "")
    threading.Thread(target=_gh_delete_bot_files, args=(b,), daemon=True).start()
    delete_bot_doc(bot_id)
    ack(call, "All data deleted")
    audit(call.from_user.id, "bot_delall", f"bot={bot_id}")
    render_bots_menu(call)


def action_bot_clone(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    if b["owner"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    u = db_load()["users"][str(call.from_user.id)]
    if len(list_user_bots(call.from_user.id)) >= user_max_bots(u):
        ack(call, "Slot limit reached"); return
    loading(call, "Cloning bot")
    new_id = secrets.token_hex(8)
    new_dir = DIRS["sandbox"] / f"{call.from_user.id}_{new_id}"
    new_dir.mkdir(parents=True, exist_ok=True)
    new_doc = {
        "_id": new_id, "owner": call.from_user.id,
        "name": f"{b['name']}_clone",
        "dir": str(new_dir), "created": ts_iso(),
        "enc_files": [], "env": dict(b.get("env") or {}), "status": "stopped",
    }
    for f in b.get("enc_files") or []:
        key = KEYRING.fetch(f["key_id"])
        if not key:
            continue
        try:
            plain = read_encrypted(Path(f["enc_path"]), key)
        except InvalidToken:
            continue
        kid, k2, cipher = encrypt_file(plain)
        rel = f"{call.from_user.id}/{int(time.time())}_{safe_name(f['filename'])}.enc"
        out = DIRS["encfiles"] / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(cipher)
        meta = dict(f); meta.update({"clone_of": b["_id"], "stored_at": str(out)})
        KEYRING.store(kid, k2, meta)
        new_doc["enc_files"].append({
            "key_id": kid, "enc_path": str(out),
            "filename": f["filename"], "rel_path": f.get("rel_path") or f["filename"],
        })
    save_bot(new_doc)
    audit(call.from_user.id, "bot_clone", f"src={bot_id} dst={new_id}")
    ack(call, "Cloned")
    render_bots_menu(call)


def action_bot_download(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    if b["owner"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    files = b.get("enc_files") or []
    if not files:
        ack(call, "No files"); return
    loading(call, "Preparing download")
    out = Path(tempfile.gettempdir()) / f"dl_{b['_id']}.zip"
    try:
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            for f in files:
                key = KEYRING.fetch(f["key_id"])
                if not key:
                    continue
                try:
                    plain = read_encrypted(Path(f["enc_path"]), key)
                except Exception:
                    continue
                z.writestr(f.get("rel_path") or f["filename"], plain)
        with open(out, "rb") as fh:
            bot.send_document(
                call.message.chat.id, fh,
                caption=f"{G['download']} {sc('Bot files')} — {esc(b['name'])}",
                visible_file_name=f"{safe_name(b['name'])}.zip",
            )
        ack(call, "Sent")
    except Exception as e:
        ack(call, f"Error: {e}")
    finally:
        try:
            out.unlink()
        except Exception:
            pass
    # Restore the bot view so the loading caption isn't left on screen.
    try:
        render_bot_view(call, bot_id)
    except Exception:
        pass


def render_env_menu(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    if b["owner"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    env = b.get("env") or {}
    rows = "\n".join(f"{bullet(k, v)}" for k, v in env.items()) or f"<i>{sc('no variables yet')}</i>"
    cap = (
        f"<b>{G['settings']} {sc('Env Vars')} — {esc(b['name'])}</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup()
    kb.add(Btn(
        f"{G['plus']}  {sc('Add Variable')}", callback_data=f"env_add_{bot_id}"))
    for k in env:
        kb.add(Btn(
            f"{G['no']}  {sc('Delete')} {k}", callback_data=f"env_del_{bot_id}_{k}"))
    kb.add(Btn(
        f"{G['back']}  {sc('Bot')}", callback_data=f"bot_view_{bot_id}"))
    show_menu(call.message.chat.id, PHOTOS["bot"], cap, kb, call=call)


def start_env_add(call: types.CallbackQuery, bot_id: str) -> None:
    USER_STATES[call.from_user.id] = {"flow": "await_env_kv", "bot_id": bot_id}
    bot.send_message(
        call.message.chat.id,
        f"{G['plus']} {sc('Send the variable as')} <code>KEY=VALUE</code>.\n"
        f"/cancel {sc('to abort')}.",
        parse_mode="HTML",
    )


def start_tunnel_flow(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    if b["owner"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    owner_doc = db_load()["users"].get(str(b["owner"])) or {}
    if owner_doc.get("plan", "free") == "free" or not user_plan_active(owner_doc):
        bot.send_message(
            call.message.chat.id,
            f"{G['no']} <b>{sc('Public URL is a premium feature')}.</b>\n"
            f"{sc('Upgrade your plan to unlock cloudflared tunnels')}.{FOOTER}",
            parse_mode="HTML",
        )
        return

    # Toggle: if already running, stop it.
    cur = TUNNELS.get(bot_id)
    if cur and cur.get("proc") and cur["proc"].poll() is None:
        _stop_tunnel(bot_id)
        bot.send_message(
            call.message.chat.id,
            f"{G['ok']} {sc('Public URL closed')}.{FOOTER}",
            parse_mode="HTML",
        )
        try:
            render_bot_view(call, bot_id)
        except Exception:
            pass
        return

    USER_STATES[call.from_user.id] = {"flow": "await_tunnel_port", "bot_id": bot_id}
    bot.send_message(
        call.message.chat.id,
        f"<b>{G['cloud']} {sc('Open a Public URL')}</b>\n"
        f"{G['div']}\n"
        f"{sc('Send the local port your bot is listening on')} "
        f"({sc('e.g.')} <code>8080</code>).\n"
        f"{sc('A random')} <code>*.trycloudflare.com</code> {sc('URL will proxy to that port')}.\n\n"
        f"{sc('If the port is already in use by another tunnel, pick a different one')}.\n"
        f"/cancel {sc('to abort')}.",
        parse_mode="HTML",
    )


def _handle_tunnel_port(m: types.Message, st: Dict[str, Any]) -> None:
    USER_STATES.pop(m.from_user.id, None)
    txt = (m.text or "").strip()
    if not txt.isdigit():
        bot.reply_to(m, f"{G['no']} {sc('Port must be a number')}.")
        return
    port = int(txt)
    if not (1 <= port <= 65535):
        bot.reply_to(m, f"{G['no']} {sc('Port must be between 1 and 65535')}.")
        return
    b = find_bot(st["bot_id"])
    if not b:
        bot.reply_to(m, f"{G['no']} {sc('Bot not found')}."); return
    if b["owner"] != m.from_user.id and not is_admin(m.from_user.id):
        bot.reply_to(m, f"{G['no']} {sc('Not yours')}."); return

    # Refuse if any other bot already holds this port via a tunnel
    for other_id, rec in list(TUNNELS.items()):
        if other_id == b["_id"]:
            continue
        if rec.get("port") == port and rec.get("proc") and rec["proc"].poll() is None:
            bot.reply_to(
                m,
                f"{G['no']} <b>{sc('Port')} {port} {sc('is already in use by another tunnel')}.</b>\n"
                f"{sc('Please pick a different port')}.",
                parse_mode="HTML",
            )
            return

    status = bot.reply_to(
        m,
        f"{G['refresh']} {sc('Opening tunnel on port')} <code>{port}</code> ...",
        parse_mode="HTML",
    )
    res = _start_tunnel(b["_id"], port)
    if not res.get("ok"):
        try:
            bot.edit_message_text(
                f"{G['no']} <b>{sc('Tunnel failed')}.</b>\n"
                f"<code>{esc(res.get('error', 'unknown error'))}</code>",
                chat_id=status.chat.id, message_id=status.message_id,
                parse_mode="HTML",
            )
        except Exception:
            pass
        return
    url = res.get("url") or "(provisioning…)"
    try:
        bot.edit_message_text(
            f"{G['ok']} <b>{sc('Public URL is live')}</b>\n"
            f"{G['div']}\n"
            f"{bullet('URL',  url)}\n"
            f"{bullet('Port', port)}\n\n"
            f"{sc('Tap the bot menu Public URL button again to stop it')}.{FOOTER}",
            chat_id=status.chat.id, message_id=status.message_id,
            parse_mode="HTML", disable_web_page_preview=True,
        )
    except Exception:
        pass


def start_pip_install_flow(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    if b["owner"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    USER_STATES[call.from_user.id] = {"flow": "await_pip_install", "bot_id": bot_id}
    bot.send_message(
        call.message.chat.id,
        f"<b>{G['download']} {sc('Install Python package')}</b>\n"
        f"{G['div']}\n"
        f"{sc('Send one or more package names separated by spaces')}.\n"
        f"{sc('Examples')}:\n"
        f"  <code>requests</code>\n"
        f"  <code>numpy pandas</code>\n"
        f"  <code>flask==3.0.0</code>\n\n"
        f"/cancel {sc('to abort')}.",
        parse_mode="HTML",
    )


def action_env_delete(call: types.CallbackQuery, bot_id: str, key: str) -> None:
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    if b["owner"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    env = b.get("env") or {}
    env.pop(key, None)
    b["env"] = env
    save_bot(b)
    ack(call, "Deleted")
    render_env_menu(call, bot_id)


def render_cron(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    cron = b.get("cron") or {}
    cap = (
        f"<b>{G['cog']} {sc('Cron')} — {esc(b['name'])}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Restart every', cron.get('restart_hours', '—'))}\n"
        f"{bullet('Backup every',  cron.get('backup_hours', '—'))}\n"
        f"{G['div']}\n"
        f"{sc('Send a message like')} <code>restart=6 backup=12</code> {sc('to set hours')}.\n"
        f"{sc('Send')} <code>off</code> {sc('to disable cron')}.{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_cron", "bot_id": bot_id}
    show_menu(call.message.chat.id, PHOTOS["bot"], cap,
              back_kb(f"bot_view_{bot_id}", "Back"), call=call)


# ═════════════════════════════════════════════════════════════════
# 20. ADMIN PANEL  RENDERS
# ═════════════════════════════════════════════════════════════════

def render_admin(call: types.CallbackQuery) -> None:
    if not admin_only_call(call, "view_stats"):
        return
    role = admin_role(call.from_user.id)
    cap = (
        f"<b>{G['shield']} {sc('Admin Panel')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Role',  role)}\n"
        f"{bullet('Users', len(db_load()['users']))}\n"
        f"{bullet('Bots',  len(db_load()['bots']))}\n"
        f"{bullet('Run',   sum(1 for x in RUNNING.values() if x['proc'].poll() is None))}\n"
        f"{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, admin_kb(), call=call)


def render_admin_subroute(call: types.CallbackQuery, data: str) -> None:
    if data == "adm_stats":
        return render_adm_stats(call)
    if data == "adm_users":
        return render_adm_users(call)
    if data == "adm_allbots":
        return render_adm_allbots(call)
    if data == "adm_payments":
        return render_adm_payments(call)
    if data == "adm_broadcast":
        return render_adm_broadcast(call)
    if data == "adm_ban":
        return render_adm_ban(call)
    if data == "adm_giveplan":
        return render_adm_giveplan(call)
    if data == "adm_approve":
        return render_adm_payments(call)
    if data == "adm_coupons":
        return render_adm_coupons(call)
    if data == "adm_tickets":
        return render_adm_tickets(call)
    if data == "adm_admins":
        return render_adm_admins(call)
    if data == "adm_audit":
        return render_adm_audit(call)
    if data == "adm_github":
        return render_adm_github(call)
    if data == "adm_vm_nodes":
        return render_adm_vm_nodes(call)
    if data == "adm_mongo":
        return render_adm_mongo(call)
    if data == "adm_vm_add":
        USER_STATES[call.from_user.id] = {"flow": "await_vm_url"}
        bot.send_message(call.message.chat.id, f"{G['plus']} {sc('Send the VM URL now')} (<code>https://....onrender.com</code>).", parse_mode="HTML"); return
    if data == "adm_vm_testall":
        _bg_vm_testall(call); return
    if data.startswith("adm_vm_info:"):
        return render_adm_vm_info(call, data.split(":", 1)[1])
    if data.startswith("adm_vm_toggle:"):
        _vm_toggle(call, data.split(":", 1)[1]); return render_adm_vm_info(call, data.split(":", 1)[1])
    if data.startswith("adm_vm_remove:"):
        _vm_remove(call, data.split(":", 1)[1]); return render_adm_vm_nodes(call)
    if data.startswith("adm_vm_test:"):
        _vm_test_one(call, data.split(":", 1)[1]); return
    if data == "adm_mongo_add":
        USER_STATES[call.from_user.id] = {"flow": "await_mongo_uri"}
        bot.send_message(call.message.chat.id, f"{G['key']} {sc('Send the MongoDB URI now')} (<code>mongodb+srv://...</code>).", parse_mode="HTML"); return
    if data.startswith("adm_mongo_remove:"):
        _mongo_remove_idx(call, data.split(":", 1)[1]); return render_adm_mongo(call)
    if data.startswith("adm_mongo_info:"):
        ack(call, "Fetching URI details…"); return render_adm_mongo_info(call, data.split(":", 1)[1])
    if data == "adm_security":
        return render_adm_security(call)
    if data == "adm_maint":
        return render_adm_maintenance(call)
    if data == "adm_maint_toggle":
        cur = bool(get_setting("maintenance", False))
        set_setting("maintenance", not cur)
        audit(call.from_user.id, "maintenance_toggle", f"now={not cur}")
        ack(call, f"Maintenance: {'ON' if not cur else 'OFF'}")
        return render_adm_maintenance(call)
    if data == "adm_settings":
        return render_adm_settings(call)
    if data == "adm_approval_toggle":
        cur = approval_required()
        set_approval_required(not cur)
        audit(call.from_user.id, "approval_toggle", f"now={not cur}")
        ack(call, f"Approval Mode: {'ON' if not cur else 'OFF'}")
        return render_admin(call)
    if data == "adm_pending":
        return render_adm_pending(call)
    if data == "adm_photos":
        return render_adm_photos(call)
    if data.startswith("adm_photo_"):
        key = data[len("adm_photo_"):]
        return render_adm_photo_one(call, key)
    if data == "adm_force_backup":
        if not is_owner(call.from_user.id):
            ack(call, "Owner only"); return
        ack(call, "Backing up…")
        def _bg() -> None:
            try:
                ok1 = gh_sync_user_data()
                pushed = 0
                for b in db_load()["bots"].values():
                    if (b.get("approval_status") in (None, "approved")) and b.get("enc_files"):
                        try:
                            _gh_sync_bot_files(b)
                            b["gh_synced_at"] = int(time.time())
                            save_bot(b)
                            pushed += 1
                        except Exception:
                            pass
                try:
                    bot.send_message(
                        call.from_user.id,
                        f"<b>{G['ok']} {sc('Force backup done')}</b>\n"
                        f"{bullet('user_data.json', 'OK' if ok1 else 'FAIL')}\n"
                        f"{bullet('Bots pushed', pushed)}",
                        parse_mode="HTML",
                    )
                except Exception:
                    pass
            except Exception as e:
                try:
                    bot.send_message(call.from_user.id,
                                     f"{G['no']} {sc('Backup error')}: <code>{esc(e)}</code>",
                                     parse_mode="HTML")
                except Exception:
                    pass
        threading.Thread(target=_bg, daemon=True).start()
        return

    # ── advanced settings ──────────────────────────────────────────
    if data == "adm_set_sysinfo":
        return render_adm_sysinfo(call)
    if data == "adm_set_plans":
        return render_adm_plans(call)
    if data == "adm_set_plans_reset":
        if not is_owner(call.from_user.id):
            ack(call, "Owner only"); return
        s = settings_load()
        for k in list(s.keys()):
            if k.startswith("plan_max_bots_"):
                s.pop(k, None)
        settings_save(s)
        audit(call.from_user.id, "plans_reset", "")
        ack(call, "Plans reset")
        return render_adm_plans(call)
    if data.startswith("adm_set_plan_show_"):
        ack(call, "Use ➕ / ➖ to adjust"); return
    if data.startswith("adm_set_plan_inc_") or data.startswith("adm_set_plan_dec_"):
        if not is_owner(call.from_user.id):
            ack(call, "Owner only"); return
        inc = data.startswith("adm_set_plan_inc_")
        key = data.split("_")[-1]
        if key not in PLAN_LIMITS:
            ack(call, "Unknown plan"); return
        cur = int(get_setting(f"plan_max_bots_{key}",
                              PLAN_LIMITS[key]["max_bots"]))
        cur = max(1, cur + (1 if inc else -1))
        set_setting(f"plan_max_bots_{key}", cur)
        audit(call.from_user.id, "plan_edit", f"{key} max_bots={cur}")
        ack(call, f"{PLAN_LIMITS[key]['name']}: {cur}")
        return render_adm_plans(call)
    if data == "adm_set_reload":
        if not is_admin(call.from_user.id):
            ack(call, "No permission"); return
        cache_clear_all()
        audit(call.from_user.id, "reload_caches", "")
        ack(call, "Caches dropped — next read = disk")
        return render_adm_settings(call)
    if data == "adm_set_brand":
        if not is_owner(call.from_user.id):
            ack(call, "Owner only"); return
        USER_STATES[call.from_user.id] = {"flow": "await_set_brand"}
        bot.send_message(call.message.chat.id,
                         f"{G['settings']} {sc('Send the new brand tag')} "
                         f"(<i>{sc('plain text, will appear in headers')}</i>):",
                         parse_mode="HTML")
        return
    if data == "adm_set_announce":
        if not is_owner(call.from_user.id):
            ack(call, "Owner only"); return
        USER_STATES[call.from_user.id] = {"flow": "await_set_announce"}
        bot.send_message(call.message.chat.id,
                         f"{G['broadcast']} {sc('Send the announce channel handle')} "
                         f"(<code>@channel</code> or <code>-</code> {sc('to clear')}):",
                         parse_mode="HTML")
        return
    if data == "adm_set_owner":
        if not is_owner(call.from_user.id):
            ack(call, "Owner only"); return
        USER_STATES[call.from_user.id] = {"flow": "await_set_owner"}
        bot.send_message(call.message.chat.id,
                         f"{G['shield']} {sc('Send the new owner numeric Telegram ID')}.\n"
                         f"<i>{sc('You will lose owner rights after this')}.</i>",
                         parse_mode="HTML")
        return
    if data == "adm_set_restart_all":
        if not is_owner(call.from_user.id):
            ack(call, "Owner only"); return
        return render_adm_confirm(call, "adm_set_restart_all", "Restart all running bots")
    if data == "adm_set_restart_all_yes":
        if not is_owner(call.from_user.id):
            ack(call, "Owner only"); return
        ack(call, "Restarting…")
        def _rb() -> None:
            ok, fail = _do_restart_all_bots(call.from_user.id)
            try:
                bot.send_message(call.from_user.id,
                                 f"{G['ok']} {sc('Restart-all done')}: "
                                 f"{ok} ok, {fail} fail.")
            except Exception:
                pass
        threading.Thread(target=_rb, daemon=True).start()
        return
    if data == "adm_set_stop_all":
        if not is_owner(call.from_user.id):
            ack(call, "Owner only"); return
        return render_adm_confirm(call, "adm_set_stop_all", "Turn off all bots? They will stop replying until you start them again. Nothing will be deleted.")
    if data == "adm_set_stop_all_yes":
        if not is_owner(call.from_user.id):
            ack(call, "Owner only"); return
        ack(call, "Turning off…")
        def _sb() -> None:
            n = _do_stop_all_bots(call.from_user.id)
            try:
                bot.send_message(call.from_user.id,
                                 f"{G['ok']} {sc('All bots are now off')} ({n}). {sc('Nothing is deleted. Start them again from My Bots / All Bots when ready')}.")
            except Exception:
                pass
        threading.Thread(target=_sb, daemon=True).start()
        return
    if data == "adm_set_clean_orphans":
        if not is_admin(call.from_user.id):
            ack(call, "No permission"); return
        ack(call, "Scanning…")
        def _co() -> None:
            dirs, files = _do_clean_orphans()
            audit(call.from_user.id, "clean_orphans",
                  f"sandboxes={dirs} files={files}")
            try:
                bot.send_message(call.from_user.id,
                                 f"{G['ok']} {sc('Cleaned')}: "
                                 f"{dirs} {sc('sandbox(es)')}, "
                                 f"{files} {sc('orphan file(s)')}.")
            except Exception:
                pass
        threading.Thread(target=_co, daemon=True).start()
        return
    if data == "adm_set_export":
        if not is_owner(call.from_user.id):
            ack(call, "Owner only"); return
        ack(call, "Packing export…")
        def _ex() -> None:
            try:
                p = _do_export_data(call.from_user.id)
                with p.open("rb") as fh:
                    bot.send_document(
                        call.from_user.id, fh,
                        caption=f"{G['ok']} {sc('Encrypted DB export')} "
                                f"({p.stat().st_size // 1024} KB)")
            except Exception as e:
                try:
                    bot.send_message(
                        call.from_user.id,
                        f"{G['no']} {sc('Export error')}: <code>{esc(e)}</code>",
                        parse_mode="HTML")
                except Exception:
                    pass
        threading.Thread(target=_ex, daemon=True).start()
        return

    # ── NEW: 6 Advanced Sub-Panel Routes ────────────────────────────
    if data == "adm_analytics":
        return render_adm_analytics(call)
    if data == "adm_user_tools":
        return render_adm_user_tools(call)
    if data == "adm_bot_manager":
        return render_adm_bot_manager(call)
    if data == "adm_sec_center":
        return render_adm_sec_center(call)
    if data == "adm_notify_center":
        return render_adm_notify_center(call)
    if data == "adm_sys_tools":
        return render_adm_sys_tools(call)
    # Analytics sub-routes
    if data == "adm_revenue_report":
        return render_adm_revenue_report(call)
    if data == "adm_growth_stats":
        return render_adm_growth_stats(call)
    if data == "adm_top_users":
        return render_adm_top_users(call)
    if data == "adm_plan_dist":
        return render_adm_plan_dist(call)
    if data == "adm_bot_activity":
        return render_adm_bot_activity(call)
    # User Tools sub-routes
    if data == "adm_user_search":
        return render_adm_user_search(call)
    if data == "adm_banned_list":
        return render_adm_banned_list(call)
    if data == "adm_wallet_admin":
        return render_adm_wallet_admin(call)
    if data == "adm_user_export_csv":
        return render_adm_user_export_csv(call)
    if data == "adm_notify_user":
        return render_adm_notify_user(call)
    if data == "adm_user_reset":
        return render_adm_user_reset_prompt(call)
    # Bot Manager sub-routes
    if data == "adm_crashed_bots":
        return render_adm_crashed_bots(call)
    if data == "adm_mass_restart_stopped":
        return render_adm_mass_restart_stopped(call)
    if data == "adm_mass_restart_stopped_yes":
        return action_adm_mass_restart_stopped(call)
    if data == "adm_bot_search":
        return render_adm_bot_search(call)
    if data == "adm_bot_size_report":
        return render_adm_bot_size_report(call)
    if data == "adm_force_scan_all":
        return action_adm_force_scan_all(call)
    if data == "adm_kill_all_now":
        return render_adm_confirm_custom(call, "adm_kill_all_now_yes",
                                         "Kill ALL running bots immediately", "adm_bot_manager")
    if data == "adm_kill_all_now_yes":
        return action_adm_kill_all(call)
    # Security Center sub-routes
    if data == "adm_threat_log":
        return render_adm_threat_log(call)
    if data == "adm_sec_stats":
        return render_adm_sec_stats(call)
    if data == "adm_sec_whitelist":
        return render_adm_sec_whitelist_prompt(call)
    if data == "adm_scan_report":
        return render_adm_scan_report(call)
    if data == "adm_sec_blacklist":
        return render_adm_sec_blacklist(call)
    # Notifications sub-routes
    if data == "adm_notify_all":
        return render_adm_notify_all(call)
    if data == "adm_notify_running":
        return render_adm_notify_running(call)
    if data == "adm_notify_plan_select":
        return render_adm_notify_plan_select(call)
    if data.startswith("adm_notify_plan_"):
        plan_key = data[len("adm_notify_plan_"):]
        return render_adm_notify_plan(call, plan_key)
    if data == "adm_schedule_msg":
        return render_adm_schedule_msg(call)
    if data == "adm_quick_announce":
        return render_adm_quick_announce(call)
    # System Tools sub-routes
    if data == "adm_sys_health":
        return render_adm_sys_health(call)
    if data == "adm_disk_usage":
        return render_adm_disk_usage(call)
    if data == "adm_db_info":
        return render_adm_db_info(call)
    if data == "adm_clear_cache":
        cache_clear_all()
        audit(call.from_user.id, "clear_cache", "manual")
        ack(call, "All caches cleared!")
        return render_adm_sys_tools(call)
    if data == "adm_token_check":
        return render_adm_token_check(call)
    if data == "adm_export_users_csv":
        return render_adm_user_export_csv(call)
    if data == "adm_set_footer_text":
        if not is_owner(call.from_user.id):
            ack(call, "Owner only"); return
        USER_STATES[call.from_user.id] = {"flow": "await_set_footer"}
        bot.send_message(call.message.chat.id,
                         f"{G['settings']} <b>{sc('Send new footer text')}</b> "
                         f"(<i>{sc('or')} <code>-</code> {sc('to reset')}</i>):",
                         parse_mode="HTML")
        return
    if data == "adm_set_welcome_text":
        if not is_owner(call.from_user.id):
            ack(call, "Owner only"); return
        USER_STATES[call.from_user.id] = {"flow": "await_set_welcome"}
        bot.send_message(call.message.chat.id,
                         f"{G['broadcast']} <b>{sc('Send new welcome message')}</b>:",
                         parse_mode="HTML")
        return
    if data == "adm_set_rules_text":
        if not is_owner(call.from_user.id):
            ack(call, "Owner only"); return
        USER_STATES[call.from_user.id] = {"flow": "await_set_rules"}
        bot.send_message(call.message.chat.id,
                         f"{G['shield']} <b>{sc('Send new hosting rules text')}</b>:",
                         parse_mode="HTML")
        return

    # ══════════════════ MEGA ADVANCED PANEL ROUTES ══════════════════
    # GitHub Browser
    if data == "adm_gh_browser":        return render_adm_gh_browser(call)
    if data == "adm_gh_repos":          return render_adm_gh_repos(call)
    if data == "adm_gh_refresh_repos":  return render_adm_gh_repos(call, force=True)
    if data.startswith("adm_ghrepo_"):
        repo = data[len("adm_ghrepo_"):]
        st2 = USER_STATES.get(call.from_user.id, {})
        gh_path = st2.get("gh_path", "")
        return render_adm_gh_files(call, repo, gh_path)
    if data == "adm_gh_up":
        st2 = USER_STATES.get(call.from_user.id, {})
        repo = st2.get("gh_repo", "")
        path = "/".join(st2.get("gh_path", "").split("/")[:-1])
        USER_STATES[call.from_user.id] = {**st2, "gh_path": path}
        return render_adm_gh_files(call, repo, path)
    if data.startswith("adm_ghfile_"):
        idx = int(data[len("adm_ghfile_"):])
        st2 = USER_STATES.get(call.from_user.id, {})
        files_list = st2.get("gh_files_list", [])
        if idx < len(files_list):
            item = files_list[idx]
            repo = st2.get("gh_repo", "")
            if item["type"] == "dir":
                USER_STATES[call.from_user.id] = {**st2, "gh_path": item["path"]}
                return render_adm_gh_files(call, repo, item["path"])
            else:
                return render_adm_gh_file_view(call, repo, item["path"])
    if data == "adm_gh_run_file":
        st2 = USER_STATES.get(call.from_user.id, {})
        return action_adm_gh_run_file(call, st2.get("gh_repo",""), st2.get("gh_view_path",""))
    if data == "adm_gh_dl_file":
        st2 = USER_STATES.get(call.from_user.id, {})
        return action_adm_gh_dl_file(call, st2.get("gh_repo",""), st2.get("gh_view_path",""))
    if data == "adm_gh_browse_repo":
        st2 = USER_STATES.get(call.from_user.id, {})
        repo = st2.get("gh_repo","")
        return render_adm_gh_files(call, repo, "")
    if data == "adm_gh_set_default_repo":
        st2 = USER_STATES.get(call.from_user.id, {})
        repo = st2.get("gh_repo","")
        if repo:
            set_setting("github_repo", repo)
            gh_set_config({"repo": repo}); gh_load_config()
            audit(call.from_user.id, "gh_set_default_repo", repo)
            ack(call, f"Default repo set: {repo}")
        return render_adm_gh_browser(call)
    # Payment Config
    if data == "adm_pay_config":          return render_adm_pay_config(call)
    if data == "adm_pay_methods":         return render_adm_pay_methods(call)
    if data.startswith("adm_pay_edit_"):  return render_adm_pay_method_edit(call, data[len("adm_pay_edit_"):])
    if data == "adm_pay_limits":          return render_adm_pay_limits(call)
    if data == "adm_pay_currency":        return render_adm_pay_currency(call)
    if data == "adm_pay_auto_approve":
        cur = bool(get_setting("auto_approve_payments", False))
        set_setting("auto_approve_payments", not cur)
        audit(call.from_user.id, "auto_approve_toggle", f"now={not cur}")
        ack(call, f"Auto-approve: {'ON' if not cur else 'OFF'}")
        return render_adm_pay_config(call)
    if data == "adm_pay_receipt_tmpl":    return render_adm_pay_receipt_tmpl(call)
    if data == "adm_pay_notif":           return render_adm_pay_notif_settings(call)
    if data.startswith("adm_pay_method_"): return action_adm_pay_method_number(call, data)
    # Bot Config
    if data == "adm_bot_cfg":             return render_adm_bot_cfg(call)
    if data == "adm_bc_timeouts":         return render_adm_bc_timeouts(call)
    if data == "adm_bc_limits":           return render_adm_bc_limits(call)
    if data == "adm_bc_sandbox":          return render_adm_bc_sandbox(call)
    if data == "adm_bc_policy":           return render_adm_bc_policy(call)
    if data == "adm_bc_upload":           return render_adm_bc_upload(call)
    if data == "adm_bc_env":              return render_adm_bc_env(call)
    if data.startswith("adm_bc_toggle_"):
        flag_key = data[len("adm_bc_toggle_"):]
        cur = bool(get_setting(f"bc_{flag_key}", False))
        set_setting(f"bc_{flag_key}", not cur)
        audit(call.from_user.id, f"bc_toggle_{flag_key}", f"now={not cur}")
        ack(call, f"{flag_key}: {'ON' if not cur else 'OFF'}")
        return render_adm_bot_cfg(call)
    if data.startswith("adm_bc_set_"):
        USER_STATES[call.from_user.id] = {"flow": "await_adm_bc_set", "bc_key": data[len("adm_bc_set_"):]}
        bot.send_message(call.message.chat.id, f"{G['settings']} {sc('Send new value')}:", parse_mode="HTML"); return
    # Appearance
    if data == "adm_appearance":          return render_adm_appearance(call)
    if data == "adm_app_emojis":          return render_adm_app_emojis(call)
    if data == "adm_app_theme":           return render_adm_app_theme(call)
    if data.startswith("adm_app_theme_"):
        theme = data[len("adm_app_theme_"):]
        set_setting("ui_theme", theme)
        audit(call.from_user.id, "set_theme", theme)
        ack(call, f"Theme: {theme}")
        return render_adm_app_theme(call)
    if data == "adm_app_banner":          return render_adm_app_banner(call)
    if data == "adm_rebuild_banners":
        _PHOTO_FILE_IDS.clear()
        ack(call, f"{G['ok']} Banner cache cleared — photos will reload fresh")
        return render_adm_app_banner(call)
    if data == "adm_bc_set_currency_symbol":
        USER_STATES[call.from_user.id] = {"flow": "await_adm_bc_set", "bc_key": "currency_symbol"}
        bot.send_message(call.message.chat.id, f"{G['settings']} Send new currency symbol (e.g. ₹ $ €):", parse_mode="HTML"); return
    if data.startswith("adm_bc_set_currency_") and len(data.split("_")) >= 6:
        parts = data[len("adm_bc_set_currency_"):].split("_", 1)
        if len(parts) == 2:
            _bc_set("currency_code", parts[0]); _bc_set("currency_symbol", parts[1])
            ack(call, f"{G['ok']} Currency set: {parts[0]} {parts[1]}")
        return render_adm_pay_config(call)
    if data == "adm_app_emoji_reset":
        if not is_owner(call.from_user.id): ack(call, "Owner only"); return
        set_setting("custom_emojis", {})
        audit(call.from_user.id, "emoji_reset", "")
        ack(call, "Emojis reset to default")
        return render_adm_app_emojis(call)
    if data.startswith("adm_app_emoji_set_"):
        key = data[len("adm_app_emoji_set_"):]
        USER_STATES[call.from_user.id] = {"flow": "await_adm_emoji_set", "emoji_key": key}
        bot.send_message(call.message.chat.id, f"Send emoji for <code>{esc(key)}</code>:", parse_mode="HTML"); return
    # Coupon Plus
    if data == "adm_coupon_plus":         return render_adm_coupon_plus(call)
    if data == "adm_coupon_bulk":         return render_adm_coupon_bulk(call)
    if data == "adm_coupon_analytics":    return render_adm_coupon_analytics(call)
    if data == "adm_coupon_expiry":       return render_adm_coupon_expiry(call)
    if data == "adm_coupon_clearexp":
        d = db_load()
        now_s = ts_iso()
        before = len(d["coupons"])
        d["coupons"] = {k: v for k, v in d["coupons"].items()
                        if not (v.get("expiry") and v["expiry"] < now_s)}
        db_save(d)
        removed = before - len(d["coupons"])
        audit(call.from_user.id, "coupon_clear_expired", f"removed={removed}")
        ack(call, f"Removed {removed} expired coupons")
        return render_adm_coupon_plus(call)
    # Templates
    if data == "adm_templates":           return render_adm_templates(call)
    if data.startswith("adm_tmpl_edit_"):
        key = data[len("adm_tmpl_edit_"):]
        USER_STATES[call.from_user.id] = {"flow": "await_adm_tmpl_edit", "tmpl_key": key}
        cur = get_setting(f"tmpl_{key}", "") or ""
        bot.send_message(call.message.chat.id,
                         f"<b>📝 {sc('Edit Template')}: <code>{esc(key)}</code></b>\n"
                         f"{G['div']}\n<i>{sc('Current')}:</i>\n{esc(cur) or '(default)'}\n\n"
                         f"{sc('Send new template text. Use')} <code>{{name}}</code>, <code>{{plan}}</code>, "
                         f"<code>{{amount}}</code>, <code>{{date}}</code> {sc('as placeholders')}.",
                         parse_mode="HTML"); return
    if data.startswith("adm_tmpl_reset_"):
        key = data[len("adm_tmpl_reset_"):]
        set_setting(f"tmpl_{key}", "")
        audit(call.from_user.id, f"tmpl_reset_{key}", "")
        ack(call, f"Template {key} reset to default")
        return render_adm_templates(call)
    # Referral System
    if data == "adm_referral_sys":        return render_adm_referral_sys(call)
    if data == "adm_ref_toggle":
        cur = bool(get_setting("referral_enabled", True))
        set_setting("referral_enabled", not cur)
        audit(call.from_user.id, "referral_toggle", f"now={not cur}")
        ack(call, f"Referrals: {'ON' if not cur else 'OFF'}")
        return render_adm_referral_sys(call)
    if data == "adm_ref_stats":           return render_adm_ref_stats(call)
    if data == "adm_ref_rewards":         return render_adm_ref_rewards(call)
    if data == "adm_ref_leaderboard":     return render_adm_ref_leaderboard(call)
    if data == "adm_ref_set_reward":
        USER_STATES[call.from_user.id] = {"flow": "await_adm_ref_reward"}
        bot.send_message(call.message.chat.id,
                         f"{G['settings']} {sc('Send wallet reward amount per referral (in ৳)')}."); return
    if data == "adm_ref_set_min_plan":
        USER_STATES[call.from_user.id] = {"flow": "await_adm_ref_min_plan"}
        plans = ", ".join(PLAN_LIMITS.keys())
        bot.send_message(call.message.chat.id,
                         f"{G['settings']} {sc('Send min plan to enable referrals')}: <code>{plans}</code>",
                         parse_mode="HTML"); return
    # Janitor
    if data == "adm_janitor":             return render_adm_janitor(call)
    if data == "adm_jan_run_now":
        ack(call, "Running janitor…")
        threading.Thread(target=lambda: action_adm_jan_run(call.from_user.id), daemon=True).start(); return
    if data == "adm_jan_rules":           return render_adm_jan_rules(call)
    if data == "adm_jan_schedule":        return render_adm_jan_schedule(call)
    if data.startswith("adm_jan_toggle_"):
        k = data[len("adm_jan_toggle_"):]
        cur = bool(get_setting(f"jan_{k}", False))
        set_setting(f"jan_{k}", not cur)
        audit(call.from_user.id, f"jan_toggle_{k}", f"now={not cur}")
        ack(call, f"Janitor {k}: {'ON' if not cur else 'OFF'}")
        return render_adm_janitor(call)
    # Webhooks
    if data == "adm_webhooks":            return render_adm_webhooks(call)
    if data == "adm_wh_set":
        USER_STATES[call.from_user.id] = {"flow": "await_adm_wh_set"}
        bot.send_message(call.message.chat.id, f"{G['settings']} {sc('Send full HTTPS webhook URL')}:"); return
    if data == "adm_wh_clear":
        try:
            bot.remove_webhook()
            set_setting("webhook_url", "")
            audit(call.from_user.id, "wh_clear", "")
            ack(call, "Webhook cleared → polling mode")
        except Exception as _we:
            ack(call, f"Error: {_we}")
        return render_adm_webhooks(call)
    if data == "adm_wh_test":             return action_adm_wh_test(call)
    if data == "adm_wh_info":             return render_adm_wh_info(call)
    # Feature Flags
    if data == "adm_feature_flags":       return render_adm_feature_flags(call)
    if data.startswith("adm_ff_toggle_"):
        ff_key = data[len("adm_ff_toggle_"):]
        cur = bool(get_setting(f"ff_{ff_key}", _FEATURE_FLAG_DEFAULTS.get(ff_key, True)))
        set_setting(f"ff_{ff_key}", not cur)
        audit(call.from_user.id, f"ff_toggle_{ff_key}", f"now={not cur}")
        ack(call, f"Flag {ff_key}: {'ON' if not cur else 'OFF'}")
        return render_adm_feature_flags(call)
    if data == "adm_ff_reset_all":
        for k, v in _FEATURE_FLAG_DEFAULTS.items():
            set_setting(f"ff_{k}", v)
        audit(call.from_user.id, "ff_reset_all", "")
        ack(call, "All feature flags reset to defaults")
        return render_adm_feature_flags(call)
    # Rate Limits
    if data == "adm_rate_config":         return render_adm_rate_config(call)
    if data.startswith("adm_rate_plan_"): return render_adm_rate_plan(call, data[len("adm_rate_plan_"):])
    if data.startswith("adm_rate_set_"):
        USER_STATES[call.from_user.id] = {"flow": "await_adm_rate_set", "rate_key": data[len("adm_rate_set_"):]}
        bot.send_message(call.message.chat.id, f"{G['settings']} {sc('Send new limit value (integer)')}:"); return
    # Live Monitor
    if data == "adm_live_monitor":        return render_adm_live_monitor(call)
    if data == "adm_monitor_bots":        return render_adm_monitor_bots(call)
    if data == "adm_monitor_system":      return render_adm_monitor_system(call)
    if data == "adm_monitor_refresh":     return render_adm_live_monitor(call)
    # Revenue Goals
    if data == "adm_rev_goals":           return render_adm_rev_goals(call)
    if data == "adm_goal_set_monthly":
        USER_STATES[call.from_user.id] = {"flow": "await_adm_goal_set", "goal_type": "monthly"}
        bot.send_message(call.message.chat.id, f"{G['settings']} {sc('Send monthly revenue target (৳)')}:"); return
    if data == "adm_goal_set_yearly":
        USER_STATES[call.from_user.id] = {"flow": "await_adm_goal_set", "goal_type": "yearly"}
        bot.send_message(call.message.chat.id, f"{G['settings']} {sc('Send yearly revenue target (৳)')}:"); return
    if data == "adm_goal_history":        return render_adm_goal_history(call)
    # Scheduler
    if data == "adm_scheduler":           return render_adm_scheduler(call)
    if data == "adm_sched_add":
        USER_STATES[call.from_user.id] = {"flow": "await_adm_sched_add"}
        bot.send_message(call.message.chat.id,
                         f"<b>⏰ {sc('Add Scheduled Task')}</b>\n{G['div']}\n"
                         f"{sc('Format')}: <code>HH:MM daily Your message</code>\n"
                         f"{sc('or')}: <code>YYYY-MM-DD HH:MM once Your message</code>\n"
                         f"{sc('Example')}: <code>09:00 daily Good morning everyone!</code>",
                         parse_mode="HTML"); return
    if data == "adm_sched_list":          return render_adm_sched_list(call)
    if data.startswith("adm_sched_del_"):
        tid = data[len("adm_sched_del_"):]
        tasks = get_setting("scheduled_tasks", []) or []
        tasks = [t for t in tasks if t.get("id") != tid]
        set_setting("scheduled_tasks", tasks)
        audit(call.from_user.id, "sched_del", tid)
        ack(call, f"Task {tid[:8]} deleted")
        return render_adm_sched_list(call)
    if data.startswith("adm_sched_toggle_"):
        tid = data[len("adm_sched_toggle_"):]
        tasks = get_setting("scheduled_tasks", []) or []
        for t in tasks:
            if t.get("id") == tid:
                t["enabled"] = not t.get("enabled", True)
        set_setting("scheduled_tasks", tasks)
        ack(call, "Task toggled")
        return render_adm_sched_list(call)
    # Import / Export
    if data == "adm_import_export":       return render_adm_import_export(call)
    if data == "adm_export_full_cfg":     return action_adm_export_full_cfg(call)
    if data == "adm_export_userdata":     return render_adm_user_export_csv(call)
    if data == "adm_import_cfg":
        USER_STATES[call.from_user.id] = {"flow": "await_adm_import_cfg"}
        bot.send_message(call.message.chat.id,
                         f"{G['upload']} {sc('Upload the settings JSON file exported from this bot')}."); return
    if data == "adm_import_reset":
        if not is_owner(call.from_user.id): ack(call, "Owner only"); return
        USER_STATES[call.from_user.id] = {"flow": "await_adm_factory_reset"}
        bot.send_message(call.message.chat.id,
                         f"⚠️ <b>{sc('FACTORY RESET')}</b> — {sc('Type')} <code>CONFIRM RESET</code> "
                         f"{sc('to wipe ALL settings (not user data). This cannot be undone!')}",
                         parse_mode="HTML"); return
    # Admin 2FA
    if data == "adm_admin_2fa":           return render_adm_admin_2fa(call)
    if data == "adm_2fa_setup":           return action_adm_2fa_setup(call)
    if data == "adm_2fa_disable":
        if not is_owner(call.from_user.id): ack(call, "Owner only"); return
        set_setting("admin_2fa_secret", "")
        set_setting("admin_2fa_enabled", False)
        audit(call.from_user.id, "2fa_disable", "")
        ack(call, "2FA disabled")
        return render_adm_admin_2fa(call)
    # Leaderboard
    if data == "adm_leaderboard":         return render_adm_leaderboard(call)
    if data == "adm_lb_spenders":         return render_adm_lb_spenders(call)
    if data == "adm_lb_bots":             return render_adm_lb_bots(call)
    if data == "adm_lb_referrals":        return render_adm_lb_referrals(call)
    if data == "adm_lb_active":           return render_adm_lb_active(call)
    if data == "adm_lb_uptime":           return render_adm_lb_uptime(call)
    # Languages
    if data == "adm_languages":           return render_adm_languages(call)
    if data.startswith("adm_lang_set_"):
        lang = data[len("adm_lang_set_"):]
        set_setting("default_language", lang)
        audit(call.from_user.id, "set_lang", lang)
        ack(call, f"Default language: {lang}")
        return render_adm_languages(call)
    # Bot Controls
    if data == "adm_bot_controls":        return render_adm_bot_controls_panel(call)
    if data == "adm_bc_list_all":         return render_adm_bc_list_all(call)
    if data.startswith("adm_bcbot_"):     return render_adm_bc_single(call, data[len("adm_bcbot_"):])
    if data.startswith("adm_bc_env_"):    return render_adm_bc_env_editor(call, data[len("adm_bc_env_"):])
    if data.startswith("adm_bc_res_"):    return render_adm_bc_resources(call, data[len("adm_bc_res_"):])
    if data.startswith("adm_bc_logs_"):   return render_adm_bc_logs(call, data[len("adm_bc_logs_"):])
    if data.startswith("adm_bc_restart_"):
        bid = data[len("adm_bc_restart_"):]
        b = find_bot(bid)
        if b:
            threading.Thread(target=lambda: restart_child(b), daemon=True).start()
            ack(call, f"Restarting {b.get('name','?')[:15]}…")
        return
    if data.startswith("adm_bc_stop_"):
        bid = data[len("adm_bc_stop_"):]
        stop_child(bid, manual=True)
        ack(call, f"Stopped {bid[:8]}")
        return render_adm_bc_list_all(call)
    if data.startswith("adm_bc_del_"):
        bid = data[len("adm_bc_del_"):]
        b = find_bot(bid)
        if b:
            return render_adm_confirm_custom(call, f"adm_bc_del_confirm_{bid}",
                                             f"Delete bot {b.get('name','?')[:20]}", "adm_bot_controls")
    if data.startswith("adm_bc_del_confirm_"):
        bid = data[len("adm_bc_del_confirm_"):]
        stop_child(bid, manual=True)
        d = db_load()
        d["bots"].pop(bid, None)
        db_save(d)
        audit(call.from_user.id, "admin_del_bot", bid)
        ack(call, f"Bot {bid[:8]} deleted")
        return render_adm_bc_list_all(call)
    # Subscriptions
    if data == "adm_subscriptions":       return render_adm_subscriptions(call)
    if data == "adm_sub_expiring":        return render_adm_sub_expiring(call)
    if data == "adm_sub_expired":         return render_adm_sub_expired(call)
    if data == "adm_sub_remind_all":
        ack(call, "Sending reminders…")
        threading.Thread(target=lambda: action_adm_sub_remind_all(call.from_user.id), daemon=True).start(); return
    if data == "adm_sub_auto_downgrade":
        cur = bool(get_setting("auto_downgrade_expired", True))
        set_setting("auto_downgrade_expired", not cur)
        audit(call.from_user.id, "auto_downgrade_toggle", f"now={not cur}")
        ack(call, f"Auto-downgrade: {'ON' if not cur else 'OFF'}")
        return render_adm_subscriptions(call)
    if data == "adm_sub_extend_prompt":
        USER_STATES[call.from_user.id] = {"flow": "await_adm_sub_extend"}
        bot.send_message(call.message.chat.id,
                         f"{G['settings']} {sc('Format')}: <code>uid days</code> {sc('(e.g.')} <code>12345 30</code>)",
                         parse_mode="HTML"); return
    if data == "adm_sub_history":
        USER_STATES[call.from_user.id] = {"flow": "await_adm_sub_history"}
        bot.send_message(call.message.chat.id,
                         f"{G['settings']} {sc('Send user ID to view subscription history')}:"); return
    if data == "adm_sub_run_downgrade":
        if not is_owner(call.from_user.id): ack(call, "Owner only"); return
        ack(call, "Running downgrade now…")
        threading.Thread(target=lambda: action_adm_downgrade_expired(call.from_user.id), daemon=True).start(); return

    ack(call, "?")


def render_adm_stats(call: types.CallbackQuery) -> None:
    d = db_load()
    users = d["users"]
    bots  = d["bots"]
    pays  = d["payments"]
    revenue = sum(p.get("amount", 0) for p in pays if p.get("status") == "approved")
    today_str = now_utc().strftime("%Y-%m-%d")
    new_today = sum(1 for u in users.values() if str(u.get("joined", "")).startswith(today_str))
    week_ago = now_utc() - timedelta(days=7)
    new_week = 0
    for u in users.values():
        try:
            if datetime.fromisoformat(str(u.get("joined")).replace("Z", "+00:00")) >= week_ago:
                new_week += 1
        except Exception:
            pass
    plan_counts: Dict[str, int] = defaultdict(int)
    for u in users.values():
        plan_counts[u.get("plan", "free")] += 1
    rss = 0
    if psutil is not None:
        try:
            rss = psutil.Process(os.getpid()).memory_info().rss
        except Exception:
            pass
    storage_size = 0
    for root, _, files in os.walk(BASE_DIR / "storage"):
        for f in files:
            try:
                storage_size += (Path(root) / f).stat().st_size
            except OSError:
                pass

    cap = (
        f"<b>{G['graph']} {sc('System Stats')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Total users',  len(users))}\n"
        f"{bullet('New today',    new_today)}\n"
        f"{bullet('New this week', new_week)}\n"
        f"{bullet('Total bots',   len(bots))}\n"
        f"{bullet('Bots running', sum(1 for x in RUNNING.values() if x['proc'].poll() is None))}\n"
        f"{bullet('Revenue',      '{}$'.format(revenue))}\n"
        f"{bullet('Storage',      fmt_bytes(storage_size))}\n"
        f"{bullet('Panel RSS',    fmt_bytes(rss))}\n"
        f"{bullet('Uptime',       fmt_dur(int(time.time() * 1000) - START_TS))}\n"
        f"{G['div']}\n"
        + "\n".join(f"{bullet(PLAN_LIMITS[p]['name'], n)}" for p, n in plan_counts.items())
        + FOOTER
    )
    show_menu(call.message.chat.id, PHOTOS["stats"], cap, back_admin_kb(), call=call)


def render_adm_users(call: types.CallbackQuery) -> None:
    d = db_load()["users"]
    items = sorted(d.values(), key=lambda u: u.get("joined", ""), reverse=True)[:20]
    rows = "\n".join(
        f"{G['bullet']} <code>{u['_id']}</code> — {esc(u.get('name'))} "
        f"(@{esc(u.get('username') or '—')}) "
        f"{G['bullet']} <i>{esc(PLAN_LIMITS.get(u.get('plan'), {}).get('name', u.get('plan')))}</i>"
        for u in items
    ) or f"<i>{sc('no users yet')}</i>"
    cap = (
        f"<b>{G['users']} {sc('Recent Users')} ({len(d)} {sc('total')})</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}\n"
        f"{sc('Send a numeric user id to look one up')}.{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_admin_finduser"}
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, back_admin_kb(), call=call)


def render_adm_allbots(call: types.CallbackQuery) -> None:
    # All bots from ALL PIDs (live) + DB. No local RUNNING — PIDs are truth.
    agg = _pid_fetch_all_bots()
    try:
        d = db_load_ro().get("bots", {}) or {}
    except Exception:
        d = {}
    for bid, b in (d.items() if isinstance(d, dict) else []):
        if bid not in agg:
            try:
                agg[bid] = {"vm_id": b.get("vm_id"), "live": None, "record": b}
            except Exception:
                pass
    items = list(agg.values())[:25]
    def _row(e: Dict[str, Any]) -> str:
        rec = e.get("record") or {}
        live = e.get("live") or {}
        bid = rec.get("_id") or live.get("bot_id") or "?"
        name = rec.get("name") or live.get("bot_id") or "?"
        owner = rec.get("owner") or "?"
        vm_id = e.get("vm_id") or rec.get("vm_id") or "?"
        status = (live.get("status") if isinstance(live, dict) else None) or rec.get("status") or "idle"
        icon = "run" if status == "running" else "idle"
        return (f"{G['bullet']} <code>{esc(bid)}</code> — {esc(name)} "
                f"{G['bullet']} <i>uid {esc(owner)}</i> "
                f"{G['bullet']} {esc(vm_id)} {G['bullet']} {icon}")
    rows = "\n".join(_row(e) for e in items) or f"<i>{sc('no bots')}</i>"
    cap = (
        f"<b>{G['diamond']} {sc('All Bots')} ({len(agg)})</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, back_admin_kb(), call=call)


def render_adm_payments(call: types.CallbackQuery) -> None:
    d = db_load()
    pays = [p for p in d["payments"] if p.get("status") == "pending"][-15:]
    rows = "\n".join(
        f"{G['bullet']} <code>{p['id']}</code> {G['bullet']} uid {p['uid']} "
        f"{G['bullet']} {esc(p.get('plan', '—'))} {G['bullet']} {esc(p.get('method'))}"
        for p in pays
    ) or f"<i>{sc('no pending payments')}</i>"
    cap = (
        f"<b>{G['wallet']} {sc('Pending Payments')}</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}\n"
        f"{sc('Tap a payment id from the inbox notification to approve or reject')}.{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, back_admin_kb(), call=call)


def render_adm_broadcast(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>{G['broadcast']} {sc('Broadcast')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Send the message text now')}.\n"
        f"<b>{sc('Optional prefix')}:</b>\n"
        f"  <code>plan:pro</code> — {sc('only pro users')}\n"
        f"  <code>plan:free</code> — {sc('only free users')}\n"
        f"  <code>at:YYYY-MM-DD HH:MM</code> — {sc('schedule')}\n"
        f"  {sc('Otherwise message goes to everyone now')}.{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_broadcast"}
    show_menu(call.message.chat.id, PHOTOS["broadcast"], cap, back_admin_kb(), call=call)


def render_adm_ban(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>{G['no']} {sc('Ban / Unban')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Send')} <code>ban &lt;user_id&gt; &lt;reason&gt;</code>\n"
        f"{sc('Send')} <code>unban &lt;user_id&gt;</code>{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_ban_cmd"}
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, back_admin_kb(), call=call)


def render_adm_giveplan(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>{G['plus']} {sc('Give Plan')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Send')} <code>&lt;user_id&gt; &lt;plan&gt; [days]</code>\n"
        f"{sc('Plans')}: {', '.join(PLAN_LIMITS.keys())}{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_giveplan"}
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, back_admin_kb(), call=call)


def render_adm_coupons(call: types.CallbackQuery) -> None:
    d = db_load()["coupons"]
    rows = "\n".join(
        f"{G['bullet']} <code>{esc(code)}</code> — {esc(c.get('percent'))}% "
        f"{G['bullet']} {esc(c.get('uses_left'))} {sc('uses left')}"
        for code, c in d.items()
    ) or f"<i>{sc('no coupons yet')}</i>"
    cap = (
        f"<b>{G['key']} {sc('Coupons')}</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}\n"
        f"{sc('Send')} <code>add CODE PERCENT USES</code> {sc('to create')}.\n"
        f"{sc('Send')} <code>del CODE</code> {sc('to remove')}.{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_coupon_admin"}
    show_menu(call.message.chat.id, PHOTOS["coupon"], cap, back_admin_kb(), call=call)


def render_adm_tickets(call: types.CallbackQuery) -> None:
    d = db_load()["tickets"]
    open_t = [t for t in d.values() if t.get("status") == "open"][-15:]
    rows = "\n".join(
        f"{G['bullet']} <code>{t['id']}</code> uid {t['uid']} — {esc(t.get('subject'))[:40]}"
        for t in open_t
    ) or f"<i>{sc('no open tickets')}</i>"
    cap = (
        f"<b>{G['ticket']} {sc('Open Tickets')}</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup()
    for t in open_t:
        kb.add(Btn(
            f"{G['eye']}  #{t['id']}", callback_data=f"ticket_view_{t['id']}"))
    kb.add(Btn(
        f"{G['back']}  {sc('Admin')}", callback_data="menu_admin"))
    show_menu(call.message.chat.id, PHOTOS["ticket"], cap, kb, call=call)


def render_adm_admins(call: types.CallbackQuery) -> None:
    if not is_owner(call.from_user.id):
        ack(call, "Owner only"); return
    d = db_load()["admins"]
    rows = "\n".join(
        f"{G['bullet']} <code>{uid}</code> — {esc(a.get('role'))}"
        for uid, a in d.items()
    ) or f"<i>{sc('no extra admins yet')}</i>"
    cap = (
        f"<b>{G['shield']} {sc('Admins')}</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}\n"
        f"{sc('Send')} <code>add &lt;uid&gt; &lt;role&gt;</code>\n"
        f"  {sc('Roles')}: <code>view-only</code>, <code>manage-users</code>, <code>full-access</code>\n"
        f"{sc('Send')} <code>del &lt;uid&gt;</code>{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_admin_admins"}
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, back_admin_kb(), call=call)


def render_adm_audit(call: types.CallbackQuery) -> None:
    d = db_load()["audit"][-25:]
    rows = "\n".join(
        f"{G['bullet']} {esc(a['ts'][11:19])} uid {a['uid']} → {esc(a['action'])} {esc(a.get('detail', ''))[:60]}"
        for a in reversed(d)
    ) or f"<i>{sc('no audit entries yet')}</i>"
    cap = (
        f"<b>{G['eye']} {sc('Recent Audit')}</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["security"], cap, back_admin_kb(), call=call)


def render_adm_pending(call: types.CallbackQuery) -> None:
    """List of bot uploads waiting for approval. Each row links back
    to a quick approve / reject pair for that upload."""
    if not admin_only_call(call, "approve_payment"):
        return
    items = pending_list()
    if not items:
        cap = (
            f"<b>{G['eye']} {sc('Pending Uploads')}</b>\n"
            f"{G['div_eq']}\n<i>{sc('Inbox is empty — nothing waiting for approval')}.</i>\n"
            f"{G['div']}{FOOTER}"
        )
        show_menu(call.message.chat.id, PHOTOS["admin"], cap, back_admin_kb(), call=call)
        return
    rows = []
    kb = types.InlineKeyboardMarkup(row_width=2)
    for bid, info in items[:15]:
        b = find_bot(bid)
        nm = (b or {}).get("name") or info.get("file_name") or bid
        rows.append(
            f"{G['bullet']} <code>{esc(bid)}</code> — {esc(nm)} "
            f"{G['bullet']} uid {info.get('user_id')} "
            f"{G['bullet']} {fmt_bytes(info.get('size', 0))}"
        )
        kb.add(
            Btn(f"{G['ok']}  {sc('OK')} {esc(nm)[:18]}",
                                       callback_data=f"appr_ok_{bid}"),
            Btn(f"{G['no']}  {sc('No')} {esc(nm)[:18]}",
                                       callback_data=f"appr_no_{bid}"),
        )
    kb.add(Btn(
        f"{G['back']}  {sc('Admin')}", callback_data="menu_admin"))
    cap = (
        f"<b>{G['eye']} {sc('Pending Uploads')} ({len(items)})</b>\n"
        f"{G['div_eq']}\n" + "\n".join(rows) + f"\n{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


def render_adm_photos(call: types.CallbackQuery) -> None:
    """List every menu photo key. Tapping one prompts the admin to
    send a fresh photo, which replaces that banner."""
    if not is_owner(call.from_user.id) and not admin_can(call.from_user.id, "manage_admins"):
        # Allow only owner / full-access admins to change branding.
        ack(call, "Owner / full-access only.")
        return
    cap = (
        f"<b>{G['upload']} {sc('Menu Photos')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Tap any menu below, then send a photo to replace its banner')}.\n"
        f"{sc('Photos are saved locally and synced to GitHub on next backup')}.\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    items = sorted(PHOTO_KEYS_FRIENDLY.items())
    pairs: List[types.InlineKeyboardButton] = []
    for key, label in items:
        if key not in _PHOTO_SPECS:
            continue
        pairs.append(Btn(
            f"{G['cog']}  {sc(label)}", callback_data=f"adm_photo_{key}"))
    # 2 per row
    for i in range(0, len(pairs), 2):
        kb.add(*pairs[i:i + 2])
    kb.add(Btn(
        f"{G['back']}  {sc('Admin')}", callback_data="menu_admin"))
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


def render_adm_photo_one(call: types.CallbackQuery, key: str) -> None:
    """Prompt the admin to send the next photo as the banner for `key`."""
    if not is_owner(call.from_user.id) and not admin_can(call.from_user.id, "manage_admins"):
        ack(call, "Owner / full-access only.")
        return
    if key not in _PHOTO_SPECS:
        ack(call, "Unknown photo key.")
        return
    USER_STATES[call.from_user.id] = {"flow": "await_admin_photo", "photo_key": key}
    label = PHOTO_KEYS_FRIENDLY.get(key, key)
    cap = (
        f"<b>{G['upload']} {sc('Replace banner')}: {esc(label)}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Send the new photo now (as a photo, not a file)')}.\n"
        f"{sc('Send /cancel to abort')}.\n"
        f"{G['div']}{FOOTER}"
    )
    # Show the current banner so the admin sees what they're replacing.
    cur = PHOTOS.get(key) or PHOTOS.get("admin", "")
    show_menu(call.message.chat.id, cur, cap, back_admin_kb(), call=call)


def render_adm_github(call: types.CallbackQuery) -> None:
    s = gh_status()
    cap = (
        f"<b>{G['cog']} {sc('GitHub Backup')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Configured', 'Yes' if s['enabled'] else 'No')}\n"
        f"{bullet('Repo',       s['repo'] or '—')}\n"
        f"{bullet('Branch',     s['branch'])}\n"
        f"{bullet('Interval',   '{} min'.format(s['intervalMin']))}\n"
        f"{bullet('Auto',       'On' if s['autoEnabled'] else 'Off')}\n"
        f"{bullet('Last',       fmt_ts(s['lastBackup']))}\n"
        f"{bullet('Last err',   s['lastError'] or '—')}\n"
        f"{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["github"], cap, github_kb(s), call=call)


def render_github_subroute(call: types.CallbackQuery, data: str) -> None:
    if data == "gh_backup_now":
        threading.Thread(target=lambda: _gh_backup_thread(call), daemon=True).start()
        ack(call, "Backup started"); return
    if data == "gh_restore_now":
        threading.Thread(target=lambda: _gh_restore_thread(call), daemon=True).start()
        ack(call, "Restore started"); return
    if data == "gh_toggle_auto":
        GH["autoEnabled"] = not GH["autoEnabled"]
        set_setting("github_auto_enabled", GH["autoEnabled"])
        ack(call, f"Auto: {'ON' if GH['autoEnabled'] else 'OFF'}")
        render_adm_github(call); return
    if data == "gh_set_token":
        USER_STATES[call.from_user.id] = {"flow": "await_gh_token"}
        bot.send_message(call.message.chat.id, f"{G['key']} {sc('Send the GitHub token now')} (Tᴇxᴛ)."); return
    if data == "gh_set_repo":
        USER_STATES[call.from_user.id] = {"flow": "await_gh_repo"}
        bot.send_message(call.message.chat.id, f"{G['diamond']} {sc('Send the repo as')} <code>Oᴡɴᴇʀ/repo</code>.", parse_mode="HTML"); return
    if data == "gh_set_branch":
        USER_STATES[call.from_user.id] = {"flow": "await_gh_branch"}
        bot.send_message(call.message.chat.id, f"{G['tri']} {sc('Send the branch name')}."); return
    if data == "gh_set_interval":
        USER_STATES[call.from_user.id] = {"flow": "await_gh_interval"}
        bot.send_message(call.message.chat.id, f"{G['cog']} {sc('Send interval in minutes (>=15)')}."); return
    if data == "gh_clear":
        gh_set_config({"token": "", "repo": "", "branch": "main", "intervalMin": 360})
        gh_load_config()
        ack(call, "Cleared")
        render_adm_github(call); return
    ack(call, "?")


def _gh_backup_thread(call: types.CallbackQuery) -> None:
    res = gh_backup_now()
    msg = (f"{G['ok']} {sc('backup ok')} ({res.get('sizeMB')} MB)"
           if res["ok"] else f"{G['no']} {esc(res.get('error'))}")
    try:
        bot.send_message(call.message.chat.id, msg)
    except Exception:
        pass


def _gh_restore_thread(call: types.CallbackQuery) -> None:
    res = gh_restore_now(overwrite=True)
    msg = (f"{G['ok']} {sc('restore ok')} ({fmt_bytes(res.get('sizeBytes', 0))})"
           if res["ok"] else f"{G['no']} {esc(res.get('error'))}")
    try:
        bot.send_message(call.message.chat.id, msg)
    except Exception:
        pass


def render_adm_security(call: types.CallbackQuery) -> None:
    d = db_load()
    cap = (
        f"<b>{G['lock']} {sc('Security')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Banned users', sum(1 for u in d['users'].values() if u.get('banned')))}\n"
        f"{bullet('Rate violators', sum(1 for n in d.get('rate_violations', {}).values() if int(n) > 0))}\n"
        f"{bullet('Encryption',   'Fernet (AES-128-CBC) per file')}\n"
        f"{bullet('Key storage',  'GitHub' if KEYRING.gh_enabled() else 'Local cache')}\n"
        f"{bullet('Path-traversal','blocked (safe_path_join)')}\n"
        f"{bullet('Secret env strip','active')}\n"
        f"{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["security"], cap, back_admin_kb(), call=call)


def render_adm_maintenance(call: types.CallbackQuery) -> None:
    cur = bool(get_setting("maintenance", False))
    cap = (
        f"<b>{G['warn']} {sc('Maintenance Mode')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('State', 'ON' if cur else 'OFF')}\n"
        f"{sc('When ON, only admins can use the bot')}.{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup()
    label = "Turn OFF" if cur else "Turn ON"
    kb.add(Btn(
        f"{G['refresh']}  {sc(label)}", callback_data="adm_maint_toggle",
        style="danger" if cur else "success"))
    kb.add(Btn(
        f"{G['back']}  {sc('Admin')}", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS["maint"], cap, kb, call=call)


def render_adm_settings(call: types.CallbackQuery) -> None:
    running_n = sum(1 for x in RUNNING.values() if x['proc'].poll() is None)
    total_bots = len(db_load_ro()['bots'])
    cap = (
        f"<b>{G['settings']} {sc('Settings & Advanced')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Brand',          BRAND_TAG)}\n"
        f"{bullet('Owner ID',       OWNER_ID)}\n"
        f"{bullet('Announce chan',  ANNOUNCE_CHANNEL or '—')}\n"
        f"{bullet('Keep-alive port', KEEPALIVE_PORT)}\n"
        f"{bullet('GitHub keys',    'GitHub' if KEYRING.gh_enabled() else 'Local cache')}\n"
        f"{bullet('GitHub backup',  'On' if gh_enabled() and GH['autoEnabled'] else 'Off')}\n"
        f"{bullet('Bots running',   f'{running_n} / {total_bots}')}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    # ── live tunables ───────────────────────────────────────────────
    kb.add(
        Btn(f"{G['settings']}  {sc('Edit Brand')}",
            callback_data="adm_set_brand",   style="primary"),
        Btn(f"{G['broadcast']}  {sc('Announce Chan')}",
            callback_data="adm_set_announce", style="primary"),
    )
    kb.add(
        Btn(f"{G['shield']}  {sc('Transfer Owner')}",
            callback_data="adm_set_owner",   style="primary"),
        Btn(f"{G['diamond']}  {sc('Plans Editor')}",
            callback_data="adm_set_plans",   style="primary"),
    )
    # ── ops actions ─────────────────────────────────────────────────
    kb.add(
        Btn(f"{G['refresh']}  {sc('Reload Caches')}",
            callback_data="adm_set_reload",  style="success"),
        Btn(f"{G['eye']}  {sc('System Info')}",
            callback_data="adm_set_sysinfo", style="primary"),
    )
    kb.add(
        Btn(f"{G['refresh']}  {sc('Restart All Bots')}",
            callback_data="adm_set_restart_all", style="success"),
        Btn(f"{G['no']}  {sc('Stop All Bots')}",
            callback_data="adm_set_stop_all",    style="danger"),
    )
    kb.add(
        Btn(f"{G['warn']}  {sc('Clean Orphans')}",
            callback_data="adm_set_clean_orphans", style="danger"),
        Btn(f"{G['upload']}  {sc('Export Data')}",
            callback_data="adm_set_export",        style="primary"),
    )
    kb.add(Btn(f"{G['back']}  {sc('Admin')}", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


# ───────────────────────────────────────────────────────────────────
#  Advanced settings — sub-renderers + handlers
# ───────────────────────────────────────────────────────────────────

def _set_back_kb() -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup()
    kb.add(Btn(
        f"{G['back']}  {sc('Settings')}", callback_data="adm_settings"))
    return kb


def render_adm_sysinfo(call: types.CallbackQuery) -> None:
    """Live system info — RAM, disk, uptime, child processes."""
    rss = vms = pct = 0
    if psutil is not None:
        try:
            p = psutil.Process(os.getpid())
            mi = p.memory_info()
            rss, vms = mi.rss, mi.vms
            pct = p.cpu_percent(interval=0.2)
        except Exception:
            pass
    storage_size = 0
    storage_files = 0
    for root, _, files in os.walk(BASE_DIR / "storage"):
        for f in files:
            try:
                storage_size += (Path(root) / f).stat().st_size
                storage_files += 1
            except OSError:
                pass
    sandbox_size = 0
    sandbox_dirs = 0
    sandbox_root = BASE_DIR / "sandbox"
    if sandbox_root.exists():
        for entry in sandbox_root.iterdir():
            if entry.is_dir():
                sandbox_dirs += 1
                for root, _, files in os.walk(entry):
                    for f in files:
                        try:
                            sandbox_size += (Path(root) / f).stat().st_size
                        except OSError:
                            pass
    up_secs = int(time.time() - START_TIME) if "START_TIME" in globals() else 0
    days, rem = divmod(up_secs, 86400)
    hours, rem = divmod(rem, 3600)
    mins, _ = divmod(rem, 60)
    running_n = sum(1 for x in RUNNING.values() if x['proc'].poll() is None)
    cap = (
        f"<b>{G['eye']} {sc('System Info')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Uptime',       f'{days}d {hours}h {mins}m')}\n"
        f"{bullet('Panel RSS',    f'{rss / 1024 / 1024:.1f} MB')}\n"
        f"{bullet('Panel VMS',    f'{vms / 1024 / 1024:.1f} MB')}\n"
        f"{bullet('CPU sample',   f'{pct:.1f}%')}\n"
        f"{bullet('Bots live',    running_n)}\n"
        f"{bullet('Storage',      f'{storage_size / 1024 / 1024:.1f} MB ({storage_files} files)')}\n"
        f"{bullet('Sandboxes',    f'{sandbox_dirs} dirs, {sandbox_size / 1024 / 1024:.1f} MB')}\n"
        f"{bullet('Cache entries', len(_DB_CACHE))}\n"
        f"{bullet('PID',          os.getpid())}\n"
        f"{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, _set_back_kb(), call=call)


def render_adm_plans(call: types.CallbackQuery) -> None:
    """Live plan editor — adjust max_bots per plan tier."""
    rows = []
    for k, v in PLAN_LIMITS.items():
        live = int(get_setting(f"plan_max_bots_{k}", v["max_bots"]))
        rows.append(f"{bullet(v['name'], f'max_bots = {live}')}")
    cap = (
        f"<b>{G['diamond']} {sc('Plans Editor')}</b>\n"
        f"{G['div_eq']}\n"
        + "\n".join(rows) + "\n"
        f"{G['div']}\n"
        f"<i>{sc('Tap a plan to bump its bot quota')}.</i>{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=3)
    for k, v in PLAN_LIMITS.items():
        live = int(get_setting(f"plan_max_bots_{k}", v["max_bots"]))
        kb.add(
            Btn(f"➖ {sc(v['name'])}",
                                       callback_data=f"adm_set_plan_dec_{k}"),
            Btn(f"{live}",
                                       callback_data=f"adm_set_plan_show_{k}"),
            Btn(f"➕ {sc(v['name'])}",
                                       callback_data=f"adm_set_plan_inc_{k}"),
        )
    kb.add(Btn(
        f"{G['refresh']}  {sc('Reset Defaults')}",
        callback_data="adm_set_plans_reset"))
    kb.add(Btn(
        f"{G['back']}  {sc('Settings')}", callback_data="adm_settings"))
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


def render_adm_confirm(call: types.CallbackQuery, action: str, label: str) -> None:
    cap = (
        f"<b>{G['warn']} {sc('Confirm')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('You are about to')}: <b>{esc(label)}</b>.\n"
        f"{sc('This affects every running bot. Continue')}?{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn(f"{G['ok']}  {sc('Yes, do it')}",
                                   callback_data=f"{action}_yes"),
        Btn(f"{G['no']}  {sc('Cancel')}",
                                   callback_data="adm_settings"),
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


def render_adm_confirm_custom(call: types.CallbackQuery, action: str,
                              label: str, back_cb: str = "menu_admin") -> None:
    cap = (
        f"<b>{G['warn']} {sc('Confirm')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('You are about to')}: <b>{esc(label)}</b>.\n"
        f"{sc('Are you sure')}?{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn(f"{G['ok']}  {sc('Yes')}",    callback_data=action,  style="danger"),
        Btn(f"{G['no']}  {sc('Cancel')}", callback_data=back_cb, style="primary"),
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


# ═══════════════════════════════════════════════════════════════════
#  ADVANCED ADMIN SUB-PANELS  (35+ new features)
# ═══════════════════════════════════════════════════════════════════

def _adm_back(dest: str = "menu_admin") -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup()
    kb.add(Btn(f"{G['back']}  {sc('Back')}", callback_data=dest, style="primary"))
    return kb


# ─── 1. ANALYTICS ────────────────────────────────────────────────────────────

def render_adm_analytics(call: types.CallbackQuery) -> None:
    d = db_load()
    total_rev = sum(p.get("amount", 0) for p in d["payments"] if p.get("status") == "approved")
    running_n = sum(1 for x in RUNNING.values() if x["proc"].poll() is None)
    cap = (
        f"<b>📊 {sc('Analytics Dashboard')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Total Revenue',   f'{total_rev}৳')}\n"
        f"{bullet('Total Users',     len(d['users']))}\n"
        f"{bullet('Total Bots',      len(d['bots']))}\n"
        f"{bullet('Bots Running',    running_n)}\n"
        f"{G['div']}\n{sc('Choose a report below')}.{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("📈  Rᴇᴠᴇɴᴜᴇ Rᴇᴘᴏʀᴛ",  callback_data="adm_revenue_report", style="success"),
        Btn("📉  Gʀᴏᴡᴛʜ Sᴛᴀᴛꜱ",    callback_data="adm_growth_stats",   style="primary"),
    )
    kb.add(
        Btn("🏆  Tᴏᴘ Uꜱᴇʀꜱ",       callback_data="adm_top_users",      style="primary"),
        Btn("🥧  Pʟᴀɴ Dɪꜱᴛ",       callback_data="adm_plan_dist",      style="primary"),
    )
    kb.add(
        Btn("🤖  Bᴏᴛ Aᴄᴛɪᴠɪᴛʏ",   callback_data="adm_bot_activity",   style="primary"),
        Btn("📊  Sᴛᴀᴛꜱ Oᴠᴇʀᴠɪᴇᴡ",  callback_data="adm_stats",          style="primary"),
    )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


def render_adm_revenue_report(call: types.CallbackQuery) -> None:
    pays = db_load()["payments"]
    now = now_utc()
    today   = now.strftime("%Y-%m-%d")
    week_ago = (now - timedelta(days=7)).strftime("%Y-%m-%d")
    month_ago = (now - timedelta(days=30)).strftime("%Y-%m-%d")
    def _sum(since: str) -> float:
        return sum(p.get("amount", 0) for p in pays
                   if p.get("status") == "approved" and str(p.get("ts", "")) >= since)
    rev_day   = _sum(today)
    rev_week  = _sum(week_ago)
    rev_month = _sum(month_ago)
    rev_all   = sum(p.get("amount", 0) for p in pays if p.get("status") == "approved")
    plan_rev: Dict[str, float] = defaultdict(float)
    for p in pays:
        if p.get("status") == "approved":
            plan_rev[p.get("plan", "unknown")] += p.get("amount", 0)
    by_plan = "\n".join(f"{bullet(k, f'{v}৳')}" for k, v in sorted(plan_rev.items()))
    cap = (
        f"<b>📈 {sc('Revenue Report')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Today',        f'{rev_day}৳')}\n"
        f"{bullet('Last 7 days',  f'{rev_week}৳')}\n"
        f"{bullet('Last 30 days', f'{rev_month}৳')}\n"
        f"{bullet('All time',     f'{rev_all}৳')}\n"
        f"{G['div']}\n<b>{sc('By Plan')}:</b>\n{by_plan}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, _adm_back("adm_analytics"), call=call)


def render_adm_growth_stats(call: types.CallbackQuery) -> None:
    users = db_load()["users"].values()
    now = now_utc()
    def _count(days: int) -> int:
        since = (now - timedelta(days=days)).strftime("%Y-%m-%d")
        return sum(1 for u in users if str(u.get("joined", "")) >= since)
    bar = lambda n, mx: "█" * int(n / max(mx, 1) * 10) + "░" * (10 - int(n / max(mx, 1) * 10))
    d1, d7, d30, all_ = _count(1), _count(7), _count(30), len(list(users))
    cap = (
        f"<b>📉 {sc('User Growth')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Today',        f'{d1}  {bar(d1, d30)}')}\n"
        f"{bullet('Last 7 days',  f'{d7}  {bar(d7, all_)}')}\n"
        f"{bullet('Last 30 days', f'{d30}  {bar(d30, all_)}')}\n"
        f"{bullet('Total users',  all_)}\n"
        f"{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, _adm_back("adm_analytics"), call=call)


def render_adm_top_users(call: types.CallbackQuery) -> None:
    d = db_load()
    pays = d["payments"]
    spend: Dict[str, float] = defaultdict(float)
    for p in pays:
        if p.get("status") == "approved":
            spend[str(p.get("uid", ""))] += p.get("amount", 0)
    top = sorted(spend.items(), key=lambda x: x[1], reverse=True)[:10]
    rows = []
    for i, (uid, amt) in enumerate(top, 1):
        u = d["users"].get(uid, {})
        name = esc(u.get("name") or uid)
        bot_count = sum(1 for b in d["bots"].values() if str(b.get("owner")) == uid)
        rows.append(f"{i}. {name} — <b>{amt}৳</b> {G['bullet']} {bot_count} bots")
    cap = (
        f"<b>🏆 {sc('Top Users by Spending')}</b>\n"
        f"{G['div_eq']}\n"
        + ("\n".join(rows) or f"<i>{sc('No payments yet')}</i>")
        + FOOTER
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, _adm_back("adm_analytics"), call=call)


def render_adm_plan_dist(call: types.CallbackQuery) -> None:
    users = list(db_load()["users"].values())
    total = max(len(users), 1)
    counts: Dict[str, int] = defaultdict(int)
    for u in users:
        counts[u.get("plan", "free")] += 1
    bar = lambda n: "█" * int(n / total * 12) + "░" * (12 - int(n / total * 12))
    rows = "\n".join(
        f"{bullet(PLAN_LIMITS.get(p, {}).get('name', p), f'{n} ({n*100//total}%) {bar(n)}')}"
        for p, n in sorted(counts.items(), key=lambda x: x[1], reverse=True)
    )
    cap = (
        f"<b>🥧 {sc('Plan Distribution')}</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, _adm_back("adm_analytics"), call=call)


def render_adm_bot_activity(call: types.CallbackQuery) -> None:
    bots = list(db_load()["bots"].values())
    total   = len(bots)
    running = sum(1 for x in RUNNING.values() if x["proc"].poll() is None)
    stopped = total - running
    crashed = sum(1 for b in bots if b.get("last_exit_code") not in (None, 0, ""))
    never   = sum(1 for b in bots if not b.get("last_started"))
    bar = lambda n: "█" * int(n / max(total, 1) * 10)
    cap = (
        f"<b>🤖 {sc('Bot Activity')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Total bots',   total)}\n"
        f"{bullet('▶ Running',    f'{running}  {bar(running)}')}\n"
        f"{bullet('⏹ Stopped',    f'{stopped}  {bar(stopped)}')}\n"
        f"{bullet('💥 Crashed',   f'{crashed}  {bar(crashed)}')}\n"
        f"{bullet('⬜ Never run', never)}\n"
        f"{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, _adm_back("adm_analytics"), call=call)


# ─── 2. USER TOOLS ───────────────────────────────────────────────────────────

def render_adm_user_tools(call: types.CallbackQuery) -> None:
    d = db_load()
    banned_n = sum(1 for u in d["users"].values() if u.get("banned"))
    cap = (
        f"<b>👥 {sc('User Tools')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Total users', len(d['users']))}\n"
        f"{bullet('Banned',      banned_n)}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("🔍  Sᴇᴀʀᴄʜ Uꜱᴇʀ",    callback_data="adm_user_search",     style="primary"),
        Btn("🚫  Bᴀɴɴᴇᴅ Lɪꜱᴛ",    callback_data="adm_banned_list",     style="danger"),
    )
    kb.add(
        Btn("💰  Wᴀʟʟᴇᴛ Aᴅᴊᴜꜱᴛ",  callback_data="adm_wallet_admin",    style="success"),
        Btn("📤  Exᴘᴏʀᴛ CSV",      callback_data="adm_user_export_csv", style="primary"),
    )
    kb.add(
        Btn("📨  Nᴏᴛɪꜰʏ Uꜱᴇʀ",    callback_data="adm_notify_user",     style="primary"),
        Btn("🔄  Rᴇꜱᴇᴛ Uꜱᴇʀ",     callback_data="adm_user_reset",      style="danger"),
    )
    kb.add(
        Btn("🎁  Gɪᴠᴇ Pʟᴀɴ",      callback_data="adm_giveplan",        style="success"),
        Btn("🚫  Bᴀɴ/Uɴʙᴀɴ",      callback_data="adm_ban",             style="danger"),
    )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


def render_adm_user_search(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>🔍 {sc('Search User')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Send a user ID, @username or part of their name')}.{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_adm_user_search"}
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, _adm_back("adm_user_tools"), call=call)


def render_adm_banned_list(call: types.CallbackQuery) -> None:
    users = db_load()["users"]
    banned = [(uid, u) for uid, u in users.items() if u.get("banned")]
    rows = "\n".join(
        f"{G['bullet']} <code>{uid}</code> — {esc(u.get('name','?'))} "
        f"({esc(u.get('ban_reason','—'))})"
        for uid, u in banned[:20]
    ) or f"<i>{sc('No banned users')}</i>"
    cap = (
        f"<b>🚫 {sc('Banned Users')} ({len(banned)})</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, _adm_back("adm_user_tools"), call=call)


def render_adm_wallet_admin(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>💰 {sc('Adjust User Wallet')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Send')}: <code>&lt;user_id&gt; +amount</code> {sc('to add')}\n"
        f"{sc('Send')}: <code>&lt;user_id&gt; -amount</code> {sc('to deduct')}\n"
        f"{sc('Send')}: <code>&lt;user_id&gt; =amount</code> {sc('to set exact')}{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_adm_wallet_adjust"}
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, _adm_back("adm_user_tools"), call=call)


def render_adm_user_export_csv(call: types.CallbackQuery) -> None:
    if not is_owner(call.from_user.id):
        ack(call, "Owner only"); return
    ack(call, "Building CSV…")
    def _bg() -> None:
        try:
            d = db_load()
            lines = ["id,name,username,plan,joined,bots,wallet,banned"]
            bots_by_owner: Dict[str, int] = defaultdict(int)
            for b in d["bots"].values():
                bots_by_owner[str(b.get("owner", ""))] += 1
            for uid, u in d["users"].items():
                lines.append(",".join(str(x).replace(",", " ") for x in [
                    uid,
                    u.get("name", ""),
                    u.get("username", ""),
                    u.get("plan", "free"),
                    str(u.get("joined", ""))[:10],
                    bots_by_owner.get(uid, 0),
                    u.get("wallet", 0),
                    "yes" if u.get("banned") else "no",
                ]))
            csv_bytes = "\n".join(lines).encode("utf-8")
            tmp = Path(tempfile.mktemp(suffix="_users.csv"))
            tmp.write_bytes(csv_bytes)
            with tmp.open("rb") as fh:
                bot.send_document(
                    call.from_user.id, fh,
                    caption=f"{G['ok']} {sc('Users CSV')} ({len(d['users'])} rows)",
                    visible_file_name="users_export.csv")
            tmp.unlink(missing_ok=True)
        except Exception as e:
            try:
                bot.send_message(call.from_user.id,
                                 f"{G['no']} CSV error: <code>{esc(e)}</code>",
                                 parse_mode="HTML")
            except Exception:
                pass
    threading.Thread(target=_bg, daemon=True).start()


def render_adm_notify_user(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>📨 {sc('Notify Specific User')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Send')}: <code>&lt;user_id&gt; Your message here</code>{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_adm_notify_user"}
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, _adm_back("adm_user_tools"), call=call)


def render_adm_user_reset_prompt(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>🔄 {sc('Reset User')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('This will stop all bots, delete bot records, and reset plan to free')}.\n"
        f"{sc('Send')}: <code>&lt;user_id&gt;</code> {sc('to reset')}.{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_adm_user_reset"}
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, _adm_back("adm_user_tools"), call=call)


# ─── 3. BOT MANAGER ──────────────────────────────────────────────────────────

def render_adm_bot_manager(call: types.CallbackQuery) -> None:
    bots = db_load()["bots"]
    running_n = sum(1 for x in RUNNING.values() if x["proc"].poll() is None)
    crashed_n = sum(1 for b in bots.values()
                    if b.get("last_exit_code") not in (None, 0, "") and
                    b["_id"] not in RUNNING)
    cap = (
        f"<b>🤖 {sc('Bot Manager')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Total bots',  len(bots))}\n"
        f"{bullet('Running',     running_n)}\n"
        f"{bullet('Crashed',     crashed_n)}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("💥  Cʀᴀꜱʜᴇᴅ Bᴏᴛꜱ",     callback_data="adm_crashed_bots",        style="danger"),
        Btn("🔄  Rᴇꜱᴛᴀʀᴛ Sᴛᴏᴘᴘᴇᴅ",   callback_data="adm_mass_restart_stopped", style="success"),
    )
    kb.add(
        Btn("🔍  Sᴇᴀʀᴄʜ Bᴏᴛ",        callback_data="adm_bot_search",          style="primary"),
        Btn("📦  Sɪᴢᴇ Rᴇᴘᴏʀᴛ",       callback_data="adm_bot_size_report",     style="primary"),
    )
    kb.add(
        Btn("🧪  AI Sᴄᴀɴ Pᴇɴᴅɪɴɢ",   callback_data="adm_force_scan_all",      style="primary"),
        Btn("📋  Aʟʟ Bᴏᴛꜱ",          callback_data="adm_allbots",             style="primary"),
    )
    kb.add(
        Btn("🔴  Kɪʟʟ Aʟʟ Nᴏᴡ",     callback_data="adm_kill_all_now",        style="danger"),
        Btn("🗑️  Cʟᴇᴀɴ Oʀᴘʜᴀɴꜱ",    callback_data="adm_set_clean_orphans",   style="danger"),
    )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


def render_adm_crashed_bots(call: types.CallbackQuery) -> None:
    bots = db_load()["bots"].values()
    crashed = [b for b in bots
               if b.get("last_exit_code") not in (None, 0, "")
               and b["_id"] not in RUNNING]
    rows = "\n".join(
        f"{G['bullet']} <code>{b['_id']}</code> {esc(b['name'][:20])} "
        f"— exit <b>{b.get('last_exit_code')}</b> "
        f"uid {b.get('owner')}"
        for b in crashed[:20]
    ) or f"<i>{sc('No crashed bots')}</i>"
    cap = (
        f"<b>💥 {sc('Crashed Bots')} ({len(crashed)})</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, _adm_back("adm_bot_manager"), call=call)


def render_adm_mass_restart_stopped(call: types.CallbackQuery) -> None:
    stopped = [b for b in db_load()["bots"].values()
               if b["_id"] not in RUNNING
               and b.get("approval_status") != "pending"
               and b.get("status") != "stopped"]
    cap = (
        f"<b>🔄 {sc('Mass Restart Stopped Bots')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Eligible bots', len(stopped))}\n"
        f"{sc('This will try to start all idle/crashed bots')}.\n"
        f"{sc('Continue')}?{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn(f"{G['ok']}  {sc('Yes, Start All')}", callback_data="adm_mass_restart_stopped_yes", style="success"),
        Btn(f"{G['no']}  {sc('Cancel')}",          callback_data="adm_bot_manager",              style="primary"),
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


def action_adm_mass_restart_stopped(call: types.CallbackQuery) -> None:
    ack(call, "Starting bots…")
    def _bg() -> None:
        ok = fail = 0
        for b in list(db_load()["bots"].values()):
            if b["_id"] in RUNNING:
                continue
            if b.get("approval_status") in ("pending", "rejected"):
                continue
            try:
                r = start_child(b)
                if r.get("ok"):
                    ok += 1
                else:
                    fail += 1
            except Exception:
                fail += 1
        audit(call.from_user.id, "mass_restart_stopped", f"ok={ok} fail={fail}")
        try:
            bot.send_message(call.from_user.id,
                             f"{G['ok']} {sc('Mass restart done')}: {ok} started, {fail} failed.")
        except Exception:
            pass
    threading.Thread(target=_bg, daemon=True).start()


def render_adm_bot_search(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>🔍 {sc('Search Bot')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Send a bot name or bot ID to find it')}.{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_adm_bot_search"}
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, _adm_back("adm_bot_manager"), call=call)


def render_adm_bot_size_report(call: types.CallbackQuery) -> None:
    bots = db_load()["bots"].values()
    usage: List[Tuple[float, str, str]] = []
    sandbox_root = BASE_DIR / "sandbox"
    for b in bots:
        bot_dir = Path(b.get("dir", ""))
        total = 0
        if bot_dir.exists():
            for root, _, files in os.walk(bot_dir):
                for f in files:
                    try:
                        total += (Path(root) / f).stat().st_size
                    except OSError:
                        pass
        usage.append((total, b["_id"], b.get("name", "?")))
    usage.sort(reverse=True)
    rows = "\n".join(
        f"{G['bullet']} {esc(name[:20])} — <b>{fmt_bytes(size)}</b>"
        for size, _, name in usage[:15]
    ) or f"<i>{sc('No sandboxes found')}</i>"
    total_all = sum(s for s, _, _ in usage)
    cap = (
        f"<b>📦 {sc('Bot Storage Report')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Total storage', fmt_bytes(total_all))}\n"
        f"{bullet('Bot count',     len(usage))}\n"
        f"{G['div']}\n{rows}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, _adm_back("adm_bot_manager"), call=call)


def action_adm_force_scan_all(call: types.CallbackQuery) -> None:
    ack(call, "Scanning pending bots with AI…")
    def _bg() -> None:
        pending = pending_list()
        scanned = flagged = 0
        results = []
        for bid, info in pending[:5]:
            b = find_bot(bid)
            if not b or not b.get("enc_files"):
                continue
            scanned += 1
            try:
                files_added = [(r, cipher_decrypt(enc)) for r, enc in
                               list(b["enc_files"].items())[:3]]
                result = _run_security_scan(files_added)
                verdict = result.get("verdict", "SAFE")
                if verdict in ("DANGEROUS", "SUSPICIOUS"):
                    flagged += 1
                    results.append(f"⚠️ {b['name'][:20]}: {verdict}")
                else:
                    results.append(f"✅ {b['name'][:20]}: SAFE")
            except Exception as e:
                results.append(f"❌ {bid[:8]}: error")
        summary = "\n".join(results) or "No pending bots to scan."
        audit(call.from_user.id, "force_scan_all", f"scanned={scanned} flagged={flagged}")
        try:
            bot.send_message(
                call.from_user.id,
                f"<b>🧪 {sc('AI Scan Report')}</b>\n"
                f"{G['div_eq']}\n"
                f"{bullet('Scanned', scanned)}\n"
                f"{bullet('Flagged', flagged)}\n"
                f"{G['div']}\n{summary}",
                parse_mode="HTML")
        except Exception:
            pass
    threading.Thread(target=_bg, daemon=True).start()


def action_adm_kill_all(call: types.CallbackQuery) -> None:
    ack(call, "Turning all off…")
    def _bg() -> None:
        n = _do_stop_all_bots(call.from_user.id)
        try:
            bot.send_message(call.from_user.id,
                             f"{G['ok']} {sc('All bots are now off')} ({n}). {sc('Nothing is deleted. Start them again when ready')}.")
        except Exception:
            pass
    threading.Thread(target=_bg, daemon=True).start()


# ─── 4. SECURITY CENTER ──────────────────────────────────────────────────────

def render_adm_sec_center(call: types.CallbackQuery) -> None:
    d = db_load()
    scan_log = d.get("scan_log", [])
    blocked  = sum(1 for s in scan_log if s.get("verdict") == "DANGEROUS")
    reviewed = sum(1 for s in scan_log if s.get("verdict") == "SUSPICIOUS")
    banned_n = sum(1 for u in d["users"].values() if u.get("banned"))
    cap = (
        f"<b>🛡️ {sc('Security Center')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Files Blocked',     blocked)}\n"
        f"{bullet('Manual Reviews',    reviewed)}\n"
        f"{bullet('Banned Users',      banned_n)}\n"
        f"{bullet('AI Scanner',        'Active' if os.environ.get('AI_INTEGRATIONS_OPENROUTER_BASE_URL') else 'No URL')}\n"
        f"{bullet('Pattern Scanner',   'Active')}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("📋  Tʜʀᴇᴀᴛ Lᴏɢ",      callback_data="adm_threat_log",     style="danger"),
        Btn("📊  Sᴇᴄ Sᴛᴀᴛꜱ",        callback_data="adm_sec_stats",      style="primary"),
    )
    kb.add(
        Btn("✅  Wʜɪᴛᴇʟɪꜱᴛ Uꜱᴇʀ",  callback_data="adm_sec_whitelist",  style="success"),
        Btn("🚫  Bʟᴀᴄᴋʟɪꜱᴛ",        callback_data="adm_sec_blacklist",  style="danger"),
    )
    kb.add(
        Btn("🔍  Sᴄᴀɴ Rᴇᴘᴏʀᴛ",     callback_data="adm_scan_report",    style="primary"),
        Btn("🚫  Bᴀɴɴᴇᴅ Lɪꜱᴛ",     callback_data="adm_banned_list",    style="primary"),
    )
    kb.add(
        Btn("🛡️  Sᴇᴄᴜʀɪᴛʏ Iɴꜰᴏ",   callback_data="adm_security",       style="primary"),
        Btn("📋  Aᴜᴅɪᴛ Lᴏɢ",        callback_data="adm_audit",          style="primary"),
    )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS["security"], cap, kb, call=call)


def render_adm_threat_log(call: types.CallbackQuery) -> None:
    scan_log = db_load().get("scan_log", [])
    flagged = [s for s in scan_log if s.get("verdict") in ("DANGEROUS", "SUSPICIOUS")][-20:]
    rows = "\n".join(
        f"{G['bullet']} <b>{esc(s.get('verdict'))}</b> "
        f"risk={s.get('risk_score',0)} "
        f"uid {s.get('uid','?')} "
        f"— {esc(s.get('filename','?'))[:25]} "
        f"<i>{str(s.get('ts',''))[:10]}</i>"
        for s in reversed(flagged)
    ) or f"<i>{sc('No threats logged')}</i>"
    cap = (
        f"<b>📋 {sc('Threat Log')} ({len(flagged)} {sc('entries')})</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["security"], cap, _adm_back("adm_sec_center"), call=call)


def render_adm_sec_stats(call: types.CallbackQuery) -> None:
    scan_log = db_load().get("scan_log", [])
    total    = len(scan_log)
    blocked  = sum(1 for s in scan_log if s.get("verdict") == "DANGEROUS")
    sus      = sum(1 for s in scan_log if s.get("verdict") == "SUSPICIOUS")
    safe_n   = sum(1 for s in scan_log if s.get("verdict") == "SAFE")
    avg_risk = int(sum(s.get("risk_score", 0) for s in scan_log) / max(total, 1))
    cap = (
        f"<b>📊 {sc('Security Statistics')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Total scans',    total)}\n"
        f"{bullet('🔴 Blocked',     blocked)}\n"
        f"{bullet('🟡 Suspicious',  sus)}\n"
        f"{bullet('✅ Safe',        safe_n)}\n"
        f"{bullet('Avg risk score', avg_risk)}\n"
        f"{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["security"], cap, _adm_back("adm_sec_center"), call=call)


def render_adm_sec_whitelist_prompt(call: types.CallbackQuery) -> None:
    wl = get_setting("scan_whitelist", []) or []
    rows = ", ".join(f"<code>{uid}</code>" for uid in wl) or f"<i>{sc('Empty')}</i>"
    cap = (
        f"<b>✅ {sc('Scan Whitelist')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Whitelisted users skip AI + pattern scan')}.\n"
        f"{sc('Current')}: {rows}\n"
        f"{G['div']}\n"
        f"{sc('Send')}: <code>add &lt;uid&gt;</code> {sc('or')} <code>del &lt;uid&gt;</code>{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_adm_whitelist"}
    show_menu(call.message.chat.id, PHOTOS["security"], cap, _adm_back("adm_sec_center"), call=call)


def render_adm_scan_report(call: types.CallbackQuery) -> None:
    scan_log = db_load().get("scan_log", [])
    last10 = scan_log[-10:]
    rows = "\n".join(
        f"{G['bullet']} {esc(s.get('verdict','?'))[:4]} "
        f"risk={s.get('risk_score',0):>3} "
        f"{esc(s.get('filename','?')[:22])} "
        f"<i>uid {s.get('uid','?')}</i>"
        for s in reversed(last10)
    ) or f"<i>{sc('No scans yet')}</i>"
    cap = (
        f"<b>🔍 {sc('Recent Scan Report')} (last {len(last10)})</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["security"], cap, _adm_back("adm_sec_center"), call=call)


def render_adm_sec_blacklist(call: types.CallbackQuery) -> None:
    bl = get_setting("domain_blacklist", []) or []
    rows = "\n".join(f"{G['bullet']} <code>{esc(d)}</code>" for d in bl) or f"<i>{sc('Empty')}</i>"
    cap = (
        f"<b>🚫 {sc('Domain Blacklist')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Bots containing these domains auto-flag as SUSPICIOUS')}.\n"
        f"{sc('Current')}: {rows}\n"
        f"{G['div']}\n"
        f"{sc('Send')}: <code>add domain.com</code> {sc('or')} <code>del domain.com</code>{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_adm_blacklist"}
    show_menu(call.message.chat.id, PHOTOS["security"], cap, _adm_back("adm_sec_center"), call=call)


# ─── 5. NOTIFICATIONS ────────────────────────────────────────────────────────

def render_adm_notify_center(call: types.CallbackQuery) -> None:
    users_n  = len(db_load()["users"])
    running_n = sum(1 for x in RUNNING.values() if x["proc"].poll() is None)
    cap = (
        f"<b>💬 {sc('Notifications Center')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Total users',    users_n)}\n"
        f"{bullet('Running bots',   running_n)}\n"
        f"{G['div']}\n{sc('Choose notification type')}.{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("📢  Nᴏᴛɪꜰʏ Eᴠᴇʀʏᴏɴᴇ", callback_data="adm_notify_all",        style="success"),
        Btn("▶️  Bᴏᴛ Uꜱᴇʀꜱ Oɴʟʏ",  callback_data="adm_notify_running",     style="primary"),
    )
    kb.add(
        Btn("📊  Bʏ Pʟᴀɴ",          callback_data="adm_notify_plan_select", style="primary"),
        Btn("📨  Sɪɴɢʟᴇ Uꜱᴇʀ",     callback_data="adm_notify_user",        style="primary"),
    )
    kb.add(
        Btn("⏰  Sᴄʜᴇᴅᴜʟᴇ Mꜱɢ",    callback_data="adm_schedule_msg",       style="primary"),
        Btn("📣  Qᴜɪᴄᴋ Aɴɴᴏᴜɴᴄᴇ",  callback_data="adm_quick_announce",     style="success"),
    )
    kb.add(
        Btn("📡  Bʀᴏᴀᴅᴄᴀꜱᴛ",        callback_data="adm_broadcast",          style="success"),
    )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS["broadcast"], cap, kb, call=call)


def render_adm_notify_all(call: types.CallbackQuery) -> None:
    total = len(db_load()["users"])
    cap = (
        f"<b>📢 {sc('Notify All Users')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Recipients', total)}\n"
        f"{sc('Send your message now — it will be delivered to every user')}.{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_broadcast"}
    show_menu(call.message.chat.id, PHOTOS["broadcast"], cap, _adm_back("adm_notify_center"), call=call)


def render_adm_notify_running(call: types.CallbackQuery) -> None:
    running_owner_ids: set = {str(info["owner"]) for info in RUNNING.values()
                               if info["proc"].poll() is None}
    cap = (
        f"<b>▶️ {sc('Notify Active Bot Users')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Recipients', len(running_owner_ids))}\n"
        f"{sc('Send your message now')}.{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_adm_notify_running",
                                       "target_uids": list(running_owner_ids)}
    show_menu(call.message.chat.id, PHOTOS["broadcast"], cap, _adm_back("adm_notify_center"), call=call)


def render_adm_notify_plan_select(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>📊 {sc('Notify By Plan')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Choose which plan to message')}.{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    for k, v in PLAN_LIMITS.items():
        cnt = sum(1 for u in db_load()["users"].values() if u.get("plan") == k)
        kb.add(Btn(f"{esc(v['name'])} ({cnt})", callback_data=f"adm_notify_plan_{k}"))
    kb.add(Btn(f"{G['back']}  {sc('Back')}", callback_data="adm_notify_center"))
    show_menu(call.message.chat.id, PHOTOS["broadcast"], cap, kb, call=call)


def render_adm_notify_plan(call: types.CallbackQuery, plan_key: str) -> None:
    users = db_load()["users"]
    targets = [uid for uid, u in users.items() if u.get("plan") == plan_key]
    plan_name = PLAN_LIMITS.get(plan_key, {}).get("name", plan_key)
    cap = (
        f"<b>📊 {sc('Notify')} {esc(plan_name)} {sc('Users')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Recipients', len(targets))}\n"
        f"{sc('Send your message now')}.{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_adm_notify_running",
                                       "target_uids": targets}
    show_menu(call.message.chat.id, PHOTOS["broadcast"], cap, _adm_back("adm_notify_center"), call=call)


def render_adm_schedule_msg(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>⏰ {sc('Schedule Message')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Send in format')}:\n"
        f"<code>at:YYYY-MM-DD HH:MM Your message text</code>\n"
        f"{sc('Example')}: <code>at:2025-12-31 10:00 Happy New Year!</code>{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_broadcast"}
    show_menu(call.message.chat.id, PHOTOS["broadcast"], cap, _adm_back("adm_notify_center"), call=call)


def render_adm_quick_announce(call: types.CallbackQuery) -> None:
    chan = ANNOUNCE_CHANNEL or "—"
    cap = (
        f"<b>📣 {sc('Quick Announce')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Channel', chan)}\n"
        f"{sc('Send your message — it will be pinned in the announce channel')}.{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_adm_quick_announce"}
    show_menu(call.message.chat.id, PHOTOS["broadcast"], cap, _adm_back("adm_notify_center"), call=call)


# ─── 6. SYSTEM TOOLS ─────────────────────────────────────────────────────────

def render_adm_sys_tools(call: types.CallbackQuery) -> None:
    rss = 0
    if psutil is not None:
        try:
            rss = psutil.Process(os.getpid()).memory_info().rss
        except Exception:
            pass
    up_secs = int(time.time() - START_TIME) if "START_TIME" in globals() else 0
    cap = (
        f"<b>⚙️ {sc('System Tools')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Uptime',   fmt_dur(up_secs * 1000))}\n"
        f"{bullet('RAM',      fmt_bytes(rss))}\n"
        f"{bullet('PID',      os.getpid())}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("🖥️  Sʏꜱ Hᴇᴀʟᴛʜ",    callback_data="adm_sys_health",      style="primary"),
        Btn("💾  Dɪꜱᴋ Uꜱᴀɢᴇ",    callback_data="adm_disk_usage",      style="primary"),
    )
    kb.add(
        Btn("🗄️  DB Iɴꜰᴏ",       callback_data="adm_db_info",         style="primary"),
        Btn("🧹  Cʟᴇᴀʀ Cᴀᴄʜᴇ",   callback_data="adm_clear_cache",     style="danger"),
    )
    kb.add(
        Btn("🔑  Tᴏᴋᴇɴ Cʜᴇᴄᴋ",   callback_data="adm_token_check",     style="primary"),
        Btn("📤  Exᴘᴏʀᴛ Dᴀᴛᴀ",   callback_data="adm_set_export",      style="primary"),
    )
    kb.add(
        Btn("🔄  Rᴇʟᴏᴀᴅ Cᴀᴄʜᴇ",  callback_data="adm_set_reload",      style="success"),
        Btn("👁️  Sʏꜱᴛᴇᴍ Iɴꜰᴏ",   callback_data="adm_set_sysinfo",     style="primary"),
    )
    kb.add(
        Btn("✏️  Fᴏᴏᴛᴇʀ Tᴇxᴛ",   callback_data="adm_set_footer_text", style="primary"),
        Btn("👋  Wᴇʟᴄᴏᴍᴇ Mꜱɢ",   callback_data="adm_set_welcome_text",style="primary"),
    )
    kb.add(
        Btn("📜  Rᴜʟᴇꜱ Tᴇxᴛ",    callback_data="adm_set_rules_text",  style="primary"),
        Btn("📦  Gɪᴛʜᴜʙ",         callback_data="adm_github",          style="primary"),
    )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


def render_adm_sys_health(call: types.CallbackQuery) -> None:
    rss = vms = cpu_p = 0.0
    disk_total = disk_used = disk_free = 0
    if psutil is not None:
        try:
            p = psutil.Process(os.getpid())
            mi = p.memory_info()
            rss, vms = mi.rss, mi.vms
            cpu_p = p.cpu_percent(interval=0.3)
            du = psutil.disk_usage("/")
            disk_total, disk_used, disk_free = du.total, du.used, du.free
        except Exception:
            pass
    # Child bot CPU/RAM
    child_rss = 0
    child_n   = 0
    if psutil is not None:
        for info in RUNNING.values():
            if info["proc"].poll() is not None:
                continue
            try:
                cp = psutil.Process(info["proc"].pid)
                child_rss += cp.memory_info().rss
                child_n += 1
            except Exception:
                pass
    up_secs = int(time.time() - START_TIME) if "START_TIME" in globals() else 0
    cap = (
        f"<b>🖥️ {sc('System Health')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Uptime',          fmt_dur(up_secs * 1000))}\n"
        f"{bullet('Panel RAM (RSS)', fmt_bytes(int(rss)))}\n"
        f"{bullet('Panel RAM (VMS)', fmt_bytes(int(vms)))}\n"
        f"{bullet('Panel CPU',       f'{cpu_p:.1f}%')}\n"
        f"{bullet('Child bots',      f'{child_n} running')}\n"
        f"{bullet('Child RAM total', fmt_bytes(child_rss))}\n"
        f"{bullet('Disk total',      fmt_bytes(disk_total))}\n"
        f"{bullet('Disk used',       fmt_bytes(disk_used))}\n"
        f"{bullet('Disk free',       fmt_bytes(disk_free))}\n"
        f"{bullet('PID',             os.getpid())}\n"
        f"{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, _adm_back("adm_sys_tools"), call=call)


def render_adm_disk_usage(call: types.CallbackQuery) -> None:
    bots = db_load()["bots"].values()
    by_user: Dict[str, int] = defaultdict(int)
    for b in bots:
        bot_dir = Path(b.get("dir", ""))
        if not bot_dir.exists():
            continue
        size = 0
        for root, _, files in os.walk(bot_dir):
            for f in files:
                try:
                    size += (Path(root) / f).stat().st_size
                except OSError:
                    pass
        by_user[str(b.get("owner", "unknown"))] += size
    top = sorted(by_user.items(), key=lambda x: x[1], reverse=True)[:12]
    d = db_load()
    rows = "\n".join(
        f"{G['bullet']} uid <code>{uid}</code> "
        f"({esc(d['users'].get(uid, {}).get('name', '?')[:15])}) — <b>{fmt_bytes(sz)}</b>"
        for uid, sz in top
    ) or f"<i>{sc('No data')}</i>"
    cap = (
        f"<b>💾 {sc('Disk Usage by User')}</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, _adm_back("adm_sys_tools"), call=call)


def render_adm_db_info(call: types.CallbackQuery) -> None:
    d = db_load()
    db_file = DB_FILE
    db_size = db_file.stat().st_size if db_file.exists() else 0
    settings_size = SETTINGS_FILE.stat().st_size if SETTINGS_FILE.exists() else 0
    cap = (
        f"<b>🗄️ {sc('Database Info')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('DB file',       db_file.name)}\n"
        f"{bullet('DB size',       fmt_bytes(db_size))}\n"
        f"{bullet('Settings size', fmt_bytes(settings_size))}\n"
        f"{bullet('Users',         len(d['users']))}\n"
        f"{bullet('Bots',          len(d['bots']))}\n"
        f"{bullet('Payments',      len(d['payments']))}\n"
        f"{bullet('Coupons',       len(d['coupons']))}\n"
        f"{bullet('Tickets',       len(d.get('tickets', {})))}\n"
        f"{bullet('Audit entries', len(d.get('audit', [])))}\n"
        f"{bullet('Scan log',      len(d.get('scan_log', [])))}\n"
        f"{bullet('Cache entries', len(_DB_CACHE))}\n"
        f"{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, _adm_back("adm_sys_tools"), call=call)


def render_adm_token_check(call: types.CallbackQuery) -> None:
    ack(call, "Checking tokens…")
    def _bg() -> None:
        bots = list(db_load()["bots"].values())
        valid = invalid = missing = 0
        bad_list: List[str] = []
        for b in bots[:20]:
            tok = b.get("env", {}).get("BOT_TOKEN") or b.get("token")
            if not tok:
                missing += 1
                continue
            try:
                resp = _urllib_req.urlopen(
                    f"https://api.telegram.org/bot{tok}/getMe", timeout=5)
                data = _json.loads(resp.read())
                if data.get("ok"):
                    valid += 1
                else:
                    invalid += 1
                    bad_list.append(b.get("name", b["_id"])[:20])
            except Exception:
                invalid += 1
                bad_list.append(b.get("name", b["_id"])[:20])
        bad_txt = "\n".join(f"  ❌ {n}" for n in bad_list) or "  (none)"
        audit(call.from_user.id, "token_check", f"valid={valid} invalid={invalid}")
        try:
            bot.send_message(
                call.from_user.id,
                f"<b>🔑 {sc('Token Check Report')}</b>\n"
                f"{G['div_eq']}\n"
                f"{bullet('Valid',   valid)}\n"
                f"{bullet('Invalid', invalid)}\n"
                f"{bullet('Missing', missing)}\n"
                f"{G['div']}\n<b>Invalid bots:</b>\n{bad_txt}",
                parse_mode="HTML")
        except Exception:
            pass
    threading.Thread(target=_bg, daemon=True).start()

# ═══════════════════════ END NEW ADMIN SUB-PANELS ═══════════════════════════


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║          MEGA ADVANCED ADMIN PANELS  (20+ new panels, 200+ features)     ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS / DEFAULTS for new systems
# ─────────────────────────────────────────────────────────────────────────────

_FEATURE_FLAG_DEFAULTS: Dict[str, bool] = {
    "user_registration":    True,   # allow new users to register
    "bot_upload":           True,   # allow users to upload bots
    "bot_auto_start":       True,   # auto-start bots after approval
    "payment_system":       True,   # enable the payment panel
    "coupon_system":        True,   # allow coupon redemption
    "referral_system":      True,   # enable referrals
    "ticket_system":        True,   # enable support tickets
    "wallet_topup":         True,   # allow wallet top-up
    "gift_plan":            True,   # allow gifting plans
    "trial_plan":           True,   # allow free trials
    "public_stats":         False,  # show stats to regular users
    "bot_logs_user":        True,   # users can view their own bot logs
    "multi_file_upload":    True,   # allow zip uploads with multiple files
    "github_backup":        True,   # enable GitHub backup
    "cloudflare_tunnel":    True,   # enable Cloudflare tunnel feature
    "ai_scanner":           True,   # enable AI security scan
    "approval_system":      True,   # require admin approval for uploads
    "maintenance_bypass":   False,  # admins bypass maintenance mode
    "sandbox_wipe":         True,   # wipe source files after start
    "rate_limiting":        True,   # enable rate limiting
    "audit_logging":        True,   # log admin actions to audit trail
    "auto_restart_bots":    True,   # auto-restart crashed bots
    "broadcast_enabled":    True,   # enable broadcast messages
    "webhook_notifications":False,  # send events to external webhook
    "2fa_required":         False,  # require 2FA for admin actions
}

_BOT_CONFIG_DEFAULTS: Dict[str, Any] = {
    "sandbox_wipe_delay":   6,      # seconds before wiping source files
    "max_upload_mb":        75,     # max upload size in MB
    "allowed_extensions":   ".py,.js,.zip,.txt,.json,.env",
    "bot_start_timeout":    30,     # seconds to wait for bot to start
    "bot_stop_timeout":     10,     # seconds for graceful stop
    "crash_restart_delay":  5,      # seconds before auto-restart after crash
    "max_crash_restarts":   5,      # max auto-restarts per bot per hour
    "log_ring_size":        200,    # lines kept in memory log ring
    "zip_max_files":        50,     # max files in a zip upload
    "env_strip_secrets":    True,   # strip BOT_TOKEN etc from child env
    "sandbox_network":      True,   # allow bots to use network
    "idle_timeout_mins":    0,      # 0 = no idle timeout
    "resource_check_secs":  30,     # interval for resource checks
}

_RATE_LIMIT_DEFAULTS: Dict[str, Dict[str, int]] = {
    "free":       {"uploads_per_day": 3,  "starts_per_hour": 5,  "msgs_per_min": 20},
    "starter":    {"uploads_per_day": 10, "starts_per_hour": 15, "msgs_per_min": 40},
    "basic":      {"uploads_per_day": 20, "starts_per_hour": 30, "msgs_per_min": 60},
    "pro":        {"uploads_per_day": 50, "starts_per_hour": 60, "msgs_per_min": 120},
    "enterprise": {"uploads_per_day": 100,"starts_per_hour": 120,"msgs_per_min": 240},
    "lifetime":   {"uploads_per_day": 999,"starts_per_hour": 999,"msgs_per_min": 999},
}

_MESSAGE_TEMPLATES: Dict[str, Dict[str, str]] = {
    "welcome": {
        "label": "Welcome Message",
        "default": "Welcome {name}! 🎉 You're now registered on {brand}. Use /start to explore.",
        "vars": "{name}, {brand}, {plan}",
    },
    "payment_received": {
        "label": "Payment Received",
        "default": "✅ Payment of {amount}৳ received for {plan} plan. Your account has been upgraded!",
        "vars": "{name}, {amount}, {plan}, {tx_id}, {date}",
    },
    "plan_expired": {
        "label": "Plan Expiry Warning",
        "default": "⚠️ Your {plan} plan expires in {days} days. Renew now to avoid service interruption!",
        "vars": "{name}, {plan}, {days}, {expiry_date}",
    },
    "bot_approved": {
        "label": "Bot Approved",
        "default": "✅ Your bot '{bot_name}' has been approved and is now running!",
        "vars": "{name}, {bot_name}, {bot_id}",
    },
    "bot_rejected": {
        "label": "Bot Rejected",
        "default": "❌ Your bot '{bot_name}' was rejected. Reason: {reason}",
        "vars": "{name}, {bot_name}, {reason}",
    },
    "referral_reward": {
        "label": "Referral Reward",
        "default": "🎁 You earned {amount}৳ for referring {referred_name}! Keep sharing!",
        "vars": "{name}, {amount}, {referred_name}",
    },
    "ticket_reply": {
        "label": "Ticket Reply",
        "default": "📩 Admin replied to your ticket #{ticket_id}: {reply}",
        "vars": "{name}, {ticket_id}, {reply}",
    },
    "bot_crashed": {
        "label": "Bot Crashed Alert",
        "default": "💥 Your bot '{bot_name}' crashed (exit code {exit_code}). Check logs or re-upload.",
        "vars": "{name}, {bot_name}, {exit_code}",
    },
    "maintenance": {
        "label": "Maintenance Notice",
        "default": "🔧 {brand} is currently under maintenance. We'll be back soon!",
        "vars": "{brand}, {eta}",
    },
    "upgrade_prompt": {
        "label": "Upgrade Prompt",
        "default": "💎 Upgrade to {plan} and get {max_bots} bots, {ram}MB RAM, and more!",
        "vars": "{name}, {plan}, {max_bots}, {ram}, {price}",
    },
}

_SUPPORTED_LANGUAGES: Dict[str, str] = {
    "en":    "🇬🇧 English",
    "bn":    "🇧🇩 বাংলা (Bengali)",
    "hi":    "🇮🇳 हिन्दी (Hindi)",
    "ar":    "🇸🇦 العربية (Arabic)",
    "ur":    "🇵🇰 اردو (Urdu)",
    "tr":    "🇹🇷 Türkçe",
    "ru":    "🇷🇺 Русский",
    "es":    "🇪🇸 Español",
    "fr":    "🇫🇷 Français",
    "de":    "🇩🇪 Deutsch",
    "pt":    "🇧🇷 Português",
    "id":    "🇮🇩 Bahasa Indonesia",
    "ms":    "🇲🇾 Bahasa Melayu",
    "fa":    "🇮🇷 فارسی (Persian)",
    "zh":    "🇨🇳 中文 (Chinese)",
}

_APPEARANCE_THEMES: Dict[str, Dict[str, str]] = {
    "dark":      {"name": "Dark",       "header": "#0F172A", "accent": "#6366F1", "emoji_ok": "✅"},
    "midnight":  {"name": "Midnight",   "header": "#020617", "accent": "#818CF8", "emoji_ok": "💫"},
    "ocean":     {"name": "Ocean",      "header": "#0E4472", "accent": "#38BDF8", "emoji_ok": "🌊"},
    "forest":    {"name": "Forest",     "header": "#14532D", "accent": "#4ADE80", "emoji_ok": "🌿"},
    "sunset":    {"name": "Sunset",     "header": "#7C2D12", "accent": "#FB923C", "emoji_ok": "🌅"},
    "royal":     {"name": "Royal",      "header": "#3B0764", "accent": "#C084FC", "emoji_ok": "👑"},
    "neon":      {"name": "Neon",       "header": "#0A0A0A", "accent": "#39FF14", "emoji_ok": "⚡"},
    "rose":      {"name": "Rose",       "header": "#881337", "accent": "#FB7185", "emoji_ok": "🌹"},
    "gold":      {"name": "Gold",       "header": "#451A03", "accent": "#FBBF24", "emoji_ok": "💰"},
    "ice":       {"name": "Ice",        "header": "#1E3A5F", "accent": "#BAE6FD", "emoji_ok": "❄️"},
}

# ─────────────────────────────────────────────────────────────────────────────
# GITHUB FILE BROWSER & RUNNER
# ─────────────────────────────────────────────────────────────────────────────

def _gh_api(endpoint: str, token: Optional[str] = None,
            method: str = "GET", body: Optional[bytes] = None) -> Any:
    """Make a GitHub API call. Returns parsed JSON or raises."""
    import urllib.request as _ur
    import json as _j
    tok = token or GH.get("token", "")
    url = endpoint if endpoint.startswith("http") else f"https://api.github.com{endpoint}"
    req = _ur.Request(url, method=method, data=body)
    req.add_header("Authorization", f"token {tok}")
    req.add_header("Accept",        "application/vnd.github.v3+json")
    req.add_header("User-Agent",    "SimranHostingBot/2.0")
    if body:
        req.add_header("Content-Type", "application/json")
    with _ur.urlopen(req, timeout=15) as resp:
        return _j.loads(resp.read().decode("utf-8"))


def _gh_api_safe(endpoint: str, token: Optional[str] = None) -> Tuple[bool, Any]:
    """GitHub API call returning (ok, data_or_error_str)."""
    try:
        return True, _gh_api(endpoint, token)
    except Exception as e:
        return False, str(e)


def render_adm_gh_browser(call: types.CallbackQuery) -> None:
    """GitHub File Browser — main landing panel."""
    has_token = bool(GH.get("token"))
    has_repo  = bool(GH.get("repo"))
    cur_repo  = GH.get("repo") or "—"
    cur_branch= GH.get("branch") or "main"
    cap = (
        f"<b>🐙 {sc('GitHub File Browser')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Token',  '✅ Set' if has_token else '❌ Not set')}\n"
        f"{bullet('Repo',   esc(cur_repo))}\n"
        f"{bullet('Branch', esc(cur_branch))}\n"
        f"{G['div']}\n"
        f"<i>{sc('Browse and run files directly from any GitHub repo. Works with public and private repos (with token).')}  </i>{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    if has_token:
        kb.add(Btn("📂  Bʀᴏᴡꜱᴇ Mʏ Rᴇᴘᴏꜱ",  callback_data="adm_gh_repos",        style="success"))
        if has_repo:
            kb.add(Btn(f"📁  {esc(cur_repo)[:25]}",  callback_data="adm_gh_browse_repo", style="primary"))
    kb.add(
        Btn("🔑  Sᴇᴛ Tᴏᴋᴇɴ",       callback_data="gh_set_token",   style="primary"),
        Btn("📦  Sᴇᴛ Rᴇᴘᴏ",         callback_data="gh_set_repo",    style="primary"),
    )
    kb.add(
        Btn("🌿  Sᴇᴛ Bʀᴀɴᴄʜ",       callback_data="gh_set_branch",  style="primary"),
        Btn("🔄  Rᴇꜰʀᴇꜱʜ",          callback_data="adm_gh_refresh_repos", style="primary"),
    )
    kb.add(
        Btn("📊  Gɪᴛʜᴜʙ Bᴀᴄᴋᴜᴘ",   callback_data="adm_github",     style="primary"),
        Btn(f"{G['back']}  Aᴅᴍɪɴ",  callback_data="menu_admin",     style="primary"),
    )
    show_menu(call.message.chat.id, PHOTOS.get("gh_browser", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_gh_repos(call: types.CallbackQuery, force: bool = False) -> None:
    """List all accessible GitHub repositories."""
    if not GH.get("token"):
        ack(call, "Set GitHub token first"); return render_adm_gh_browser(call)
    ack(call, "Fetching repos…")
    def _bg() -> None:
        ok, data = _gh_api_safe("/user/repos?per_page=50&sort=updated&type=all")
        if not ok:
            try:
                bot.send_message(call.from_user.id,
                                 f"{G['no']} {sc('GitHub API error')}: <code>{esc(str(data)[:200])}</code>",
                                 parse_mode="HTML")
            except Exception:
                pass
            return
        repos = data if isinstance(data, list) else []
        if not repos:
            try:
                bot.send_message(call.from_user.id, f"<i>{sc('No repos found.')}</i>", parse_mode="HTML")
            except Exception:
                pass
            return
        rows = "\n".join(
            f"{G['bullet']} <b>{esc(r['full_name'])}</b> "
            f"{'🔒' if r.get('private') else '🌐'} "
            f"⭐{r.get('stargazers_count',0)} "
            f"<i>{esc((r.get('description') or '')[:40])}</i>"
            for r in repos[:20]
        )
        cap = (
            f"<b>🐙 {sc('Your GitHub Repos')} ({len(repos)})</b>\n"
            f"{G['div_eq']}\n{rows}\n{G['div']}\n"
            f"{sc('Tap a repo to browse its files')}.{FOOTER}"
        )
        kb = types.InlineKeyboardMarkup(row_width=1)
        for r in repos[:15]:
            name = r["full_name"]
            short = name[:35]
            icon = "🔒" if r.get("private") else "🌐"
            # Store repo in state, use index-based callback
            kb.add(Btn(f"{icon} {short}", callback_data=f"adm_ghrepo_{name[:40]}", style="primary"))
        kb.add(Btn(f"{G['back']}  Gʜ Bʀᴏᴡꜱᴇʀ", callback_data="adm_gh_browser", style="primary"))
        try:
            bot.send_message(call.from_user.id, cap, reply_markup=kb, parse_mode="HTML")
        except Exception:
            pass
    threading.Thread(target=_bg, daemon=True).start()


def render_adm_gh_files(call: types.CallbackQuery, repo: str, path: str = "") -> None:
    """Browse files in a GitHub repo at a given path."""
    if not GH.get("token") or not repo:
        ack(call, "Set token and repo first"); return
    ack(call, f"Loading {repo}/{path or 'root'}…")
    def _bg() -> None:
        branch = GH.get("branch", "main")
        ep = f"/repos/{repo}/contents/{path}?ref={branch}"
        ok, data = _gh_api_safe(ep)
        if not ok:
            try:
                bot.send_message(call.from_user.id,
                                 f"{G['no']} {sc('Error loading files')}: <code>{esc(str(data)[:200])}</code>",
                                 parse_mode="HTML")
            except Exception:
                pass
            return
        items = data if isinstance(data, list) else [data]
        items.sort(key=lambda x: (0 if x.get("type") == "dir" else 1, x.get("name", "")))
        # Save file list in state for index-based navigation
        USER_STATES[call.from_user.id] = USER_STATES.get(call.from_user.id, {})
        USER_STATES[call.from_user.id].update({
            "gh_repo": repo,
            "gh_path": path,
            "gh_files_list": items,
        })
        breadcrumb = f"{repo}/{path}" if path else repo
        rows = "\n".join(
            f"{'📁' if it.get('type')=='dir' else '📄'} {esc(it.get('name','?'))} "
            + (f"<i>({fmt_bytes(it.get('size',0))})</i>" if it.get('type') != 'dir' else "")
            for it in items[:25]
        )
        cap = (
            f"<b>📂 {esc(breadcrumb[:50])}</b>\n"
            f"{G['div_eq']}\n{rows}\n"
            f"{G['div']}\n{len(items)} items{FOOTER}"
        )
        kb = types.InlineKeyboardMarkup(row_width=2)
        if path:
            kb.add(Btn("⬆️  Uᴘ",  callback_data="adm_gh_up", style="primary"))
        for i, it in enumerate(items[:12]):
            icon = "📁" if it.get("type") == "dir" else _file_icon(it.get("name",""))
            kb.add(Btn(f"{icon} {esc(it.get('name','?'))[:28]}", callback_data=f"adm_ghfile_{i}", style="primary"))
        kb.add(Btn(f"{G['back']}  Rᴇᴘᴏꜱ", callback_data="adm_gh_repos", style="primary"))
        try:
            bot.send_message(call.from_user.id, cap, reply_markup=kb, parse_mode="HTML")
        except Exception:
            pass
    threading.Thread(target=_bg, daemon=True).start()


def _file_icon(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    return {"py":"🐍",".js":"📜",".json":"📋",".env":"🔐",".txt":"📝",
            ".md":"📝",".zip":"📦",".sh":"⚙️",".yaml":"📋",".yml":"📋",
            ".toml":"📋",".cfg":"⚙️",".ini":"⚙️",".html":"🌐",".css":"🎨"}.get(ext, "📄")


def render_adm_gh_file_view(call: types.CallbackQuery, repo: str, path: str) -> None:
    """View a single file from GitHub and optionally run it."""
    ack(call, f"Loading {Path(path).name}…")
    USER_STATES[call.from_user.id] = USER_STATES.get(call.from_user.id, {})
    USER_STATES[call.from_user.id]["gh_view_path"] = path
    USER_STATES[call.from_user.id]["gh_repo"] = repo
    def _bg() -> None:
        branch = GH.get("branch", "main")
        ep = f"/repos/{repo}/contents/{path}?ref={branch}"
        ok, data = _gh_api_safe(ep)
        if not ok or isinstance(data, list):
            try:
                bot.send_message(call.from_user.id,
                                 f"{G['no']} {sc('Cannot read file')}: <code>{esc(str(data)[:200])}</code>",
                                 parse_mode="HTML")
            except Exception:
                pass
            return
        fname   = data.get("name", path)
        size    = data.get("size", 0)
        sha     = data.get("sha", "")[:7]
        dl_url  = data.get("download_url", "")
        content_b64 = data.get("content", "")
        try:
            raw = base64.b64decode(content_b64.replace("\n", ""))
            preview = raw[:1000].decode("utf-8", errors="replace")
        except Exception:
            preview = "(binary file — cannot preview)"
        ext = Path(fname).suffix.lower()
        runnable = ext in (".py", ".js")
        cap = (
            f"<b>{_file_icon(fname)} {esc(fname)}</b>\n"
            f"{G['div_eq']}\n"
            f"{bullet('Repo',   esc(repo))}\n"
            f"{bullet('Path',   esc(path))}\n"
            f"{bullet('Size',   fmt_bytes(size))}\n"
            f"{bullet('SHA',    sha)}\n"
            f"{bullet('Branch', GH.get('branch','main'))}\n"
            f"{G['div']}\n"
            f"<pre>{esc(preview[:800])}</pre>"
            f"{'...(truncated)' if len(raw) > 1000 else ''}{FOOTER}"
        )
        kb = types.InlineKeyboardMarkup(row_width=2)
        if runnable:
            kb.add(Btn("▶️  Rᴜɴ Aꜱ Bᴏᴛ",  callback_data="adm_gh_run_file",  style="success"))
        kb.add(
            Btn("📥  Dᴏᴡɴʟᴏᴀᴅ",        callback_data="adm_gh_dl_file",   style="primary"),
            Btn("📁  Bᴀᴄᴋ ᴛᴏ Fᴏʟᴅᴇʀ",  callback_data="adm_gh_browse_repo",style="primary"),
        )
        kb.add(Btn(f"{G['back']}  Gʜ Bʀᴏᴡꜱᴇʀ", callback_data="adm_gh_browser", style="primary"))
        try:
            bot.send_message(call.from_user.id, cap, reply_markup=kb, parse_mode="HTML")
        except Exception:
            pass
    threading.Thread(target=_bg, daemon=True).start()


def action_adm_gh_run_file(call: types.CallbackQuery, repo: str, path: str) -> None:
    """Download a file from GitHub and register + start it as a bot."""
    if not repo or not path:
        ack(call, "No file selected"); return
    ack(call, f"Downloading and deploying {Path(path).name}…")
    def _bg() -> None:
        try:
            branch = GH.get("branch", "main")
            ep = f"/repos/{repo}/contents/{path}?ref={branch}"
            ok, data = _gh_api_safe(ep)
            if not ok:
                bot.send_message(call.from_user.id,
                                 f"{G['no']} API error: <code>{esc(str(data)[:200])}</code>",
                                 parse_mode="HTML"); return
            fname = data.get("name", Path(path).name)
            content_b64 = data.get("content", "")
            raw = base64.b64decode(content_b64.replace("\n", ""))
            # Create a new bot entry
            bid   = secrets.token_hex(8)
            d_db  = db_load()
            owner = call.from_user.id
            bot_name = Path(fname).stem[:30]
            # Build the bot record
            bot_dir = BASE_DIR / "sandbox" / bid
            bot_dir.mkdir(parents=True, exist_ok=True)
            src_file = bot_dir / fname
            src_file.write_bytes(raw)
            # Encrypt the file for storage
            enc_files: Dict[str, str] = {}
            try:
                enc_files[fname] = cipher_encrypt(raw)
            except Exception:
                enc_files[fname] = base64.b64encode(raw).decode()
            new_bot: Dict[str, Any] = {
                "_id":          bid,
                "name":         bot_name,
                "owner":        owner,
                "dir":          str(bot_dir),
                "files":        [fname],
                "enc_files":    enc_files,
                "env":          {},
                "plan":         d_db["users"].get(str(owner), {}).get("plan", "free"),
                "status":       "stopped",
                "approval_status": "approved",  # admin-deployed
                "created_at":   ts_iso(),
                "source":       f"github:{repo}/{path}",
                "last_exit_code": None,
            }
            d_db["bots"][bid] = new_bot
            db_save(d_db)
            audit(owner, "gh_run_file", f"repo={repo} path={path} bid={bid}")
            # Start the bot
            result = start_child(new_bot)
            if result.get("ok"):
                msg = (f"✅ <b>{esc(bot_name)}</b> {sc('deployed and started from GitHub!')}\n"
                       f"{bullet('Bot ID', f'<code>{bid}</code>')}\n"
                       f"{bullet('Source', f'{esc(repo)}/{esc(path)}')} ")
            else:
                msg = (f"⚠️ <b>{esc(bot_name)}</b> {sc('uploaded but failed to start')}.\n"
                       f"{bullet('Error', esc(str(result.get('error','?'))[:100]))}")
            bot.send_message(call.from_user.id, msg, parse_mode="HTML")
        except Exception as e:
            try:
                bot.send_message(call.from_user.id,
                                 f"{G['no']} {sc('Deploy error')}: <code>{esc(e)}</code>",
                                 parse_mode="HTML")
            except Exception:
                pass
    threading.Thread(target=_bg, daemon=True).start()


def action_adm_gh_dl_file(call: types.CallbackQuery, repo: str, path: str) -> None:
    """Download a raw file from GitHub and send it to admin."""
    if not repo or not path:
        ack(call, "No file selected"); return
    ack(call, "Downloading…")
    def _bg() -> None:
        try:
            branch = GH.get("branch", "main")
            ep = f"/repos/{repo}/contents/{path}?ref={branch}"
            ok, data = _gh_api_safe(ep)
            if not ok:
                bot.send_message(call.from_user.id, f"{G['no']} {esc(str(data)[:200])}"); return
            fname = data.get("name", Path(path).name)
            raw = base64.b64decode(data.get("content","").replace("\n",""))
            tmp = Path(tempfile.mktemp(suffix=f"_{fname}"))
            tmp.write_bytes(raw)
            with tmp.open("rb") as fh:
                bot.send_document(call.from_user.id, fh,
                                  caption=f"📥 {esc(fname)} ({fmt_bytes(len(raw))})\n"
                                          f"<code>{esc(repo)}/{esc(path)}</code>",
                                  visible_file_name=fname, parse_mode="HTML")
            tmp.unlink(missing_ok=True)
        except Exception as e:
            try:
                bot.send_message(call.from_user.id, f"{G['no']} {esc(e)}")
            except Exception:
                pass
    threading.Thread(target=_bg, daemon=True).start()


# ─────────────────────────────────────────────────────────────────────────────
# PAYMENT CONFIG PANEL
# ─────────────────────────────────────────────────────────────────────────────

def render_adm_pay_config(call: types.CallbackQuery) -> None:
    """Full payment configuration panel."""
    auto_approve = bool(get_setting("auto_approve_payments", False))
    min_amt = get_setting("min_payment_amount", 50)
    max_amt = get_setting("max_payment_amount", 10000)
    currency = get_setting("payment_currency", "BDT")
    currency_sym = get_setting("currency_symbol", "৳")
    tax_pct = get_setting("payment_tax_pct", 0)
    methods_enabled = sum(1 for m in PAYMENT_METHODS.values() if get_setting(f"pm_enabled_{m['name']}", True))
    notif_chan = get_setting("payment_notif_channel", "") or "—"
    cap = (
        f"<b>💳 {sc('Payment Configuration')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Auto-Approve',   '✅ ON' if auto_approve else '❌ OFF')}\n"
        f"{bullet('Min Amount',     f'{min_amt}{currency_sym}')}\n"
        f"{bullet('Max Amount',     f'{max_amt}{currency_sym}')}\n"
        f"{bullet('Currency',       f'{currency} ({currency_sym})')}\n"
        f"{bullet('Tax/Fee %',      f'{tax_pct}%')}\n"
        f"{bullet('Active Methods', methods_enabled)}\n"
        f"{bullet('Notif Channel',  esc(notif_chan))}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn(f"{'✅' if auto_approve else '❌'}  Aᴜᴛᴏ-Aᴘᴘʀ",
            callback_data="adm_pay_auto_approve",
            style="success" if auto_approve else "danger"),
        Btn("💰  Pᴀʏ Mᴇᴛʜᴏᴅꜱ",   callback_data="adm_pay_methods",      style="primary"),
    )
    kb.add(
        Btn("📊  Aᴍᴏᴜɴᴛ Lɪᴍɪᴛꜱ",  callback_data="adm_pay_limits",       style="primary"),
        Btn("💱  Cᴜʀʀᴇɴᴄʏ",        callback_data="adm_pay_currency",     style="primary"),
    )
    kb.add(
        Btn("🧾  Rᴇᴄᴇɪᴘᴛ Tᴇᴍᴘʟ",  callback_data="adm_pay_receipt_tmpl", style="primary"),
        Btn("🔔  Nᴏᴛɪꜰ Sᴇᴛᴛɪɴɢꜱ",  callback_data="adm_pay_notif",        style="primary"),
    )
    kb.add(
        Btn("🏷️  Sᴇᴛ Tᴀx %",       callback_data="adm_bc_set_payment_tax_pct",  style="primary"),
        Btn("📋  Pᴀʏ Hɪꜱᴛᴏʀʏ",    callback_data="adm_payments",         style="primary"),
    )
    kb.add(
        Btn("✅  Aᴘᴘʀᴏᴠᴇ Pᴀʏ",     callback_data="adm_approve",          style="success"),
        Btn("📤  Exᴘᴏʀᴛ CSV",       callback_data="adm_user_export_csv",  style="primary"),
    )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("pay_config", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_pay_methods(call: types.CallbackQuery) -> None:
    """Show all payment methods with enable/disable toggle."""
    rows = []
    for key, m in PAYMENT_METHODS.items():
        enabled = bool(get_setting(f"pm_enabled_{key}", True))
        rows.append(f"{'✅' if enabled else '❌'} <b>{esc(m['name'])}</b> — "
                    f"<code>{esc(m['number'])}</code> ({esc(m['type'])})")
    cap = (
        f"<b>💰 {sc('Payment Methods')}</b>\n"
        f"{G['div_eq']}\n"
        + "\n".join(rows)
        + f"\n{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    for key, m in PAYMENT_METHODS.items():
        enabled = bool(get_setting(f"pm_enabled_{key}", True))
        kb.add(
            Btn(f"{'✅' if enabled else '❌'} {esc(m['name'])}",
                callback_data=f"adm_pay_edit_{key}", style="primary"),
        )
    kb.add(Btn(f"{G['back']}  Pᴀʏ Cᴏɴꜰɪɢ", callback_data="adm_pay_config", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("pay_config", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_pay_method_edit(call: types.CallbackQuery, key: str) -> None:
    """Edit a single payment method."""
    m = PAYMENT_METHODS.get(key)
    if not m:
        ack(call, "Unknown method"); return
    enabled = bool(get_setting(f"pm_enabled_{key}", True))
    stored_num = get_setting(f"pm_number_{key}", m["number"]) or m["number"]
    cap = (
        f"<b>💰 {sc('Edit')} {esc(m['name'])}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Status',  '✅ Enabled' if enabled else '❌ Disabled')}\n"
        f"{bullet('Number',  esc(stored_num))}\n"
        f"{bullet('Type',    esc(m['type']))}\n"
        f"{bullet('Tag',     esc(m['tag']))}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn(f"{'❌ Disable' if enabled else '✅ Enable'}",
            callback_data=f"adm_pay_method_toggle_{key}",
            style="danger" if enabled else "success"),
        Btn("✏️  Cʜᴀɴɢᴇ Nᴜᴍʙᴇʀ",
            callback_data=f"adm_pay_method_setnumber_{key}", style="primary"),
    )
    kb.add(Btn(f"{G['back']}  Pᴀʏ Mᴇᴛʜᴏᴅꜱ", callback_data="adm_pay_methods", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("pay_config", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_pay_limits(call: types.CallbackQuery) -> None:
    min_amt = get_setting("min_payment_amount", 50)
    max_amt = get_setting("max_payment_amount", 10000)
    disc_threshold = get_setting("discount_threshold", 500)
    disc_pct  = get_setting("discount_pct", 5)
    cap = (
        f"<b>📊 {sc('Payment Amount Limits')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Min Payment',      f'{min_amt}৳')}\n"
        f"{bullet('Max Payment',      f'{max_amt}৳')}\n"
        f"{bullet('Discount >= ৳',   disc_threshold)}\n"
        f"{bullet('Discount %',       f'{disc_pct}%')}\n"
        f"{G['div']}\n"
        f"{sc('Set limits below. All values in your currency unit.')}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("📉  Sᴇᴛ Mɪɴ",         callback_data="adm_bc_set_min_payment_amount",  style="primary"),
        Btn("📈  Sᴇᴛ Mᴀx",         callback_data="adm_bc_set_max_payment_amount",  style="primary"),
    )
    kb.add(
        Btn("🎯  Dɪꜱᴄ Tʜʀᴇꜱʜᴏʟᴅ", callback_data="adm_bc_set_discount_threshold",  style="primary"),
        Btn("💸  Dɪꜱᴄ %",           callback_data="adm_bc_set_discount_pct",        style="primary"),
    )
    kb.add(Btn(f"{G['back']}  Pᴀʏ Cᴏɴꜰɪɢ", callback_data="adm_pay_config", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("pay_config", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_pay_currency(call: types.CallbackQuery) -> None:
    cur = get_setting("payment_currency", "BDT")
    sym = get_setting("currency_symbol",  "৳")
    cap = (
        f"<b>💱 {sc('Currency Settings')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Currency Code', cur)}\n"
        f"{bullet('Symbol',        sym)}\n"
        f"{G['div']}\n"
        f"{sc('Examples')}: BDT/৳, USD/$, EUR/€, INR/₹, PKR/₨{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("🔤  Sᴇᴛ Cᴏᴅᴇ",     callback_data="adm_bc_set_payment_currency", style="primary"),
        Btn("💲  Sᴇᴛ Sʏᴍʙᴏʟ",   callback_data="adm_bc_set_currency_symbol",  style="primary"),
    )
    for code, sym_str in [("BDT","৳"),("USD","$"),("EUR","€"),("INR","₹"),("PKR","₨")]:
        kb.add(Btn(f"{code} {sym_str}", callback_data=f"adm_bc_set_currency_{code}_{sym_str}", style="primary"))
    kb.add(Btn(f"{G['back']}  Pᴀʏ Cᴏɴꜰɪɢ", callback_data="adm_pay_config", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("pay_config", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_pay_receipt_tmpl(call: types.CallbackQuery) -> None:
    cur = get_setting("tmpl_payment_received", "") or _MESSAGE_TEMPLATES["payment_received"]["default"]
    cap = (
        f"<b>🧾 {sc('Payment Receipt Template')}</b>\n"
        f"{G['div_eq']}\n"
        f"<i>{sc('Current template')}:</i>\n<code>{esc(cur[:300])}</code>\n"
        f"{G['div']}\n{sc('Variables')}: <code>{{name}}, {{amount}}, {{plan}}, {{tx_id}}, {{date}}</code>{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("✏️  Eᴅɪᴛ",      callback_data="adm_tmpl_edit_payment_received", style="primary"),
        Btn("🔄  Rᴇꜱᴇᴛ",     callback_data="adm_tmpl_reset_payment_received", style="danger"),
    )
    kb.add(Btn(f"{G['back']}  Pᴀʏ Cᴏɴꜰɪɢ", callback_data="adm_pay_config", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("pay_config", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_pay_notif_settings(call: types.CallbackQuery) -> None:
    chan = get_setting("payment_notif_channel", "") or "—"
    on_new   = bool(get_setting("notif_on_new_payment", True))
    on_appr  = bool(get_setting("notif_on_approved",    True))
    on_rej   = bool(get_setting("notif_on_rejected",    True))
    cap = (
        f"<b>🔔 {sc('Payment Notifications')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Channel',    esc(chan))}\n"
        f"{bullet('New payment', '✅' if on_new else '❌')}\n"
        f"{bullet('Approved',   '✅' if on_appr else '❌')}\n"
        f"{bullet('Rejected',   '✅' if on_rej else '❌')}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(Btn("📣  Sᴇᴛ Cʜᴀɴɴᴇʟ", callback_data="adm_bc_set_payment_notif_channel", style="primary"))
    kb.add(
        Btn(f"{'✅' if on_new else '❌'}  Nᴇᴡ Pᴀʏ",  callback_data="adm_bc_toggle_notif_on_new_payment",  style="primary"),
        Btn(f"{'✅' if on_appr else '❌'}  Aᴘᴘʀᴏᴠᴇᴅ",callback_data="adm_bc_toggle_notif_on_approved",    style="primary"),
    )
    kb.add(Btn(f"{'✅' if on_rej else '❌'}  Rᴇᴊᴇᴄᴛᴇᴅ", callback_data="adm_bc_toggle_notif_on_rejected", style="primary"))
    kb.add(Btn(f"{G['back']}  Pᴀʏ Cᴏɴꜰɪɢ", callback_data="adm_pay_config", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("pay_config", PHOTOS["admin"]), cap, kb, call=call)


def action_adm_pay_method_number(call: types.CallbackQuery, data: str) -> None:
    """Handle toggle or set-number for a payment method."""
    if data.startswith("adm_pay_method_toggle_"):
        key = data[len("adm_pay_method_toggle_"):]
        cur = bool(get_setting(f"pm_enabled_{key}", True))
        set_setting(f"pm_enabled_{key}", not cur)
        audit(call.from_user.id, f"pm_toggle_{key}", f"now={not cur}")
        ack(call, f"{key}: {'enabled' if not cur else 'disabled'}")
        return render_adm_pay_method_edit(call, key)
    if data.startswith("adm_pay_method_setnumber_"):
        key = data[len("adm_pay_method_setnumber_"):]
        USER_STATES[call.from_user.id] = {"flow": "await_adm_pay_number", "pm_key": key}
        bot.send_message(call.message.chat.id,
                         f"{G['settings']} {sc('Send new payment number/address for')} "
                         f"<b>{esc(PAYMENT_METHODS.get(key,{}).get('name',key))}</b>:",
                         parse_mode="HTML")
        return


# ─────────────────────────────────────────────────────────────────────────────
# BOT CONFIG PANEL
# ─────────────────────────────────────────────────────────────────────────────

def _bc_get(key: str) -> Any:
    """Get a bot config value from settings, falling back to defaults."""
    return get_setting(f"bc_{key}", _BOT_CONFIG_DEFAULTS.get(key))


def _bc_set(key: str, val: Any) -> None:
    set_setting(f"bc_{key}", val)


def render_adm_bot_cfg(call: types.CallbackQuery) -> None:
    """Full bot configuration panel."""
    _mu  = str(_bc_get("max_upload_mb")) + " MB"
    _swd = str(_bc_get("sandbox_wipe_delay")) + "s"
    _bst = str(_bc_get("bot_start_timeout")) + "s"
    _bso = str(_bc_get("bot_stop_timeout")) + "s"
    _crd = str(_bc_get("crash_restart_delay")) + "s"
    cap = (
        f"<b>🔧 {sc('Bot Configuration')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Max Upload',          _mu)}\n"
        f"{bullet('Sandbox Wipe Delay',  _swd)}\n"
        f"{bullet('Start Timeout',       _bst)}\n"
        f"{bullet('Stop Timeout',        _bso)}\n"
        f"{bullet('Crash Restart Delay', _crd)}\n"
        f"{bullet('Max Crash Restarts',  _bc_get('max_crash_restarts'))}\n"
        f"{bullet('Log Ring Size',       _bc_get('log_ring_size'))}\n"
        f"{bullet('Zip Max Files',       _bc_get('zip_max_files'))}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("⏱️  Tɪᴍᴇᴏᴜᴛꜱ",       callback_data="adm_bc_timeouts",  style="primary"),
        Btn("📊  Lɪᴍɪᴛꜱ",           callback_data="adm_bc_limits",    style="primary"),
    )
    kb.add(
        Btn("📦  Uᴘʟᴏᴀᴅ Rᴜʟᴇꜱ",    callback_data="adm_bc_upload",    style="primary"),
        Btn("🔐  Eɴᴠ Sᴛʀɪᴘ",        callback_data="adm_bc_env",       style="danger"),
    )
    kb.add(
        Btn("🔄  Rᴇꜱᴛᴀʀᴛ Pᴏʟɪᴄʏ",  callback_data="adm_bc_policy",    style="primary"),
        Btn("🧱  Sᴀɴᴅʙᴏx",           callback_data="adm_bc_sandbox",   style="primary"),
    )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("bot_config", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_bc_timeouts(call: types.CallbackQuery) -> None:
    _t1 = str(_bc_get("bot_start_timeout")) + "s"
    _t2 = str(_bc_get("bot_stop_timeout")) + "s"
    _t3 = str(_bc_get("crash_restart_delay")) + "s"
    _t4 = str(_bc_get("idle_timeout_mins") or "Off")
    _t5 = str(_bc_get("resource_check_secs")) + "s"
    cap = (
        f"<b>⏱️ {sc('Timeout Settings')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Bot Start Timeout',       _t1)}\n"
        f"{bullet('Bot Stop Timeout',        _t2)}\n"
        f"{bullet('Crash Restart Delay',     _t3)}\n"
        f"{bullet('Idle Timeout (mins)',      _t4)}\n"
        f"{bullet('Resource Check Interval', _t5)}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    for k, label in [
        ("bot_start_timeout",   "Start Timeout"),
        ("bot_stop_timeout",    "Stop Timeout"),
        ("crash_restart_delay", "Crash Delay"),
        ("idle_timeout_mins",   "Idle Timeout"),
        ("resource_check_secs", "Res Check"),
    ]:
        kb.add(Btn(f"✏️  {label}", callback_data=f"adm_bc_set_{k}", style="primary"))
    kb.add(Btn(f"{G['back']}  Bᴏᴛ Cᴏɴꜰɪɢ", callback_data="adm_bot_cfg", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("bot_config", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_bc_limits(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>📊 {sc('Resource Limits')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Max Upload MB',       _bc_get('max_upload_mb'))}\n"
        f"{bullet('Max Crash Restarts',  _bc_get('max_crash_restarts'))}\n"
        f"{bullet('Log Ring Size',       _bc_get('log_ring_size'))}\n"
        f"{bullet('Zip Max Files',       _bc_get('zip_max_files'))}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    for k, label in [
        ("max_upload_mb",     "Max Upload MB"),
        ("max_crash_restarts","Max Crash Restarts"),
        ("log_ring_size",     "Log Ring Size"),
        ("zip_max_files",     "Zip Max Files"),
    ]:
        kb.add(Btn(f"✏️  {label}", callback_data=f"adm_bc_set_{k}", style="primary"))
    kb.add(Btn(f"{G['back']}  Bᴏᴛ Cᴏɴꜰɪɢ", callback_data="adm_bot_cfg", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("bot_config", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_bc_upload(call: types.CallbackQuery) -> None:
    exts = _bc_get("allowed_extensions") or ".py,.js,.zip"
    cap = (
        f"<b>📦 {sc('Upload Rules')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Max Upload',        str(_bc_get('max_upload_mb')) + ' MB')}\n"
        f"{bullet('Allowed Ext',       esc(str(exts)))}\n"
        f"{bullet('Zip Max Files',     _bc_get('zip_max_files'))}\n"
        f"{G['div']}\n"
        f"{sc('Allowed extensions are comma-separated. E.g.')} <code>.py,.js,.zip</code>{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("✏️  Max Upload MB",    callback_data="adm_bc_set_max_upload_mb",       style="primary"),
        Btn("✏️  Allowed Ext",      callback_data="adm_bc_set_allowed_extensions",  style="primary"),
    )
    kb.add(
        Btn("✏️  Zip Max Files",    callback_data="adm_bc_set_zip_max_files",       style="primary"),
    )
    kb.add(Btn(f"{G['back']}  Bᴏᴛ Cᴏɴꜰɪɢ", callback_data="adm_bot_cfg", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("bot_config", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_bc_env(call: types.CallbackQuery) -> None:
    strip = bool(_bc_get("env_strip_secrets"))
    names = list(SECRET_ENV_NAMES)
    cap = (
        f"<b>🔐 {sc('Environment Variable Control')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Strip Secrets', '✅ ON' if strip else '❌ OFF')}\n"
        f"{G['div']}\n"
        f"<b>{sc('Currently stripped env names')}:</b>\n"
        f"<code>{', '.join(names[:10])}</code>"
        f"{('...' if len(names) > 10 else '')}\n"
        f"{G['div']}\n{sc('When ON, child bots cannot access these env vars.')}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn(f"{'✅' if strip else '❌'}  Sᴛʀɪᴘ Sᴇᴄʀᴇᴛꜱ",
            callback_data="adm_bc_toggle_env_strip_secrets",
            style="success" if strip else "danger"),
        Btn("➕  Aᴅᴅ Sᴇᴄʀᴇᴛ Nᴀᴍᴇ",  callback_data="adm_bc_set_add_secret_name",   style="primary"),
    )
    kb.add(Btn(f"{G['back']}  Bᴏᴛ Cᴏɴꜰɪɢ", callback_data="adm_bot_cfg", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("bot_config", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_bc_sandbox(call: types.CallbackQuery) -> None:
    wipe   = bool(get_setting("ff_sandbox_wipe", True))
    delay  = _bc_get("sandbox_wipe_delay")
    net    = bool(_bc_get("sandbox_network"))
    cap = (
        f"<b>🧱 {sc('Sandbox Settings')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('File Wipe',   '✅ ON' if wipe else '❌ OFF')}\n"
        f"{bullet('Wipe Delay',  f'{delay}s after start')}\n"
        f"{bullet('Network',     '✅ Allowed' if net else '❌ Blocked')}\n"
        f"{G['div']}\n"
        f"<i>{sc('File Wipe removes source .py/.js files after bot starts so child bots cannot read their own code.')}</i>{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn(f"{'✅' if wipe else '❌'}  Fɪʟᴇ Wɪᴘᴇ",
            callback_data="adm_ff_toggle_sandbox_wipe",
            style="success" if wipe else "danger"),
        Btn("✏️  Wɪᴘᴇ Dᴇʟᴀʏ",     callback_data="adm_bc_set_sandbox_wipe_delay", style="primary"),
    )
    kb.add(
        Btn(f"{'✅' if net else '❌'}  Nᴇᴛᴡᴏʀᴋ",
            callback_data="adm_bc_toggle_sandbox_network",
            style="success" if net else "danger"),
    )
    kb.add(Btn(f"{G['back']}  Bᴏᴛ Cᴏɴꜰɪɢ", callback_data="adm_bot_cfg", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("bot_config", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_bc_policy(call: types.CallbackQuery) -> None:
    auto_r  = bool(get_setting("ff_auto_restart_bots", True))
    max_r   = _bc_get("max_crash_restarts")
    delay_r = _bc_get("crash_restart_delay")
    auto_dg = bool(get_setting("auto_downgrade_expired", True))
    cap = (
        f"<b>🔄 {sc('Restart & Policy')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Auto-Restart Crashed', '✅ ON' if auto_r else '❌ OFF')}\n"
        f"{bullet('Max Restarts/hour',    max_r)}\n"
        f"{bullet('Restart Delay',        str(delay_r) + 's')}\n"
        f"{bullet('Auto-Downgrade Expiry','✅ ON' if auto_dg else '❌ OFF')}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn(f"{'✅' if auto_r else '❌'}  Aᴜᴛᴏ-Rᴇꜱᴛᴀʀᴛ",
            callback_data="adm_ff_toggle_auto_restart_bots",
            style="success" if auto_r else "danger"),
        Btn("✏️  Mᴀx Rᴇꜱᴛᴀʀᴛꜱ",   callback_data="adm_bc_set_max_crash_restarts", style="primary"),
    )
    kb.add(
        Btn("✏️  Rᴇꜱᴛᴀʀᴛ Dᴇʟᴀʏ",  callback_data="adm_bc_set_crash_restart_delay", style="primary"),
        Btn(f"{'✅' if auto_dg else '❌'}  Aᴜᴛᴏ-Dɢ",
            callback_data="adm_sub_auto_downgrade",
            style="success" if auto_dg else "danger"),
    )
    kb.add(Btn(f"{G['back']}  Bᴏᴛ Cᴏɴꜰɪɢ", callback_data="adm_bot_cfg", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("bot_config", PHOTOS["admin"]), cap, kb, call=call)


# ─────────────────────────────────────────────────────────────────────────────
# APPEARANCE PANEL
# ─────────────────────────────────────────────────────────────────────────────

def render_adm_appearance(call: types.CallbackQuery) -> None:
    theme    = get_setting("ui_theme", "dark")
    brand    = BRAND_TAG
    footer   = (get_setting("custom_footer", "") or "")[:40]
    welcome  = bool(get_setting("custom_welcome", ""))
    rules    = bool(get_setting("hosting_rules",  ""))
    cap = (
        f"<b>🎨 {sc('Appearance & Branding')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Theme',     esc(theme))}\n"
        f"{bullet('Brand Tag', esc(brand))}\n"
        f"{bullet('Footer',    esc(footer or '(default)'))}\n"
        f"{bullet('Custom Welcome', '✅' if welcome else '❌ (default)')}\n"
        f"{bullet('Custom Rules',   '✅' if rules else '❌ (default)')}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("🎭  Tʜᴇᴍᴇꜱ",            callback_data="adm_app_theme",      style="primary"),
        Btn("🏷️  Bʀᴀɴᴅ Tᴀɢ",         callback_data="adm_set_brand",      style="primary"),
    )
    kb.add(
        Btn("📝  Fᴏᴏᴛᴇʀ Tᴇxᴛ",       callback_data="adm_set_footer_text",    style="primary"),
        Btn("👋  Wᴇʟᴄᴏᴍᴇ Mꜱɢ",      callback_data="adm_set_welcome_text",   style="primary"),
    )
    kb.add(
        Btn("📜  Rᴜʟᴇꜱ Tᴇxᴛ",        callback_data="adm_set_rules_text",     style="primary"),
        Btn("😀  Cᴜꜱᴛᴏᴍ Eᴍᴏᴊɪꜱ",     callback_data="adm_app_emojis",         style="primary"),
    )
    kb.add(
        Btn("🖼️  Mᴇɴᴜ Pʜᴏᴛᴏꜱ",      callback_data="adm_photos",             style="primary"),
        Btn("📣  Aɴɴ Cʜᴀɴɴᴇʟ",       callback_data="adm_set_announce",       style="primary"),
    )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("appearance", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_app_theme(call: types.CallbackQuery) -> None:
    cur = get_setting("ui_theme", "dark")
    cap = (
        f"<b>🎭 {sc('UI Themes')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Current')}: <b>{esc(cur)}</b>\n"
        f"{G['div']}\n"
        + "\n".join(
            f"{'✅' if k == cur else '  '} <b>{v['name']}</b> — "
            f"header={v['header']} accent={v['accent']} ok={v['emoji_ok']}"
            for k, v in _APPEARANCE_THEMES.items()
        )
        + f"\n{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    for k, v in _APPEARANCE_THEMES.items():
        kb.add(Btn(f"{'✅' if k == cur else '  '} {v['name']}",
                   callback_data=f"adm_app_theme_{k}", style="primary"))
    kb.add(Btn(f"{G['back']}  Aᴘᴘᴇᴀʀᴀɴᴄᴇ", callback_data="adm_appearance", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("appearance", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_app_emojis(call: types.CallbackQuery) -> None:
    custom_emojis = get_setting("custom_emojis", {}) or {}
    sample_keys = ["ok", "no", "warn", "bullet", "div", "shield", "key"]
    rows = "\n".join(
        f"{G['bullet']} <code>{k}</code>: {custom_emojis.get(k, G.get(k, '?'))} "
        f"{'<i>(custom)</i>' if k in custom_emojis else '<i>(default)</i>'}"
        for k in sample_keys
    )
    cap = (
        f"<b>😀 {sc('Custom Emojis')}</b>\n"
        f"{G['div_eq']}\n"
        f"{rows}\n"
        f"{G['div']}\n"
        f"{sc('Tap a key to set a custom emoji. Use')} <code>-</code> {sc('to reset.')}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    for k in sample_keys:
        kb.add(Btn(f"✏️ {k}: {custom_emojis.get(k, G.get(k,'?'))}",
                   callback_data=f"adm_app_emoji_set_{k}", style="primary"))
    kb.add(Btn("🔄  Rᴇꜱᴇᴛ Aʟʟ", callback_data="adm_app_emoji_reset", style="danger"))
    kb.add(Btn(f"{G['back']}  Aᴘᴘᴇᴀʀᴀɴᴄᴇ", callback_data="adm_appearance", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("appearance", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_app_banner(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>🖼️ {sc('Banner / Photo Settings')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Each menu section has its own banner image.')}\n"
        f"{sc('Use Menu Photos to update each one by name.')}\n"
        f"{G['div']}\n"
        f"{bullet('Sections', len(PHOTOS))}\n"
        f"{bullet('Cached file IDs', len(_PHOTO_FILE_IDS))}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(Btn("🖼️  Mᴇɴᴜ Pʜᴏᴛᴏꜱ", callback_data="adm_photos",     style="primary"))
    kb.add(Btn("🔄  Rᴇʙᴜɪʟᴅ Bᴀɴɴᴇʀꜱ", callback_data="adm_rebuild_banners", style="danger"))
    kb.add(Btn(f"{G['back']}  Aᴘᴘᴇᴀʀᴀɴᴄᴇ", callback_data="adm_appearance", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("appearance", PHOTOS["admin"]), cap, kb, call=call)


# ─────────────────────────────────────────────────────────────────────────────
# ADVANCED COUPON MANAGER
# ─────────────────────────────────────────────────────────────────────────────

def render_adm_coupon_plus(call: types.CallbackQuery) -> None:
    d = db_load()
    coupons = d["coupons"]
    total     = len(coupons)
    now_s     = ts_iso()
    active    = sum(1 for c in coupons.values()
                    if not (c.get("expiry") and c["expiry"] < now_s)
                    and c.get("uses_left", 1) != 0)
    expired   = total - active
    used_total = sum((c.get("max_uses", 1) - c.get("uses_left", 1))
                     for c in coupons.values() if c.get("max_uses"))
    cap = (
        f"<b>🎫 {sc('Advanced Coupon Manager')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Total Coupons',   total)}\n"
        f"{bullet('Active',          active)}\n"
        f"{bullet('Expired/Used',    expired)}\n"
        f"{bullet('Total Redemptions', used_total)}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("➕  Cʀᴇᴀᴛᴇ Cᴏᴜᴘᴏɴ",   callback_data="adm_coupons",          style="success"),
        Btn("🗂️  Bᴜʟᴋ Cʀᴇᴀᴛᴇ",      callback_data="adm_coupon_bulk",      style="primary"),
    )
    kb.add(
        Btn("📊  Aɴᴀʟʏᴛɪᴄꜱ",        callback_data="adm_coupon_analytics", style="primary"),
        Btn("⏰  Exᴘɪʀʏ Mɢʀ",        callback_data="adm_coupon_expiry",    style="primary"),
    )
    kb.add(
        Btn("🗑️  Cʟᴇᴀʀ Exᴘɪʀᴇᴅ",   callback_data="adm_coupon_clearexp",  style="danger"),
        Btn("📋  Aʟʟ Cᴏᴜᴘᴏɴꜱ",      callback_data="adm_coupons",          style="primary"),
    )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("coupon_plus", PHOTOS["coupon"]), cap, kb, call=call)


def render_adm_coupon_bulk(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>🗂️ {sc('Bulk Create Coupons')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Format (one per line or send count')}:\n"
        f"<code>count plan discount_pct [max_uses] [days_valid]</code>\n"
        f"{sc('Example')}:\n"
        f"<code>10 pro 20 1 30</code>\n"
        f"→ {sc('Creates 10 single-use coupons for pro plan at 20% off, valid 30 days')}{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_adm_coupon_bulk"}
    show_menu(call.message.chat.id, PHOTOS.get("coupon_plus", PHOTOS["coupon"]), cap,
              _adm_back("adm_coupon_plus"), call=call)


def render_adm_coupon_analytics(call: types.CallbackQuery) -> None:
    coupons = db_load()["coupons"]
    now_s = ts_iso()
    by_plan: Dict[str, int] = defaultdict(int)
    by_discount: Dict[int, int] = defaultdict(int)
    total_savings: float = 0.0
    for c in coupons.values():
        pl = c.get("plan", "any")
        by_plan[pl] += 1
        disc = int(c.get("discount", c.get("pct", 0)))
        by_discount[disc] += 1
        used = c.get("max_uses", 1) - c.get("uses_left", 1)
        if used and c.get("plan") and PLAN_LIMITS.get(c["plan"]):
            price = PLAN_LIMITS[c["plan"]]["price"]
            total_savings += price * disc / 100 * used
    plan_rows = "\n".join(f"  {G['bullet']} {k}: {v}" for k, v in sorted(by_plan.items()))
    cap = (
        f"<b>📊 {sc('Coupon Analytics')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Total Coupons',    len(coupons))}\n"
        f"{bullet('Total Savings Given', f'{total_savings:.0f}৳')}\n"
        f"{G['div']}\n<b>{sc('By Plan')}:</b>\n{plan_rows}\n{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS.get("coupon_plus", PHOTOS["coupon"]), cap,
              _adm_back("adm_coupon_plus"), call=call)


def render_adm_coupon_expiry(call: types.CallbackQuery) -> None:
    coupons = db_load()["coupons"]
    now_s = ts_iso()
    expiring_soon = [
        (code, c) for code, c in coupons.items()
        if c.get("expiry") and c["expiry"] > now_s
        and c["expiry"] <= (now_utc() + timedelta(days=7)).isoformat()
    ]
    expired = [
        (code, c) for code, c in coupons.items()
        if c.get("expiry") and c["expiry"] < now_s
    ]
    rows_soon = "\n".join(
        f"{G['bullet']} <code>{esc(code)}</code> expires <i>{str(c['expiry'])[:10]}</i>"
        for code, c in expiring_soon[:10]
    ) or f"<i>{sc('None expiring soon')}</i>"
    cap = (
        f"<b>⏰ {sc('Coupon Expiry Manager')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Expiring in 7 days', len(expiring_soon))}\n"
        f"{bullet('Already expired',    len(expired))}\n"
        f"{G['div']}\n<b>{sc('Expiring soon')}:</b>\n{rows_soon}\n{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(Btn("🗑️  Cʟᴇᴀʀ Exᴘɪʀᴇᴅ", callback_data="adm_coupon_clearexp", style="danger"))
    kb.add(Btn(f"{G['back']}  Cᴏᴜᴘᴏɴ Mɢʀ", callback_data="adm_coupon_plus", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("coupon_plus", PHOTOS["coupon"]), cap, kb, call=call)


# ─────────────────────────────────────────────────────────────────────────────
# TEMPLATE MANAGER
# ─────────────────────────────────────────────────────────────────────────────

def render_adm_templates(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>📝 {sc('Message Template Manager')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Customize every message the bot sends. Use placeholders like')} "
        f"<code>{{name}}</code>, <code>{{plan}}</code>, <code>{{amount}}</code> {sc('etc.')}\n"
        f"{G['div']}\n"
        + "\n".join(
            f"{G['bullet']} <b>{esc(v['label'])}</b> "
            f"{'✅ custom' if get_setting(f'tmpl_{k}') else '📄 default'}"
            for k, v in _MESSAGE_TEMPLATES.items()
        )
        + f"\n{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    for k, v in _MESSAGE_TEMPLATES.items():
        has_custom = bool(get_setting(f"tmpl_{k}"))
        kb.add(Btn(f"{'✅' if has_custom else '📄'} {v['label'][:25]}",
                   callback_data=f"adm_tmpl_edit_{k}", style="primary"))
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("templates", PHOTOS["admin"]), cap, kb, call=call)


# ─────────────────────────────────────────────────────────────────────────────
# REFERRAL SYSTEM
# ─────────────────────────────────────────────────────────────────────────────

def render_adm_referral_sys(call: types.CallbackQuery) -> None:
    enabled   = bool(get_setting("referral_enabled", True))
    reward    = get_setting("referral_reward_amount", 20)
    min_plan  = get_setting("referral_min_plan", "free")
    d = db_load()
    total_refs = sum(len(u.get("referrals", [])) for u in d["users"].values())
    total_paid = sum(u.get("referral_earnings", 0) for u in d["users"].values())
    cap = (
        f"<b>🔗 {sc('Referral System')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Status',        '✅ Enabled' if enabled else '❌ Disabled')}\n"
        f"{bullet('Reward/Refer',  f'{reward}৳ wallet credit')}\n"
        f"{bullet('Min Plan',      min_plan)}\n"
        f"{bullet('Total Referrals', total_refs)}\n"
        f"{bullet('Total Paid Out',  f'{total_paid}৳')}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn(f"{'✅ Enabled' if enabled else '❌ Disabled'}",
            callback_data="adm_ref_toggle",
            style="success" if enabled else "danger"),
        Btn("📊  Rᴇꜰ Sᴛᴀᴛꜱ",    callback_data="adm_ref_stats",       style="primary"),
    )
    kb.add(
        Btn("🎁  Rᴇᴡᴀʀᴅ Cᴏɴꜰɪɢ",callback_data="adm_ref_rewards",     style="primary"),
        Btn("🏆  Lᴇᴀᴅᴇʀʙᴏᴀʀᴅ",   callback_data="adm_ref_leaderboard", style="primary"),
    )
    kb.add(
        Btn("✏️  Sᴇᴛ Rᴇᴡᴀʀᴅ ৳", callback_data="adm_ref_set_reward",   style="primary"),
        Btn("✏️  Sᴇᴛ Mɪɴ Pʟᴀɴ", callback_data="adm_ref_set_min_plan", style="primary"),
    )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("referral_adm", PHOTOS["referral"]), cap, kb, call=call)


def render_adm_ref_stats(call: types.CallbackQuery) -> None:
    d = db_load()
    users = d["users"]
    top_refs   = sorted(users.items(), key=lambda x: len(x[1].get("referrals",[])), reverse=True)[:5]
    total_refs = sum(len(u.get("referrals",[])) for u in users.values())
    total_paid = sum(u.get("referral_earnings",0) for u in users.values())
    today_s    = now_utc().strftime("%Y-%m-%d")
    today_refs = sum(
        sum(1 for r in u.get("referrals",[]) if str(r.get("ts","")).startswith(today_s))
        for u in users.values()
    )
    rows = "\n".join(
        f"{i}. {esc(u.get('name','?')[:20])} — {len(u.get('referrals',[]))} refs "
        f"| earned {u.get('referral_earnings',0)}৳"
        for i, (uid, u) in enumerate(top_refs, 1)
    ) or f"<i>{sc('No referrals yet')}</i>"
    cap = (
        f"<b>📊 {sc('Referral Statistics')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Total Referrals', total_refs)}\n"
        f"{bullet('Today',           today_refs)}\n"
        f"{bullet('Total Paid',      f'{total_paid}৳')}\n"
        f"{G['div']}\n<b>{sc('Top Referrers')}:</b>\n{rows}\n{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS.get("referral_adm", PHOTOS["referral"]), cap,
              _adm_back("adm_referral_sys"), call=call)


def render_adm_ref_rewards(call: types.CallbackQuery) -> None:
    reward = get_setting("referral_reward_amount", 20)
    bonus_plan = get_setting("referral_bonus_plan", "")
    bonus_refs = get_setting("referral_bonus_threshold", 10)
    cap = (
        f"<b>🎁 {sc('Referral Reward Config')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Base Reward',         f'{reward}৳ per referral')}\n"
        f"{bullet('Bonus Plan',          bonus_plan or 'None')}\n"
        f"{bullet('Bonus Threshold',     f'{bonus_refs} refs needed for bonus')}\n"
        f"{G['div']}\n"
        f"{sc('Set a bonus plan reward for power referrers who hit the threshold.')}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("💰  Sᴇᴛ Bᴀꜱᴇ Rᴇᴡᴀʀᴅ",   callback_data="adm_ref_set_reward",      style="primary"),
        Btn("✏️  Sᴇᴛ Bᴏɴᴜꜱ Tʜʀ",     callback_data="adm_bc_set_referral_bonus_threshold", style="primary"),
    )
    kb.add(Btn(f"{G['back']}  Rᴇꜰᴇʀʀᴀʟ Sʏꜱ", callback_data="adm_referral_sys", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("referral_adm", PHOTOS["referral"]), cap, kb, call=call)


def render_adm_ref_leaderboard(call: types.CallbackQuery) -> None:
    users = db_load()["users"]
    top = sorted(users.items(),
                 key=lambda x: len(x[1].get("referrals",[])), reverse=True)[:15]
    rows = "\n".join(
        f"{i}. <b>{esc(u.get('name','?')[:20])}</b> — "
        f"{len(u.get('referrals',[]))} {sc('refs')} | "
        f"{u.get('referral_earnings',0)}৳ {sc('earned')}"
        for i, (uid, u) in enumerate(top, 1)
    ) or f"<i>{sc('No referrals yet')}</i>"
    cap = (
        f"<b>🏆 {sc('Referral Leaderboard')}</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS.get("referral_adm", PHOTOS["referral"]), cap,
              _adm_back("adm_referral_sys"), call=call)


# ─────────────────────────────────────────────────────────────────────────────
# JANITOR (AUTO-CLEANUP)
# ─────────────────────────────────────────────────────────────────────────────

def render_adm_janitor(call: types.CallbackQuery) -> None:
    flags = {
        "clean_orphan_dirs":    "Auto-clean orphan sandboxes",
        "clean_old_logs":       "Auto-clear old logs (>7 days)",
        "clean_expired_coupons":"Auto-remove expired coupons",
        "auto_ban_rate_abuse":  "Auto-ban rate limit abusers",
        "clean_old_audit":      "Trim audit log (>1000 entries)",
        "notify_crashed":       "Notify owner on bot crash",
    }
    cap = (
        f"<b>🧹 {sc('Janitor — Auto-Cleanup Rules')}</b>\n"
        f"{G['div_eq']}\n"
        + "\n".join(
            f"{'✅' if get_setting(f'jan_{k}', False) else '❌'} {v}"
            for k, v in flags.items()
        )
        + f"\n{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    for k, v in flags.items():
        on = bool(get_setting(f"jan_{k}", False))
        kb.add(Btn(f"{'✅' if on else '❌'} {v[:28]}",
                   callback_data=f"adm_jan_toggle_{k}", style="primary"))
    kb.add(
        Btn("▶️  Rᴜɴ Nᴏᴡ",         callback_data="adm_jan_run_now",   style="success"),
        Btn("📋  Jᴀɴ Rᴜʟᴇꜱ",       callback_data="adm_jan_rules",     style="primary"),
    )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("janitor", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_jan_rules(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>📋 {sc('Janitor Rule Details')}</b>\n"
        f"{G['div_eq']}\n"
        f"<b>{sc('Orphan Sandbox Cleanup')}:</b>\n"
        f"  {sc('Removes sandbox dirs with no matching bot record.')}\n\n"
        f"<b>{sc('Old Log Cleanup')}:</b>\n"
        f"  {sc('Clears log files older than 7 days from disk.')}\n\n"
        f"<b>{sc('Expired Coupon Cleanup')}:</b>\n"
        f"  {sc('Removes coupons past their expiry date automatically.')}\n\n"
        f"<b>{sc('Rate Abuse Auto-Ban')}:</b>\n"
        f"  {sc('Bans users exceeding rate limits 3+ times in 24h.')}\n\n"
        f"<b>{sc('Audit Log Trim')}:</b>\n"
        f"  {sc('Keeps only the last 1000 audit entries.')}\n\n"
        f"<b>{sc('Crash Notifications')}:</b>\n"
        f"  {sc('Sends owner a message when any bot crashes.')}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS.get("janitor", PHOTOS["admin"]), cap,
              _adm_back("adm_janitor"), call=call)


def render_adm_jan_schedule(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>⏰ {sc('Janitor Schedule')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Orphan cleanup',        'Every 6 hours')}\n"
        f"{bullet('Log cleanup',           'Daily at 03:00')}\n"
        f"{bullet('Coupon cleanup',        'Daily at 04:00')}\n"
        f"{bullet('Audit trim',            'Daily at 05:00')}\n"
        f"{bullet('Rate abuse check',      'Every 30 minutes')}\n"
        f"{G['div']}\n"
        f"<i>{sc('Janitor runs automatically in background threads.')}</i>{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS.get("janitor", PHOTOS["admin"]), cap,
              _adm_back("adm_janitor"), call=call)


def action_adm_jan_run(admin_uid: int) -> None:
    """Run all enabled janitor tasks immediately."""
    results: List[str] = []
    # Orphan cleanup
    if get_setting("jan_clean_orphan_dirs", False):
        try:
            dirs, files = _do_clean_orphans()
            results.append(f"✅ Orphan cleanup: {dirs} dirs, {files} files removed")
        except Exception as e:
            results.append(f"❌ Orphan cleanup: {e}")
    # Expired coupons
    if get_setting("jan_clean_expired_coupons", False):
        try:
            d = db_load()
            now_s = ts_iso()
            before = len(d["coupons"])
            d["coupons"] = {k: v for k, v in d["coupons"].items()
                            if not (v.get("expiry") and v["expiry"] < now_s)}
            removed = before - len(d["coupons"])
            db_save(d)
            results.append(f"✅ Expired coupons: {removed} removed")
        except Exception as e:
            results.append(f"❌ Coupon cleanup: {e}")
    # Audit trim
    if get_setting("jan_clean_old_audit", False):
        try:
            d = db_load()
            before = len(d.get("audit", []))
            d["audit"] = d.get("audit", [])[-1000:]
            db_save(d)
            results.append(f"✅ Audit trim: kept last 1000 of {before}")
        except Exception as e:
            results.append(f"❌ Audit trim: {e}")
    audit(admin_uid, "janitor_run_now", f"tasks={len(results)}")
    summary = "\n".join(results) or "No janitor tasks enabled"
    try:
        bot.send_message(admin_uid,
                         f"<b>🧹 {sc('Janitor Report')}</b>\n{G['div_eq']}\n{summary}",
                         parse_mode="HTML")
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# WEBHOOK MANAGER
# ─────────────────────────────────────────────────────────────────────────────

def render_adm_webhooks(call: types.CallbackQuery) -> None:
    wh_url = get_setting("webhook_url", "") or ""
    wh_info: Dict[str, Any] = {}
    if wh_url:
        try:
            wh_info = bot.get_webhook_info().__dict__
        except Exception:
            wh_info = {}
    mode = "Webhook" if wh_url else "Long Polling"
    pending = wh_info.get("pending_update_count", 0)
    last_err= wh_info.get("last_error_message", "—")
    cap = (
        f"<b>🌐 {sc('Webhook Manager')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Mode',           mode)}\n"
        f"{bullet('Webhook URL',    esc(wh_url[:50]) if wh_url else '—')}\n"
        f"{bullet('Pending Updates',pending)}\n"
        f"{bullet('Last Error',     esc(str(last_err)[:50]))}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("🔗  Sᴇᴛ Wᴇʙʜᴏᴏᴋ",    callback_data="adm_wh_set",   style="primary"),
        Btn("❌  Cʟᴇᴀʀ (Pᴏʟʟɪɴɢ)", callback_data="adm_wh_clear", style="danger"),
    )
    kb.add(
        Btn("🧪  Tᴇꜱᴛ Wᴇʙʜᴏᴏᴋ",   callback_data="adm_wh_test",  style="primary"),
        Btn("ℹ️  Wᴇʙʜᴏᴏᴋ Iɴꜰᴏ",   callback_data="adm_wh_info",  style="primary"),
    )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("webhooks", PHOTOS["admin"]), cap, kb, call=call)


def action_adm_wh_test(call: types.CallbackQuery) -> None:
    wh_url = get_setting("webhook_url", "")
    if not wh_url:
        ack(call, "No webhook URL set"); return
    ack(call, "Testing webhook…")
    def _bg() -> None:
        try:
            import urllib.request as _ur
            import json as _j
            payload = _j.dumps({"test": True, "ts": ts_iso(), "from": "SimranHostingBot"}).encode()
            req = _ur.Request(wh_url, data=payload, method="POST")
            req.add_header("Content-Type", "application/json")
            with _ur.urlopen(req, timeout=10) as resp:
                status = resp.status
            bot.send_message(call.from_user.id,
                             f"{G['ok']} {sc('Webhook test')}: HTTP {status} ✅")
        except Exception as e:
            try:
                bot.send_message(call.from_user.id,
                                 f"{G['no']} {sc('Webhook test failed')}: <code>{esc(e)}</code>",
                                 parse_mode="HTML")
            except Exception:
                pass
    threading.Thread(target=_bg, daemon=True).start()


def render_adm_wh_info(call: types.CallbackQuery) -> None:
    try:
        wi = bot.get_webhook_info()
        cap = (
            f"<b>ℹ️ {sc('Webhook Info')}</b>\n"
            f"{G['div_eq']}\n"
            f"{bullet('URL',             esc(str(wi.url or '—')[:60]))}\n"
            f"{bullet('Has Cert',        wi.has_custom_certificate)}\n"
            f"{bullet('Pending',         wi.pending_update_count)}\n"
            f"{bullet('Max Connections', wi.max_connections)}\n"
            f"{bullet('Last Error',      esc(str(wi.last_error_message or '—')[:60]))}\n"
            f"{bullet('Last Error Time', fmt_ts(wi.last_error_date))}\n"
            f"{bullet('IP Address',      wi.ip_address or '—')}\n"
            f"{G['div']}{FOOTER}"
        )
    except Exception as e:
        cap = f"{G['no']} {sc('Error')}: <code>{esc(e)}</code>{FOOTER}"
    show_menu(call.message.chat.id, PHOTOS.get("webhooks", PHOTOS["admin"]), cap,
              _adm_back("adm_webhooks"), call=call)


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE FLAGS
# ─────────────────────────────────────────────────────────────────────────────

def _ff_get(key: str) -> bool:
    return bool(get_setting(f"ff_{key}", _FEATURE_FLAG_DEFAULTS.get(key, True)))


def render_adm_feature_flags(call: types.CallbackQuery) -> None:
    rows = []
    for k, default in _FEATURE_FLAG_DEFAULTS.items():
        val = _ff_get(k)
        rows.append(f"{'✅' if val else '❌'} <code>{k}</code>")
    cap = (
        f"<b>🎯 {sc('Feature Flags')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Toggle any system feature on or off instantly.')}\n"
        f"{G['div']}\n"
        + "\n".join(rows)
        + f"\n{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    for k in list(_FEATURE_FLAG_DEFAULTS.keys()):
        val = _ff_get(k)
        label = k.replace("_"," ").title()[:20]
        kb.add(Btn(f"{'✅' if val else '❌'} {label}",
                   callback_data=f"adm_ff_toggle_{k}", style="primary"))
    kb.add(Btn("🔄  Rᴇꜱᴇᴛ Aʟʟ Fʟᴀɢꜱ", callback_data="adm_ff_reset_all", style="danger"))
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("features", PHOTOS["admin"]), cap, kb, call=call)


# ─────────────────────────────────────────────────────────────────────────────
# RATE LIMITER CONFIG
# ─────────────────────────────────────────────────────────────────────────────

def render_adm_rate_config(call: types.CallbackQuery) -> None:
    global_rl = _ff_get("rate_limiting")
    cap = (
        f"<b>⏱️ {sc('Rate Limit Configuration')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Global Rate Limiting', '✅ ON' if global_rl else '❌ OFF')}\n"
        f"{G['div']}\n"
        + "\n".join(
            f"<b>{PLAN_LIMITS.get(plan,{}).get('name', plan)}</b>: "
            f"↑{get_setting(f'rl_{plan}_uploads_per_day', d['uploads_per_day'])}/day "
            f"▶{get_setting(f'rl_{plan}_starts_per_hour', d['starts_per_hour'])}/hr "
            f"💬{get_setting(f'rl_{plan}_msgs_per_min', d['msgs_per_min'])}/min"
            for plan, d in _RATE_LIMIT_DEFAULTS.items()
        )
        + f"\n{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn(f"{'✅ ON' if global_rl else '❌ OFF'}  Gʟᴏʙᴀʟ RL",
            callback_data="adm_ff_toggle_rate_limiting",
            style="success" if global_rl else "danger"),
    )
    for plan in _RATE_LIMIT_DEFAULTS:
        name = PLAN_LIMITS.get(plan, {}).get("name", plan)[:10]
        kb.add(Btn(f"✏️  {name}", callback_data=f"adm_rate_plan_{plan}", style="primary"))
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("rate_limits", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_rate_plan(call: types.CallbackQuery, plan: str) -> None:
    d = _RATE_LIMIT_DEFAULTS.get(plan, {})
    name = PLAN_LIMITS.get(plan, {}).get("name", plan)
    cap = (
        f"<b>⏱️ {sc('Rate Limits for')} {esc(name)}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Uploads/Day',    get_setting(f'rl_{plan}_uploads_per_day', d.get('uploads_per_day')))}\n"
        f"{bullet('Starts/Hour',    get_setting(f'rl_{plan}_starts_per_hour', d.get('starts_per_hour')))}\n"
        f"{bullet('Messages/Min',   get_setting(f'rl_{plan}_msgs_per_min',    d.get('msgs_per_min')))}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=1)
    for metric in ("uploads_per_day", "starts_per_hour", "msgs_per_min"):
        kb.add(Btn(f"✏️  {metric.replace('_',' ').title()}",
                   callback_data=f"adm_rate_set_{plan}_{metric}", style="primary"))
    kb.add(Btn(f"{G['back']}  Rᴀᴛᴇ Cᴏɴꜰɪɢ", callback_data="adm_rate_config", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("rate_limits", PHOTOS["admin"]), cap, kb, call=call)


# ─────────────────────────────────────────────────────────────────────────────
# LIVE MONITOR
# ─────────────────────────────────────────────────────────────────────────────

def render_adm_live_monitor(call: types.CallbackQuery) -> None:
    running_bots = [(bid, info) for bid, info in RUNNING.items()
                    if info["proc"].poll() is None]
    crashed_bots = [(bid, info) for bid, info in RUNNING.items()
                    if info["proc"].poll() is not None]
    total_child_ram = 0
    total_child_cpu = 0.0
    if psutil:
        for bid, info in running_bots:
            try:
                p = psutil.Process(info["proc"].pid)
                total_child_ram += p.memory_info().rss
                total_child_cpu += p.cpu_percent(interval=0)
            except Exception:
                pass
    panel_ram = panel_cpu = 0
    if psutil:
        try:
            pp = psutil.Process(os.getpid())
            panel_ram = pp.memory_info().rss
            panel_cpu = pp.cpu_percent(interval=0.1)
        except Exception:
            pass
    up_s = int(time.time() - START_TIME) if "START_TIME" in globals() else 0
    cap = (
        f"<b>📡 {sc('Live Monitor')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Panel Uptime',   fmt_dur(up_s * 1000))}\n"
        f"{bullet('Panel RAM',      fmt_bytes(panel_ram))}\n"
        f"{bullet('Panel CPU',      f'{panel_cpu:.1f}%')}\n"
        f"{G['div']}\n"
        f"{bullet('▶ Running Bots',  len(running_bots))}\n"
        f"{bullet('💥 Crashed',      len(crashed_bots))}\n"
        f"{bullet('Child RAM Total', fmt_bytes(total_child_ram))}\n"
        f"{bullet('Child CPU Total', f'{total_child_cpu:.1f}%')}\n"
        f"{G['div']}\n"
        + "\n".join(
            f"  {G['bullet']} <code>{bid[:8]}</code> "
            f"{esc(info.get('name','?')[:18])}"
            for bid, info in running_bots[:8]
        )
        + f"\n{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("🔄  Rᴇꜰʀᴇꜱʜ",         callback_data="adm_monitor_refresh",  style="success"),
        Btn("🤖  Bᴏᴛ Dᴇᴛᴀɪʟꜱ",     callback_data="adm_monitor_bots",     style="primary"),
    )
    kb.add(
        Btn("🖥️  Sʏꜱᴛᴇᴍ",           callback_data="adm_monitor_system",   style="primary"),
        Btn("💥  Cʀᴀꜱʜᴇᴅ",          callback_data="adm_crashed_bots",     style="danger"),
    )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("monitor", PHOTOS["stats"]), cap, kb, call=call)


def render_adm_monitor_bots(call: types.CallbackQuery) -> None:
    rows: List[str] = []
    for bid, info in list(RUNNING.items())[:20]:
        rc = info["proc"].poll()
        is_running = rc is None
        b = find_bot(bid)
        name = (b.get("name","?") if b else bid)[:20]
        pid  = info["proc"].pid
        rss  = 0
        cpu  = 0.0
        if psutil and is_running:
            try:
                p = psutil.Process(pid)
                rss = p.memory_info().rss
                cpu = p.cpu_percent(interval=0)
            except Exception:
                pass
        status = "▶ running" if is_running else f"⏹ exit={rc}"
        rows.append(
            f"{G['bullet']} <b>{esc(name)}</b> <code>{bid[:8]}</code>\n"
            f"   {status} | PID {pid} | {fmt_bytes(rss)} | CPU {cpu:.1f}%"
        )
    cap = (
        f"<b>🤖 {sc('Bot Monitor')} ({len(RUNNING)} total)</b>\n"
        f"{G['div_eq']}\n"
        + ("\n".join(rows) or f"<i>{sc('No bots running')}</i>")
        + f"\n{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS.get("monitor", PHOTOS["stats"]), cap,
              _adm_back("adm_live_monitor"), call=call)


def render_adm_monitor_system(call: types.CallbackQuery) -> None:
    cpu_pct = mem_pct = disk_pct = 0.0
    load1 = load5 = load15 = 0.0
    if psutil:
        try:
            cpu_pct  = psutil.cpu_percent(interval=0.3)
            vm       = psutil.virtual_memory()
            mem_pct  = vm.percent
            du       = psutil.disk_usage("/")
            disk_pct = du.percent
        except Exception:
            pass
    try:
        load1, load5, load15 = os.getloadavg()
    except Exception:
        pass
    def bar(pct: float) -> str:
        filled = int(pct / 10)
        return "█" * filled + "░" * (10 - filled) + f" {pct:.1f}%"
    cap = (
        f"<b>🖥️ {sc('System Monitor')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('CPU',       bar(cpu_pct))}\n"
        f"{bullet('Memory',    bar(mem_pct))}\n"
        f"{bullet('Disk',      bar(disk_pct))}\n"
        f"{bullet('Load 1m',   f'{load1:.2f}')}\n"
        f"{bullet('Load 5m',   f'{load5:.2f}')}\n"
        f"{bullet('Load 15m',  f'{load15:.2f}')}\n"
        f"{bullet('Threads',   threading.active_count())}\n"
        f"{bullet('PID',       os.getpid())}\n"
        f"{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS.get("monitor", PHOTOS["stats"]), cap,
              _adm_back("adm_live_monitor"), call=call)


# ─────────────────────────────────────────────────────────────────────────────
# REVENUE GOALS
# ─────────────────────────────────────────────────────────────────────────────

def render_adm_rev_goals(call: types.CallbackQuery) -> None:
    pays = db_load()["payments"]
    now  = now_utc()
    month_start = now.replace(day=1, hour=0, minute=0, second=0).strftime("%Y-%m")
    year_start  = now.strftime("%Y")
    rev_month = sum(p.get("amount",0) for p in pays
                    if p.get("status")=="approved" and str(p.get("ts","")).startswith(month_start))
    rev_year  = sum(p.get("amount",0) for p in pays
                    if p.get("status")=="approved" and str(p.get("ts","")).startswith(year_start))
    rev_all   = sum(p.get("amount",0) for p in pays if p.get("status")=="approved")
    goal_month = get_setting("rev_goal_monthly", 0)
    goal_year  = get_setting("rev_goal_yearly",  0)
    def progress_bar(cur: float, goal: float) -> str:
        if not goal:
            return "— (no goal set)"
        pct = min(100, cur * 100 / goal)
        filled = int(pct / 5)
        return "█" * filled + "░" * (20 - filled) + f" {pct:.1f}%"
    cap = (
        f"<b>💎 {sc('Revenue Goals')}</b>\n"
        f"{G['div_eq']}\n"
        f"<b>{sc('This Month')} ({month_start})</b>\n"
        f"  {sc('Earned')}: <b>{rev_month}৳</b> / {goal_month or '?'}৳\n"
        f"  {progress_bar(rev_month, goal_month)}\n"
        f"{G['div']}\n"
        f"<b>{sc('This Year')} ({year_start})</b>\n"
        f"  {sc('Earned')}: <b>{rev_year}৳</b> / {goal_year or '?'}৳\n"
        f"  {progress_bar(rev_year, goal_year)}\n"
        f"{G['div']}\n"
        f"{bullet('All Time',   f'{rev_all}৳')}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("🎯  Sᴇᴛ Mᴏɴᴛʜʟʏ Gᴏᴀʟ", callback_data="adm_goal_set_monthly", style="primary"),
        Btn("🎯  Sᴇᴛ Yᴇᴀʀʟʏ Gᴏᴀʟ",  callback_data="adm_goal_set_yearly",  style="primary"),
    )
    kb.add(
        Btn("📈  Hɪꜱᴛᴏʀʏ",           callback_data="adm_goal_history",     style="primary"),
        Btn("📊  Rᴇᴠᴇɴᴜᴇ Rᴇᴘᴏʀᴛ",   callback_data="adm_revenue_report",   style="primary"),
    )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("rev_goals", PHOTOS["stats"]), cap, kb, call=call)


def render_adm_goal_history(call: types.CallbackQuery) -> None:
    pays  = db_load()["payments"]
    now   = now_utc()
    months: Dict[str, float] = defaultdict(float)
    for p in pays:
        if p.get("status") != "approved":
            continue
        ts = str(p.get("ts", ""))
        if len(ts) >= 7:
            months[ts[:7]] += p.get("amount", 0)
    rows = "\n".join(
        f"{G['bullet']} <b>{m}</b>: {amt:.0f}৳"
        for m, amt in sorted(months.items(), reverse=True)[:12]
    ) or f"<i>{sc('No revenue data')}</i>"
    cap = (
        f"<b>📈 {sc('Monthly Revenue History')}</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS.get("rev_goals", PHOTOS["stats"]), cap,
              _adm_back("adm_rev_goals"), call=call)


# ─────────────────────────────────────────────────────────────────────────────
# TASK SCHEDULER
# ─────────────────────────────────────────────────────────────────────────────

def render_adm_scheduler(call: types.CallbackQuery) -> None:
    tasks = get_setting("scheduled_tasks", []) or []
    enabled_n = sum(1 for t in tasks if t.get("enabled", True))
    cap = (
        f"<b>⏰ {sc('Task Scheduler')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Total Tasks',   len(tasks))}\n"
        f"{bullet('Enabled',       enabled_n)}\n"
        f"{bullet('Disabled',      len(tasks) - enabled_n)}\n"
        f"{G['div']}\n"
        + ("\n".join(
            f"{G['bullet']} {'✅' if t.get('enabled',True) else '⏸️'} "
            f"<b>{esc(t.get('type','?'))}</b> {t.get('time','?')} — "
            f"<i>{esc(str(t.get('msg',''))[:30])}</i>"
            for t in tasks[:10]
        ) or f"<i>{sc('No scheduled tasks')}</i>")
        + f"\n{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("➕  Aᴅᴅ Tᴀꜱᴋ",      callback_data="adm_sched_add",  style="success"),
        Btn("📋  Aʟʟ Tᴀꜱᴋꜱ",     callback_data="adm_sched_list", style="primary"),
    )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("scheduler", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_sched_list(call: types.CallbackQuery) -> None:
    tasks = get_setting("scheduled_tasks", []) or []
    cap = (
        f"<b>📋 {sc('Scheduled Tasks')}</b>\n"
        f"{G['div_eq']}\n"
        + ("\n".join(
            f"{G['bullet']} <code>{t.get('id','?')[:8]}</code> "
            f"{'✅' if t.get('enabled',True) else '⏸️'} "
            f"<b>{t.get('type','?')}</b> {t.get('time','?')}\n"
            f"   <i>{esc(str(t.get('msg',''))[:50])}</i>"
            for t in tasks
        ) or f"<i>{sc('No tasks')}</i>")
        + f"\n{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    for t in tasks[:8]:
        tid = t.get("id","")
        en  = t.get("enabled", True)
        kb.add(
            Btn(f"{'⏸️' if en else '▶️'} {tid[:8]}",
                callback_data=f"adm_sched_toggle_{tid}", style="primary"),
            Btn(f"🗑️ {tid[:8]}",
                callback_data=f"adm_sched_del_{tid}",    style="danger"),
        )
    kb.add(Btn("➕  Aᴅᴅ Tᴀꜱᴋ",     callback_data="adm_sched_add",   style="success"))
    kb.add(Btn(f"{G['back']}  Sᴄʜᴇᴅᴜʟᴇʀ", callback_data="adm_scheduler", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("scheduler", PHOTOS["admin"]), cap, kb, call=call)


def _sched_check_and_run() -> None:
    """Background thread — runs every 60s, fires scheduled tasks."""
    while True:
        try:
            time.sleep(60)
            tasks = get_setting("scheduled_tasks", []) or []
            now_hm = now_utc().strftime("%H:%M")
            now_dt = now_utc().strftime("%Y-%m-%d %H:%M")
            changed = False
            for t in tasks:
                if not t.get("enabled", True):
                    continue
                ttype = t.get("type", "daily")
                ttime = t.get("time", "")
                msg   = t.get("msg", "")
                if not msg:
                    continue
                fire = False
                if ttype == "daily" and ttime == now_hm:
                    fire = True
                elif ttype == "once" and ttime == now_dt:
                    fire = True
                    t["enabled"] = False
                    changed = True
                if fire:
                    _sched_broadcast(msg)
        except Exception:
            pass
        if True:  # always loop
            pass


def _sched_broadcast(msg: str) -> None:
    """Send a scheduled broadcast to all users."""
    users = db_load()["users"]
    for uid in users:
        try:
            bot.send_message(int(uid),
                             f"📣 <b>{sc('Scheduled Message')}</b>\n{G['div']}\n{esc(msg)}",
                             parse_mode="HTML")
            time.sleep(0.05)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# IMPORT / EXPORT
# ─────────────────────────────────────────────────────────────────────────────

def render_adm_import_export(call: types.CallbackQuery) -> None:
    settings_size = SETTINGS_FILE.stat().st_size if SETTINGS_FILE.exists() else 0
    db_size       = DB_FILE.stat().st_size if DB_FILE.exists() else 0
    cap = (
        f"<b>📥 {sc('Import / Export')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Settings File',  fmt_bytes(settings_size))}\n"
        f"{bullet('Database File',  fmt_bytes(db_size))}\n"
        f"{G['div']}\n"
        f"{sc('Export: download a full config backup (settings only, no user data). ')}\n"
        f"{sc('Import: upload a previously exported config to restore settings. ')}\n"
        f"{sc('User Export: CSV of all users.')}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("📤  Exᴘᴏʀᴛ Cᴏɴꜰɪɢ",  callback_data="adm_export_full_cfg", style="success"),
        Btn("📥  Iᴍᴘᴏʀᴛ Cᴏɴꜰɪɢ",  callback_data="adm_import_cfg",      style="primary"),
    )
    kb.add(
        Btn("👥  Exᴘᴏʀᴛ Uꜱᴇʀꜱ CSV",callback_data="adm_user_export_csv", style="primary"),
        Btn("🗄️  Fᴏʀᴄᴇ Bᴀᴄᴋᴜᴘ",   callback_data="adm_force_backup",    style="primary"),
    )
    kb.add(
        Btn("♻️  Fᴀᴄᴛᴏʀʏ Rᴇꜱᴇᴛ",  callback_data="adm_import_reset",    style="danger"),
    )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("import_export", PHOTOS["admin"]), cap, kb, call=call)


def action_adm_export_full_cfg(call: types.CallbackQuery) -> None:
    if not is_owner(call.from_user.id):
        ack(call, "Owner only"); return
    ack(call, "Preparing config export…")
    def _bg() -> None:
        try:
            import json as _j
            settings = {}
            if SETTINGS_FILE.exists():
                with _db_lock:
                    with SETTINGS_FILE.open("r", encoding="utf-8") as f:
                        settings = _j.load(f)
            # Strip sensitive values
            safe_settings = {k: v for k, v in settings.items()
                             if not any(s in k.lower()
                                        for s in ("token","secret","key","password","mongo"))}
            export_data = {
                "export_ts":    ts_iso(),
                "bot_version":  "2.1",
                "brand_tag":    BRAND_TAG,
                "settings":     safe_settings,
                "plan_limits":  {k: {kk: vv for kk, vv in v.items()
                                     if kk not in ("price",)}
                                 for k, v in PLAN_LIMITS.items()},
                "feature_flags":{k: _ff_get(k) for k in _FEATURE_FLAG_DEFAULTS},
            }
            tmp = Path(tempfile.mktemp(suffix="_config_export.json"))
            tmp.write_text(_j.dumps(export_data, indent=2, ensure_ascii=False), encoding="utf-8")
            with tmp.open("rb") as fh:
                bot.send_document(call.from_user.id, fh,
                                  caption=f"📥 {sc('Config Export')} — {ts_iso()[:10]}",
                                  visible_file_name="bot_config_export.json")
            tmp.unlink(missing_ok=True)
            audit(call.from_user.id, "export_config", "")
        except Exception as e:
            try:
                bot.send_message(call.from_user.id,
                                 f"{G['no']} {sc('Export error')}: <code>{esc(e)}</code>",
                                 parse_mode="HTML")
            except Exception:
                pass
    threading.Thread(target=_bg, daemon=True).start()


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN 2FA
# ─────────────────────────────────────────────────────────────────────────────

def render_adm_admin_2fa(call: types.CallbackQuery) -> None:
    enabled = bool(get_setting("admin_2fa_enabled", False))
    secret  = get_setting("admin_2fa_secret", "")
    cap = (
        f"<b>🔐 {sc('Admin 2FA')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Status',  '✅ Enabled' if enabled else '❌ Disabled')}\n"
        f"{bullet('Secret',  '✅ Set' if secret else '❌ Not configured')}\n"
        f"{G['div']}\n"
        f"<i>{sc('2FA adds an extra TOTP code requirement for critical admin actions. ')}"
        f"{sc('Use any authenticator app (Google Authenticator, Authy, etc.).')}</i>{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    if not secret:
        kb.add(Btn("🔑  Sᴇᴛᴜᴘ 2FA", callback_data="adm_2fa_setup", style="success"))
    else:
        kb.add(
            Btn(f"{'✅ ON' if enabled else '❌ OFF'}  Tᴏɢɢʟᴇ",
                callback_data="adm_bc_toggle_admin_2fa_enabled",
                style="success" if enabled else "danger"),
            Btn("🗑️  Dɪꜱᴀʙʟᴇ+Rᴇꜱᴇᴛ", callback_data="adm_2fa_disable", style="danger"),
        )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("admin_2fa", PHOTOS["security"]), cap, kb, call=call)


def action_adm_2fa_setup(call: types.CallbackQuery) -> None:
    if not is_owner(call.from_user.id):
        ack(call, "Owner only"); return
    try:
        secret = base64.b32encode(secrets.token_bytes(20)).decode("utf-8").rstrip("=")
        set_setting("admin_2fa_secret", secret)
        set_setting("admin_2fa_enabled", False)
        audit(call.from_user.id, "2fa_setup", "secret generated")
        user = db_load()["users"].get(str(call.from_user.id), {})
        label = f"{BRAND_TAG}:{user.get('username','admin')}"
        otp_url = f"otpauth://totp/{label}?secret={secret}&issuer={BRAND_TAG}"
        bot.send_message(
            call.from_user.id,
            f"<b>🔐 {sc('2FA Setup')}</b>\n{G['div_eq']}\n"
            f"{sc('Scan this secret in your authenticator app')}:\n\n"
            f"<code>{secret}</code>\n\n"
            f"{sc('OTP URL')}:\n<code>{otp_url}</code>\n\n"
            f"<i>{sc('After adding to authenticator, use the toggle to enable 2FA.')}</i>",
            parse_mode="HTML"
        )
        render_adm_admin_2fa(call)
    except Exception as e:
        ack(call, f"Error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# LEADERBOARD
# ─────────────────────────────────────────────────────────────────────────────

def render_adm_leaderboard(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>🏆 {sc('Leaderboard')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('View top users by different metrics.')}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("💰  Tᴏᴘ Sᴘᴇɴᴅᴇʀꜱ",   callback_data="adm_lb_spenders",  style="success"),
        Btn("🤖  Mᴏꜱᴛ Bᴏᴛꜱ",      callback_data="adm_lb_bots",       style="primary"),
    )
    kb.add(
        Btn("🔗  Tᴏᴘ Rᴇꜰᴇʀʀᴇʀꜱ",  callback_data="adm_lb_referrals",  style="primary"),
        Btn("⚡  Mᴏꜱᴛ Aᴄᴛɪᴠᴇ",    callback_data="adm_lb_active",     style="primary"),
    )
    kb.add(
        Btn("⏱️  Lᴏɴɢᴇꜱᴛ Uᴘᴛɪᴍᴇ", callback_data="adm_lb_uptime",     style="primary"),
        Btn("🏆  Aʟʟ Lʙꜱ",         callback_data="adm_top_users",     style="primary"),
    )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("leaderboard", PHOTOS["stats"]), cap, kb, call=call)


def render_adm_lb_spenders(call: types.CallbackQuery) -> None:
    pays = db_load()["payments"]
    spend: Dict[str, float] = defaultdict(float)
    for p in pays:
        if p.get("status") == "approved":
            spend[str(p.get("uid", ""))] += p.get("amount", 0)
    top = sorted(spend.items(), key=lambda x: x[1], reverse=True)[:15]
    users_db = db_load()["users"]
    rows = "\n".join(
        f"{i}. <b>{esc(users_db.get(uid,{}).get('name','?')[:20])}</b> "
        f"<code>{uid}</code> — <b>{amt:.0f}৳</b>"
        for i, (uid, amt) in enumerate(top, 1)
    ) or f"<i>{sc('No data')}</i>"
    cap = f"<b>💰 {sc('Top Spenders')}</b>\n{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    show_menu(call.message.chat.id, PHOTOS.get("leaderboard", PHOTOS["stats"]), cap,
              _adm_back("adm_leaderboard"), call=call)


def render_adm_lb_bots(call: types.CallbackQuery) -> None:
    bots = db_load()["bots"]
    by_owner: Dict[str, int] = defaultdict(int)
    for b in bots.values():
        by_owner[str(b.get("owner",""))] += 1
    top = sorted(by_owner.items(), key=lambda x: x[1], reverse=True)[:15]
    users_db = db_load()["users"]
    rows = "\n".join(
        f"{i}. <b>{esc(users_db.get(uid,{}).get('name','?')[:20])}</b> — {n} bots"
        for i, (uid, n) in enumerate(top, 1)
    ) or f"<i>{sc('No data')}</i>"
    cap = f"<b>🤖 {sc('Most Bots')}</b>\n{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    show_menu(call.message.chat.id, PHOTOS.get("leaderboard", PHOTOS["stats"]), cap,
              _adm_back("adm_leaderboard"), call=call)


def render_adm_lb_referrals(call: types.CallbackQuery) -> None:
    users = db_load()["users"]
    top = sorted(users.items(),
                 key=lambda x: len(x[1].get("referrals",[])), reverse=True)[:15]
    rows = "\n".join(
        f"{i}. <b>{esc(u.get('name','?')[:20])}</b> — "
        f"{len(u.get('referrals',[]))} refs | {u.get('referral_earnings',0)}৳"
        for i, (uid, u) in enumerate(top, 1) if u.get("referrals")
    ) or f"<i>{sc('No referrals yet')}</i>"
    cap = f"<b>🔗 {sc('Top Referrers')}</b>\n{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    show_menu(call.message.chat.id, PHOTOS.get("leaderboard", PHOTOS["stats"]), cap,
              _adm_back("adm_leaderboard"), call=call)


def render_adm_lb_active(call: types.CallbackQuery) -> None:
    users = db_load()["users"]
    top = sorted(users.items(),
                 key=lambda x: x[1].get("last_seen", ""), reverse=True)[:15]
    rows = "\n".join(
        f"{i}. <b>{esc(u.get('name','?')[:20])}</b> — "
        f"last: <i>{str(u.get('last_seen','?'))[:10]}</i>"
        for i, (uid, u) in enumerate(top, 1)
    ) or f"<i>{sc('No data')}</i>"
    cap = f"<b>⚡ {sc('Most Recently Active')}</b>\n{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    show_menu(call.message.chat.id, PHOTOS.get("leaderboard", PHOTOS["stats"]), cap,
              _adm_back("adm_leaderboard"), call=call)


def render_adm_lb_uptime(call: types.CallbackQuery) -> None:
    running = [(bid, info) for bid, info in RUNNING.items()
               if info["proc"].poll() is None]
    rows: List[str] = []
    for i, (bid, info) in enumerate(running[:15], 1):
        started = info.get("started_at", 0)
        uptime  = int(time.time() - started) if started else 0
        b       = find_bot(bid)
        name    = (b.get("name","?") if b else bid)[:20]
        rows.append(f"{i}. <b>{esc(name)}</b> — {fmt_dur(uptime * 1000)} uptime")
    cap = (
        f"<b>⏱️ {sc('Longest Uptime Bots')}</b>\n"
        f"{G['div_eq']}\n"
        + ("\n".join(rows) or f"<i>{sc('No running bots')}</i>")
        + f"\n{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS.get("leaderboard", PHOTOS["stats"]), cap,
              _adm_back("adm_leaderboard"), call=call)


# ─────────────────────────────────────────────────────────────────────────────
# MULTI-LANGUAGE
# ─────────────────────────────────────────────────────────────────────────────

def render_adm_languages(call: types.CallbackQuery) -> None:
    cur = get_setting("default_language", "en")
    cur_name = _SUPPORTED_LANGUAGES.get(cur, cur)
    cap = (
        f"<b>🌍 {sc('Language Settings')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Default Language', esc(cur_name))}\n"
        f"{bullet('Total Supported',  len(_SUPPORTED_LANGUAGES))}\n"
        f"{G['div']}\n"
        f"<i>{sc('Setting a default language affects message templates and bot UI text for users who have not set a personal language.')}</i>{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    for code, name in _SUPPORTED_LANGUAGES.items():
        kb.add(Btn(f"{'✅' if code == cur else '  '} {name}",
                   callback_data=f"adm_lang_set_{code}", style="primary"))
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("lang_panel", PHOTOS["admin"]), cap, kb, call=call)


# ─────────────────────────────────────────────────────────────────────────────
# PER-BOT CONTROLS
# ─────────────────────────────────────────────────────────────────────────────

def render_adm_bot_controls_panel(call: types.CallbackQuery) -> None:
    d = db_load()
    total   = len(d["bots"])
    running = sum(1 for x in RUNNING.values() if x["proc"].poll() is None)
    cap = (
        f"<b>🤖 {sc('Per-Bot Controls')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Total Bots',  total)}\n"
        f"{bullet('Running',     running)}\n"
        f"{G['div']}\n"
        f"{sc('Search, inspect, or manage individual bots.')}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("📋  Lɪꜱᴛ Aʟʟ Bᴏᴛꜱ",   callback_data="adm_bc_list_all",  style="primary"),
        Btn("🔍  Sᴇᴀʀᴄʜ Bᴏᴛ",       callback_data="adm_bot_search",   style="primary"),
    )
    kb.add(
        Btn("💥  Cʀᴀꜱʜᴇᴅ Bᴏᴛꜱ",    callback_data="adm_crashed_bots", style="danger"),
        Btn("📦  Sɪᴢᴇ Rᴇᴘᴏʀᴛ",      callback_data="adm_bot_size_report", style="primary"),
    )
    kb.add(
        Btn("🔴  Kɪʟʟ Aʟʟ",         callback_data="adm_kill_all_now", style="danger"),
        Btn("🔄  Rᴇꜱᴛᴀʀᴛ Sᴛᴏᴘᴘᴇᴅ",  callback_data="adm_mass_restart_stopped", style="success"),
    )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("bot_controls", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_bc_list_all(call: types.CallbackQuery) -> None:
    bots = db_load()["bots"]
    page = 0  # pagination
    page_size = 8
    bot_items = list(bots.items())
    total_pages = max(1, (len(bot_items) + page_size - 1) // page_size)
    page_bots   = bot_items[page * page_size:(page + 1) * page_size]
    rows = "\n".join(
        f"{G['bullet']} <code>{bid[:8]}</code> <b>{esc(b.get('name','?')[:20])}</b> "
        f"uid={b.get('owner','?')} "
        f"{'▶' if bid in RUNNING and RUNNING[bid]['proc'].poll() is None else '⏹'}"
        for bid, b in page_bots
    ) or f"<i>{sc('No bots')}</i>"
    cap = (
        f"<b>📋 {sc('All Bots')} ({len(bots)} total)</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    for bid, b in page_bots:
        is_running = bid in RUNNING and RUNNING[bid]["proc"].poll() is None
        icon = "▶" if is_running else "⏹"
        kb.add(Btn(f"{icon} {esc(b.get('name','?')[:22])}",
                   callback_data=f"adm_bcbot_{bid[:20]}", style="primary"))
    kb.add(Btn(f"{G['back']}  Bᴏᴛ Cᴏɴᴛʀᴏʟꜱ", callback_data="adm_bot_controls", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("bot_controls", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_bc_single(call: types.CallbackQuery, bid: str) -> None:
    b = find_bot(bid)
    if not b:
        ack(call, "Bot not found"); return
    is_running = bid in RUNNING and RUNNING[bid]["proc"].poll() is None
    pid = RUNNING[bid]["proc"].pid if bid in RUNNING else 0
    rss = 0
    if psutil and is_running and pid:
        try:
            rss = psutil.Process(pid).memory_info().rss
        except Exception:
            pass
    cap = (
        f"<b>🤖 {esc(b.get('name','?'))}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('ID',       f'<code>{bid}</code>')}\n"
        f"{bullet('Owner',    str(b.get('owner','?')))}\n"
        f"{bullet('Plan',     b.get('plan','free'))}\n"
        f"{bullet('Status',   '▶ Running' if is_running else '⏹ Stopped')}\n"
        f"{bullet('PID',      pid or '—')}\n"
        f"{bullet('RAM',      fmt_bytes(rss) if rss else '—')}\n"
        f"{bullet('Approval', b.get('approval_status','?'))}\n"
        f"{bullet('Files',    len(b.get('enc_files',{})))}\n"
        f"{bullet('Source',   esc(b.get('source','local')[:30]))}\n"
        f"{bullet('Created',  str(b.get('created_at','?'))[:10])}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    if is_running:
        kb.add(
            Btn("⏹  Sᴛᴏᴘ",       callback_data=f"adm_bc_stop_{bid[:20]}",    style="danger"),
            Btn("🔄  Rᴇꜱᴛᴀʀᴛ",   callback_data=f"adm_bc_restart_{bid[:20]}", style="success"),
        )
    else:
        kb.add(Btn("▶️  Sᴛᴀʀᴛ",   callback_data=f"adm_bc_restart_{bid[:20]}", style="success"))
    kb.add(
        Btn("📋  Lᴏɢꜱ",           callback_data=f"adm_bc_logs_{bid[:20]}",    style="primary"),
        Btn("🔐  Eɴᴠ Eᴅɪᴛᴏʀ",    callback_data=f"adm_bc_env_{bid[:20]}",     style="primary"),
    )
    kb.add(
        Btn("📊  Rᴇꜱᴏᴜʀᴄᴇꜱ",     callback_data=f"adm_bc_res_{bid[:20]}",     style="primary"),
        Btn("🗑️  Dᴇʟᴇᴛᴇ",        callback_data=f"adm_bc_del_{bid[:20]}",     style="danger"),
    )
    kb.add(Btn(f"{G['back']}  Aʟʟ Bᴏᴛꜱ", callback_data="adm_bc_list_all", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("bot_controls", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_bc_env_editor(call: types.CallbackQuery, bid: str) -> None:
    b = find_bot(bid)
    if not b:
        ack(call, "Bot not found"); return
    env = b.get("env", {})
    safe_env = {k: v for k, v in env.items() if k not in SECRET_ENV_NAMES}
    rows = "\n".join(
        f"{G['bullet']} <code>{esc(k)}</code> = <code>{esc(str(v)[:40])}</code>"
        for k, v in safe_env.items()
    ) or f"<i>{sc('No env vars set')}</i>"
    cap = (
        f"<b>🔐 {sc('Env Editor')}: {esc(b.get('name','?'))}</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}\n"
        f"{sc('To add/change')}: send <code>KEY=value</code>\n"
        f"{sc('To remove')}: send <code>del KEY</code>{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_adm_bot_env_edit", "bot_id": bid}
    show_menu(call.message.chat.id, PHOTOS.get("bot_controls", PHOTOS["admin"]), cap,
              _adm_back(f"adm_bcbot_{bid[:20]}"), call=call)


def render_adm_bc_resources(call: types.CallbackQuery, bid: str) -> None:
    b = find_bot(bid)
    if not b:
        ack(call, "Bot not found"); return
    is_running = bid in RUNNING and RUNNING[bid]["proc"].poll() is None
    rss = vms = cpu = 0
    num_threads = num_fds = 0
    if psutil and is_running:
        try:
            proc = psutil.Process(RUNNING[bid]["proc"].pid)
            mi   = proc.memory_info()
            rss, vms = mi.rss, mi.vms
            cpu  = proc.cpu_percent(interval=0.2)
            num_threads = proc.num_threads()
            try:
                num_fds = proc.num_fds()
            except Exception:
                pass
        except Exception:
            pass
    # Disk usage
    bot_dir = Path(b.get("dir", ""))
    disk = 0
    if bot_dir.exists():
        for root, _, files in os.walk(bot_dir):
            for f in files:
                try:
                    disk += (Path(root) / f).stat().st_size
                except OSError:
                    pass
    cap = (
        f"<b>📊 {sc('Resource Usage')}: {esc(b.get('name','?'))}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Status',   '▶ Running' if is_running else '⏹ Stopped')}\n"
        f"{bullet('RAM RSS',  fmt_bytes(rss))}\n"
        f"{bullet('RAM VMS',  fmt_bytes(vms))}\n"
        f"{bullet('CPU %',    f'{cpu:.1f}%')}\n"
        f"{bullet('Threads',  num_threads)}\n"
        f"{bullet('Open FDs', num_fds)}\n"
        f"{bullet('Disk',     fmt_bytes(disk))}\n"
        f"{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS.get("bot_controls", PHOTOS["admin"]), cap,
              _adm_back(f"adm_bcbot_{bid[:20]}"), call=call)


def render_adm_bc_logs(call: types.CallbackQuery, bid: str) -> None:
    b = find_bot(bid)
    if not b:
        ack(call, "Bot not found"); return
    ring: Deque = RUNNING.get(bid, {}).get("log_ring") or deque(maxlen=200)
    lines = list(ring)[-40:]
    log_text = "\n".join(lines) or f"({sc('No logs available')})"
    cap = (
        f"<b>📋 {sc('Logs')}: {esc(b.get('name','?'))}</b>\n"
        f"{G['div_eq']}\n"
        f"<pre>{esc(log_text[:3000])}</pre>{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS.get("logs", PHOTOS["admin"]), cap,
              _adm_back(f"adm_bcbot_{bid[:20]}"), call=call)


# ─────────────────────────────────────────────────────────────────────────────
# SUBSCRIPTION MANAGER
# ─────────────────────────────────────────────────────────────────────────────

def render_adm_subscriptions(call: types.CallbackQuery) -> None:
    users = db_load()["users"]
    now_s = ts_iso()
    paid_users   = [u for u in users.values() if u.get("plan","free") != "free"]
    expiring_7d  = []
    expired_sub  = []
    for u in paid_users:
        exp = u.get("plan_expiry")
        if not exp:
            continue
        if exp < now_s:
            expired_sub.append(u)
        elif exp < (now_utc() + timedelta(days=7)).isoformat():
            expiring_7d.append(u)
    auto_dg = bool(get_setting("auto_downgrade_expired", True))
    cap = (
        f"<b>👤 {sc('Subscription Manager')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Paid Users',       len(paid_users))}\n"
        f"{bullet('Expiring in 7d',   len(expiring_7d))}\n"
        f"{bullet('Already Expired',  len(expired_sub))}\n"
        f"{bullet('Auto-Downgrade',   '✅ ON' if auto_dg else '❌ OFF')}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("⏰  Exᴘɪʀɪɴɢ Sᴏᴏɴ",    callback_data="adm_sub_expiring",      style="danger"),
        Btn("❌  Exᴘɪʀᴇᴅ",           callback_data="adm_sub_expired",        style="primary"),
    )
    kb.add(
        Btn("📨  Rᴇᴍɪɴᴅ Aʟʟ",       callback_data="adm_sub_remind_all",     style="success"),
        Btn("➕  Exᴛᴇɴᴅ Sᴜʙ",       callback_data="adm_sub_extend_prompt",  style="primary"),
    )
    kb.add(
        Btn(f"{'✅' if auto_dg else '❌'}  Aᴜᴛᴏ-Dɢ",
            callback_data="adm_sub_auto_downgrade",
            style="success" if auto_dg else "danger"),
        Btn("⚡  Rᴜɴ Dᴏᴡɴɢʀᴀᴅᴇ",    callback_data="adm_sub_run_downgrade",  style="danger"),
    )
    kb.add(
        Btn("📋  Sᴜʙ Hɪꜱᴛᴏʀʏ",      callback_data="adm_sub_history",        style="primary"),
        Btn("💰  Pᴀʏᴍᴇɴᴛꜱ",         callback_data="adm_payments",           style="primary"),
    )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("subscriptions", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_sub_expiring(call: types.CallbackQuery) -> None:
    users = db_load()["users"]
    now_s = ts_iso()
    soon_s = (now_utc() + timedelta(days=7)).isoformat()
    expiring = [(uid, u) for uid, u in users.items()
                if u.get("plan_expiry") and now_s < u["plan_expiry"] <= soon_s]
    rows = "\n".join(
        f"{G['bullet']} <code>{uid}</code> <b>{esc(u.get('name','?')[:20])}</b> "
        f"plan={u.get('plan','?')} "
        f"exp={str(u.get('plan_expiry','?'))[:10]}"
        for uid, u in expiring[:20]
    ) or f"<i>{sc('No expiring subscriptions')}</i>"
    cap = (
        f"<b>⏰ {sc('Expiring in 7 Days')} ({len(expiring)})</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS.get("subscriptions", PHOTOS["admin"]), cap,
              _adm_back("adm_subscriptions"), call=call)


def render_adm_sub_expired(call: types.CallbackQuery) -> None:
    users = db_load()["users"]
    now_s = ts_iso()
    expired = [(uid, u) for uid, u in users.items()
               if u.get("plan_expiry") and u["plan_expiry"] < now_s
               and u.get("plan","free") != "free"]
    rows = "\n".join(
        f"{G['bullet']} <code>{uid}</code> <b>{esc(u.get('name','?')[:20])}</b> "
        f"plan={u.get('plan','?')} "
        f"exp={str(u.get('plan_expiry','?'))[:10]}"
        for uid, u in expired[:20]
    ) or f"<i>{sc('No expired subscriptions with active plans')}</i>"
    cap = (
        f"<b>❌ {sc('Expired Subscriptions')} ({len(expired)})</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS.get("subscriptions", PHOTOS["admin"]), cap,
              _adm_back("adm_subscriptions"), call=call)


def action_adm_sub_remind_all(admin_uid: int) -> None:
    """Send renewal reminders to all users with expiring subscriptions."""
    users = db_load()["users"]
    now_s = ts_iso()
    soon_s = (now_utc() + timedelta(days=7)).isoformat()
    sent = fail = 0
    for uid, u in users.items():
        exp = u.get("plan_expiry")
        if not exp or exp < now_s or exp > soon_s:
            continue
        plan_name = PLAN_LIMITS.get(u.get("plan","free"), {}).get("name", u.get("plan","?"))
        days_left = max(0, (datetime.fromisoformat(exp.replace("Z","")) -
                            now_utc().replace(tzinfo=None)).days)
        tmpl = get_setting("tmpl_plan_expired", "") or _MESSAGE_TEMPLATES["plan_expired"]["default"]
        msg = (tmpl.replace("{name}", u.get("name","User"))
                    .replace("{plan}", plan_name)
                    .replace("{days}", str(days_left))
                    .replace("{expiry_date}", str(exp)[:10]))
        try:
            bot.send_message(int(uid), msg)
            sent += 1
        except Exception:
            fail += 1
        time.sleep(0.05)
    audit(admin_uid, "sub_remind_all", f"sent={sent} fail={fail}")
    try:
        bot.send_message(admin_uid,
                         f"{G['ok']} {sc('Renewal reminders sent')}: {sent} ok, {fail} failed.")
    except Exception:
        pass


def action_adm_downgrade_expired(admin_uid: int) -> None:
    """Downgrade all expired paid users to free plan."""
    d = db_load()
    now_s = ts_iso()
    downgraded = 0
    for uid, u in d["users"].items():
        exp = u.get("plan_expiry")
        if exp and exp < now_s and u.get("plan","free") != "free":
            u["plan"] = "free"
            u["plan_expiry"] = None
            downgraded += 1
    db_save(d)
    audit(admin_uid, "downgrade_expired", f"count={downgraded}")
    try:
        bot.send_message(admin_uid,
                         f"{G['ok']} {sc('Downgraded')} {downgraded} {sc('expired subscriptions to free')}.")
    except Exception:
        pass


# ═══════════════════════ END MEGA ADVANCED PANELS ════════════════════════════


def _do_restart_all_bots(admin_uid: int) -> Tuple[int, int]:
    """Restart every bot across ALL PIDs (no local). Returns (ok, fail)."""
    ok = fail = 0
    try:
        bids = list((db_load_ro().get("bots", {}) or {}).keys())
    except Exception:
        bids = []
    for bid in bids:
        try:
            b = find_bot(bid)
        except Exception:
            b = None
        if not b:
            continue
        if (b.get("status") != "running" and not b.get("vm_id")):
            continue
        try:
            r = restart_child(b)
            if r.get("ok"):
                ok += 1
            else:
                fail += 1
        except Exception:
            fail += 1
    # purge any stray local procs (should be none — no local hosting)
    try:
        for bid in list(RUNNING.keys()):
            try:
                _stop_child_local(bid, manual=True)
            except Exception:
                pass
    except Exception:
        pass
    audit(admin_uid, "restart_all_bots", f"ok={ok} fail={fail}")
    return ok, fail


def _do_stop_all_bots(admin_uid: int) -> int:
    """Stop every bot across ALL PIDs (admin stop-all). No local hosting."""
    n = 0
    try:
        bids = list((db_load_ro().get("bots", {}) or {}).keys())
    except Exception:
        bids = []
    for bid in bids:
        try:
            r = stop_child(bid, manual=True)
            if r.get("ok"):
                n += 1
        except Exception:
            pass
    # also purge PIDs directly in case DB is out of sync
    try:
        if _ADDONS_OK and _vmc is not None:
            for vm_id, vm in _vm_nodes().items():
                try:
                    res = _vmc.list_bots(vm["url"], vm.get("secret", ""))
                except Exception:
                    continue
                for rb in (res.get("bots") or [] if isinstance(res, dict) else []):
                    try:
                        bid = rb.get("bot_id")
                        if bid and bid not in bids:
                            _vmc.stop(vm["url"], vm.get("secret", ""), bid)
                            n += 1
                    except Exception:
                        pass
    except Exception:
        pass
    audit(admin_uid, "stop_all_bots", f"stopped={n}")
    return n


def _do_clean_orphans() -> Tuple[int, int]:
    """Delete sandbox dirs and bot_data files with no matching bot
    record. Returns (sandboxes_removed, files_removed)."""
    valid_sandbox_keys: set = set()
    valid_bot_ids: set = set(db_load_ro()["bots"].keys())
    for b in db_load_ro()["bots"].values():
        owner = b.get("owner")
        bid = b.get("_id")
        if owner and bid:
            valid_sandbox_keys.add(f"{owner}_{bid}")
    removed_dirs = 0
    sandbox_root = BASE_DIR / "sandbox"
    if sandbox_root.exists():
        for entry in sandbox_root.iterdir():
            if entry.is_dir() and entry.name not in valid_sandbox_keys:
                try:
                    shutil.rmtree(entry, ignore_errors=True)
                    removed_dirs += 1
                except Exception:
                    pass
    removed_files = 0
    bot_data_dir = BASE_DIR / "storage" / "bot_data"
    if bot_data_dir.exists():
        for f in bot_data_dir.iterdir():
            if f.is_file() and f.suffix == ".json" and f.stem not in valid_bot_ids:
                try:
                    f.unlink()
                    removed_files += 1
                except Exception:
                    pass
    return removed_dirs, removed_files


def _do_export_data(admin_uid: int) -> Path:
    """Bundle DB + settings + audit + bot_data into a single zip and
    return its path."""
    out = BASE_DIR / "exports"
    out.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    target = out / f"simran_export_{stamp}.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in ("user_data.json", "settings.json", "audit.log",
                     "github_config.json"):
            p = BASE_DIR / "storage" / name
            if p.exists():
                zf.write(p, arcname=name)
        bot_data = BASE_DIR / "storage" / "bot_data"
        if bot_data.exists():
            for f in bot_data.iterdir():
                if f.is_file():
                    zf.write(f, arcname=f"bot_data/{f.name}")
    audit(admin_uid, "export_data", f"file={target.name}")
    return target


# ═════════════════════════════════════════════════════════════════
# 21. TICKETS
# ═════════════════════════════════════════════════════════════════

def render_user_tickets(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    d = db_load()["tickets"]
    mine = [t for t in d.values() if t.get("uid") == uid][-10:]
    rows = "\n".join(
        f"{G['bullet']} <code>{t['id']}</code> {G['bullet']} {esc(t.get('status'))} "
        f"{G['bullet']} {esc(t.get('subject'))[:40]}"
        for t in mine
    ) or f"<i>{sc('no tickets yet')}</i>"
    cap = (
        f"<b>{G['ticket']} {sc('Your Tickets')}</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup()
    kb.add(Btn(
        f"{G['plus']}  {sc('Open Ticket')}", callback_data="ticket_open"))
    for t in mine:
        kb.add(Btn(
            f"{G['eye']}  #{t['id']}", callback_data=f"ticket_view_{t['id']}"))
    kb.add(Btn(
        f"{G['back']}  {sc('Main Menu')}", callback_data="menu_main"))
    show_menu(call.message.chat.id, PHOTOS["ticket"], cap, kb, call=call)


def start_ticket_flow(call: types.CallbackQuery) -> None:
    USER_STATES[call.from_user.id] = {"flow": "await_ticket_subject"}
    bot.send_message(call.message.chat.id,
                     f"{G['ticket']} {sc('Send the subject of your ticket (one line)')}.")


def render_ticket_view(call: types.CallbackQuery, tid: str) -> None:
    d = db_load()
    t = d["tickets"].get(tid)
    if not t:
        ack(call, "Not found"); return
    if t["uid"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    msgs = "\n".join(
        f"<b>{esc(m['from'])}</b>: {esc(m['text'])[:200]}"
        for m in t.get("messages", [])
    )
    cap = (
        f"<b>{G['ticket']} #{t['id']}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('From',    t['uid'])}\n"
        f"{bullet('Status',  t['status'])}\n"
        f"{bullet('Subject', t['subject'])}\n"
        f"{G['div']}\n{msgs}\n{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup()
    if t["status"] == "open":
        kb.add(Btn(
            f"{G['plus']}  {sc('Reply')}", callback_data=f"ticket_reply_{tid}"))
        kb.add(Btn(
            f"{G['no']}  {sc('Close')}", callback_data=f"ticket_close_{tid}"))
    kb.add(Btn(
        f"{G['back']}  {sc('Tickets')}",
        callback_data="adm_tickets" if is_admin(call.from_user.id) else "menu_tickets"))
    show_menu(call.message.chat.id, PHOTOS["ticket"], cap, kb, call=call)


def start_ticket_reply(call: types.CallbackQuery, tid: str) -> None:
    USER_STATES[call.from_user.id] = {"flow": "await_ticket_reply", "tid": tid}
    bot.send_message(call.message.chat.id,
                     f"{G['plus']} {sc('Send your reply now')}. /cancel {sc('to abort')}.")


def action_ticket_close(call: types.CallbackQuery, tid: str) -> None:
    d = db_load()
    t = d["tickets"].get(tid)
    if not t:
        ack(call, "Not found"); return
    if t["uid"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    t["status"] = "closed"
    t["closed_at"] = ts_iso()
    db_save(d)
    audit(call.from_user.id, "ticket_close", f"tid={tid}")
    try:
        bot.send_message(t["uid"], f"<b>{G['ok']} {sc('Ticket closed')} #{tid}</b>")
    except Exception:
        pass
    ack(call, "Closed")
    render_ticket_view(call, tid)


# ═════════════════════════════════════════════════════════════════
# 22. MESSAGE/DOC HANDLERS  (state-driven flows)
# ═════════════════════════════════════════════════════════════════

@bot.message_handler(content_types=["document"])
def on_document(m: types.Message) -> None:
    if not _is_private(m):
        return
    if banned_block(m):
        return
    uid = m.from_user.id
    if not RATE.allow(uid):
        maybe_auto_ban(uid, "rate")
        return
    if not UPLOAD_RATE.allow(uid):
        bot.reply_to(m, f"{G['warn']} {sc('Too many uploads, slow down')}.")
        maybe_auto_ban(uid, "upload spam")
        return
    if maintenance_block(uid):
        return
    get_or_create_user(m.from_user)
    if not require_verified(m.chat.id, uid):
        return
    st = USER_STATES.get(uid) or {}
    if st.get("flow") == "await_payment_proof":
        return _handle_payment_proof(m, st)
    if st.get("flow") == "await_topup_proof":
        return _handle_topup_proof(m)
    # default: bot upload
    _handle_bot_upload(m)


@bot.message_handler(content_types=["photo"])
def on_photo(m: types.Message) -> None:
    if not _is_private(m):
        return
    if banned_block(m):
        return
    uid = m.from_user.id
    if not RATE.allow(uid):
        return
    get_or_create_user(m.from_user)
    if not require_verified(m.chat.id, uid):
        return
    st = USER_STATES.get(uid) or {}
    # ── admin sent a banner replacement ──
    if st.get("flow") == "await_admin_photo" and is_admin(uid):
        key = st.get("photo_key") or ""
        if key not in _PHOTO_SPECS:
            bot.reply_to(m, f"{G['no']} {sc('Unknown photo key')}.")
            USER_STATES.pop(uid, None)
            return
        try:
            ph = m.photo[-1]
            f = bot.get_file(ph.file_id)
            raw = bot.download_file(f.file_path)
        except Exception as e:
            bot.reply_to(m, f"{G['no']} {sc('download error')}: <code>{esc(e)}</code>",
                         parse_mode="HTML")
            return
        ok = replace_menu_photo(key, raw)
        USER_STATES.pop(uid, None)
        label = PHOTO_KEYS_FRIENDLY.get(key, key)
        if ok:
            audit(uid, "menu_photo_replace", f"key={key} bytes={len(raw)}")
            bot.reply_to(
                m,
                f"<b>{G['ok']} {sc('Banner updated')}</b>\n"
                f"{bullet('Menu', label)}\n"
                f"{bullet('Size', fmt_bytes(len(raw)))}",
                parse_mode="HTML",
            )
        else:
            bot.reply_to(m, f"{G['no']} {sc('Failed to save photo')}.")
        return
    if st.get("flow") == "await_payment_proof":
        _handle_payment_proof(m, st); return
    if st.get("flow") == "await_topup_proof":
        _handle_topup_proof(m); return


@bot.message_handler(func=lambda m: True, content_types=["text"])
def on_text(m: types.Message) -> None:
    if not _is_private(m):
        return
    if banned_block(m):
        return
    uid = m.from_user.id
    if not RATE.allow(uid):
        maybe_auto_ban(uid, "rate")
        return
    text = (m.text or "").strip()
    if text.startswith("/"):
        return  # handled by command handlers
    get_or_create_user(m.from_user)
    if maintenance_block(uid):
        return
    if not require_verified(m.chat.id, uid):
        return

    st = USER_STATES.get(uid) or {}
    flow = st.get("flow")
    try:
        if flow == "await_env_kv":
            return _handle_env_kv(m, st)
        if flow == "await_pip_install":
            return _handle_pip_install(m, st)
        if flow == "await_tunnel_port":
            return _handle_tunnel_port(m, st)
        if flow == "await_cron":
            return _handle_cron(m, st)
        if flow == "await_admin_finduser":
            return _handle_admin_finduser(m)
        if flow == "await_ban_cmd":
            return _handle_ban_cmd(m)
        if flow == "await_giveplan":
            return _handle_giveplan_cmd(m)
        if flow == "await_broadcast":
            return _handle_broadcast(m)
        if flow == "await_coupon":
            return _handle_coupon_user(m)
        if flow == "await_coupon_admin":
            return _handle_coupon_admin(m)
        if flow == "await_admin_admins":
            return _handle_admin_admins(m)
        if flow == "await_ticket_subject":
            return _handle_ticket_subject(m)
        if flow == "await_ticket_body":
            return _handle_ticket_body(m, st)
        if flow == "await_ticket_reply":
            return _handle_ticket_reply(m, st)
        if flow == "await_payment_proof":
            return _handle_payment_proof_text(m, st)
        if flow == "await_topup_proof":
            return _handle_topup_proof(m)
        if flow == "await_gift_target":
            return _handle_gift_target(m, st)
        if flow == "await_gift_confirm":
            return _handle_gift_confirm(m, st)
        if flow == "await_vm_url":
            url = (text or "").strip().rstrip("/")
            if not url.startswith("http"):
                bot.reply_to(m, f"{G['no']} {sc('Invalid URL — cancelled')}")
                USER_STATES.pop(uid, None); return
            USER_STATES[uid] = {"flow": "await_vm_secret", "vm_url": url}
            bot.reply_to(m, f"{G['ok']} {sc('URL saved')}. {G['key']} {sc('Now send the VM API secret')}.")
            return
        if flow == "await_vm_secret":
            st0 = USER_STATES.get(uid) or {}
            url0 = st0.get("vm_url", "")
            secret0 = (text or "").strip()
            USER_STATES.pop(uid, None)
            if not url0 or not secret0:
                bot.reply_to(m, f"{G['no']} {sc('Session expired — start again')}")
                return
            bot.reply_to(m, f"{G['refresh']} {sc('Testing connection…')}")
            def _bg_addvm(uid_=uid, chat_=m.chat.id, url_=url0, secret_=secret0) -> None:
                try:
                    ok = _vmc.ping(url_) if _vmc else False
                    if not ok:
                        bot.send_message(chat_, f"{G['no']} {sc('Cannot reach VM')}")
                        return
                    status = _vmc.get_status(url_, secret_)
                    if not status:
                        bot.send_message(chat_, f"{G['no']} {sc('Wrong secret or /status failed')}")
                        return
                    vm_id = status.get("vm_id") or url_.split("//", 1)[-1].split(".", 1)[0]
                    nodes = _vm_nodes()
                    nodes[vm_id] = {"vm_id": vm_id, "url": url_, "secret": secret_,
                                    "enabled": True, "added_at": ts_iso()}
                    _vm_save_nodes(nodes)
                    try:
                        if _mdb is not None and _mongo_ready():
                            _mdb.save_vm({"vm_id": vm_id, "url": url_, "secret": secret_, "enabled": True})
                    except Exception:
                        pass
                    audit(uid_, "vm_add", vm_id)
                    bot.send_message(chat_, f"{G['ok']} <b>{sc('VM added')}</b>\n{bullet('ID', vm_id)}\n{bullet('Free', str(status.get('free_ram_mb')) + ' MB')}", parse_mode="HTML")
                except Exception as e:
                    try:
                        bot.send_message(chat_, f"{G['no']} {esc(e)}")
                    except Exception:
                        pass
            threading.Thread(target=_bg_addvm, daemon=True).start()
            return
        if flow == "await_mongo_uri":
            uri0 = (text or "").strip()
            USER_STATES.pop(uid, None)
            if not uri0.startswith("mongodb"):
                bot.reply_to(m, f"{G['no']} {sc('Invalid MongoDB URI')}")
                return
            if not _mongo_ready():
                bot.reply_to(m, f"{G['no']} {sc('Mongo not configured — set MONGO_URI_1 env and redeploy')}")
                return
            bot.reply_to(m, f"{G['refresh']} {sc('Testing connection…')}")
            def _bg_addmongo(uid_=uid, chat_=m.chat.id, uri_=uri0) -> None:
                try:
                    res = _mdb.add_uri(uri_)
                    if res.get("ok"):
                        audit(uid_, "mongo_add", f"total={res.get('total')}")
                        bot.send_message(chat_, f"{G['ok']} <b>{sc('MongoDB URI added')}</b>\n{bullet('Total', res.get('total'))}", parse_mode="HTML")
                    else:
                        bot.send_message(chat_, f"{G['no']} {esc(res.get('error', 'failed'))}")
                except Exception as e:
                    try:
                        bot.send_message(chat_, f"{G['no']} {esc(e)}")
                    except Exception:
                        pass
            threading.Thread(target=_bg_addmongo, daemon=True).start()
            return
        if flow == "await_gh_token":
            gh_set_config({"token": text}); gh_load_config()
            USER_STATES.pop(uid, None); bot.reply_to(m, f"{G['ok']} {sc('token saved')}"); return
        if flow == "await_gh_repo":
            gh_set_config({"repo": text}); gh_load_config()
            USER_STATES.pop(uid, None); bot.reply_to(m, f"{G['ok']} {sc('repo saved')}"); return
        if flow == "await_gh_branch":
            gh_set_config({"branch": text}); gh_load_config()
            USER_STATES.pop(uid, None); bot.reply_to(m, f"{G['ok']} {sc('branch saved')}"); return
        if flow == "await_gh_interval":
            try:
                v = max(15, int(text))
            except Exception:
                v = 360
            gh_set_config({"intervalMin": v}); gh_load_config()
            USER_STATES.pop(uid, None); bot.reply_to(m, f"{G['ok']} {sc('interval saved')}"); return
        if flow == "await_set_brand":
            if not is_owner(uid):
                USER_STATES.pop(uid, None); return
            new = (text or "").strip()[:64]
            if not new:
                bot.reply_to(m, f"{G['no']} {sc('empty — cancelled')}")
                USER_STATES.pop(uid, None); return
            global BRAND_TAG
            BRAND_TAG = new
            set_setting("brand_tag", new)
            audit(uid, "set_brand", new)
            USER_STATES.pop(uid, None)
            bot.reply_to(m, f"{G['ok']} {sc('Brand updated to')}: <b>{esc(new)}</b>",
                         parse_mode="HTML")
            return
        if flow == "await_set_announce":
            if not is_owner(uid):
                USER_STATES.pop(uid, None); return
            v = (text or "").strip()
            if v == "-" or not v:
                v = ""
            elif not v.startswith("@") and not v.lstrip("-").isdigit():
                bot.reply_to(m, f"{G['no']} {sc('use @handle or numeric chat id, or - to clear')}")
                return
            global ANNOUNCE_CHANNEL
            ANNOUNCE_CHANNEL = v
            set_setting("announce_channel", v)
            audit(uid, "set_announce", v or "(cleared)")
            USER_STATES.pop(uid, None)
            bot.reply_to(m, f"{G['ok']} {sc('Announce channel set to')}: "
                            f"<code>{esc(v) if v else '—'}</code>",
                         parse_mode="HTML")
            return
        if flow == "await_set_owner":
            if not is_owner(uid):
                USER_STATES.pop(uid, None); return
            try:
                new_owner = int((text or "").strip())
                if new_owner <= 0:
                    raise ValueError
            except Exception:
                bot.reply_to(m, f"{G['no']} {sc('invalid id — send a positive integer')}")
                return
            global OWNER_ID
            OWNER_ID = new_owner
            set_setting("owner_id", new_owner)
            audit(uid, "transfer_owner", f"new={new_owner}")
            USER_STATES.pop(uid, None)
            bot.reply_to(m,
                f"{G['ok']} {sc('Ownership transferred to')} <code>{new_owner}</code>.\n"
                f"<i>{sc('You are no longer the owner. New owner can use')} /start.</i>",
                parse_mode="HTML")
            return

        # ── New advanced admin flows ──────────────────────────────────
        if flow == "await_set_footer":
            if not is_owner(uid):
                USER_STATES.pop(uid, None); return
            v = (text or "").strip()
            set_setting("custom_footer", "" if v == "-" else v)
            audit(uid, "set_footer", v)
            USER_STATES.pop(uid, None)
            bot.reply_to(m, f"{G['ok']} {sc('Footer updated')}.")
            return

        if flow == "await_set_welcome":
            if not is_owner(uid):
                USER_STATES.pop(uid, None); return
            set_setting("custom_welcome", (text or "").strip())
            audit(uid, "set_welcome", "")
            USER_STATES.pop(uid, None)
            bot.reply_to(m, f"{G['ok']} {sc('Welcome message updated')}.")
            return

        if flow == "await_set_rules":
            if not is_owner(uid):
                USER_STATES.pop(uid, None); return
            set_setting("hosting_rules", (text or "").strip())
            audit(uid, "set_rules", "")
            USER_STATES.pop(uid, None)
            bot.reply_to(m, f"{G['ok']} {sc('Hosting rules updated')}.")
            return

        if flow == "await_adm_user_search":
            if not is_admin(uid):
                USER_STATES.pop(uid, None); return
            q = (text or "").strip().lstrip("@").lower()
            d = db_load()
            results = []
            for _uid, u in d["users"].items():
                if (q.isdigit() and _uid == q) or \
                   q in str(u.get("username", "")).lower() or \
                   q in str(u.get("name", "")).lower():
                    bot_count = sum(1 for b in d["bots"].values() if str(b.get("owner")) == _uid)
                    results.append(
                        f"{G['bullet']} <code>{_uid}</code> "
                        f"<b>{esc(u.get('name','?'))}</b> "
                        f"@{esc(u.get('username','—'))} "
                        f"plan={u.get('plan','free')} "
                        f"bots={bot_count} "
                        f"wallet={u.get('wallet',0)}৳ "
                        f"{'🚫banned' if u.get('banned') else ''}"
                    )
            USER_STATES.pop(uid, None)
            reply = ("\n".join(results[:10]) or f"<i>{sc('No users found for')}: {esc(q)}</i>")
            bot.reply_to(m, f"<b>🔍 {sc('Search Results')}</b>\n{G['div_eq']}\n{reply}",
                         parse_mode="HTML")
            return

        if flow == "await_adm_wallet_adjust":
            if not is_admin(uid):
                USER_STATES.pop(uid, None); return
            parts = (text or "").strip().split(None, 1)
            if len(parts) < 2:
                bot.reply_to(m, f"{G['no']} {sc('Format')}: <code>uid +/-/=amount</code>",
                             parse_mode="HTML"); return
            target_uid, op_str = parts[0].strip(), parts[1].strip()
            d = db_load()
            if target_uid not in d["users"]:
                bot.reply_to(m, f"{G['no']} {sc('User not found')}."); return
            u = d["users"][target_uid]
            try:
                cur = float(u.get("wallet", 0))
                if op_str.startswith("+"):
                    new_bal = cur + float(op_str[1:])
                elif op_str.startswith("-"):
                    new_bal = max(0, cur - float(op_str[1:]))
                elif op_str.startswith("="):
                    new_bal = float(op_str[1:])
                else:
                    new_bal = float(op_str)
                u["wallet"] = round(new_bal, 2)
                db_save(d)
                audit(uid, "wallet_adjust", f"uid={target_uid} old={cur} new={new_bal}")
                USER_STATES.pop(uid, None)
                bot.reply_to(m, f"{G['ok']} uid <code>{target_uid}</code> wallet: "
                                f"<b>{cur}৳</b> → <b>{new_bal}৳</b>",
                             parse_mode="HTML")
            except Exception as _we:
                bot.reply_to(m, f"{G['no']} {sc('Error')}: <code>{esc(_we)}</code>",
                             parse_mode="HTML")
            return

        if flow == "await_adm_notify_user":
            if not is_admin(uid):
                USER_STATES.pop(uid, None); return
            parts = (text or "").split(None, 1)
            if len(parts) < 2:
                bot.reply_to(m, f"{G['no']} {sc('Format')}: <code>user_id message</code>",
                             parse_mode="HTML"); return
            target_uid_str, msg_text = parts[0].strip(), parts[1].strip()
            USER_STATES.pop(uid, None)
            try:
                bot.send_message(int(target_uid_str),
                                 f"<b>📨 {sc('Message from Admin')}</b>\n{G['div']}\n{esc(msg_text)}",
                                 parse_mode="HTML")
                audit(uid, "notify_user", f"to={target_uid_str}")
                bot.reply_to(m, f"{G['ok']} {sc('Message sent')}.")
            except Exception as _ne:
                bot.reply_to(m, f"{G['no']} {sc('Failed')}: <code>{esc(_ne)}</code>",
                             parse_mode="HTML")
            return

        if flow == "await_adm_user_reset":
            if not is_owner(uid):
                USER_STATES.pop(uid, None); return
            target_uid_str = (text or "").strip()
            d = db_load()
            if target_uid_str not in d["users"]:
                bot.reply_to(m, f"{G['no']} {sc('User not found')}."); return
            # Stop all their bots
            for b in list(d["bots"].values()):
                if str(b.get("owner")) == target_uid_str:
                    try:
                        stop_child(b["_id"])
                    except Exception:
                        pass
                    d["bots"].pop(b["_id"], None)
            d["users"][target_uid_str]["plan"] = "free"
            d["users"][target_uid_str]["plan_expiry"] = None
            d["users"][target_uid_str]["wallet"] = 0
            db_save(d)
            audit(uid, "user_reset", f"uid={target_uid_str}")
            USER_STATES.pop(uid, None)
            bot.reply_to(m, f"{G['ok']} uid <code>{target_uid_str}</code> {sc('reset to free plan, all bots removed')}.",
                         parse_mode="HTML")
            return

        if flow == "await_adm_bot_search":
            if not is_admin(uid):
                USER_STATES.pop(uid, None); return
            q = (text or "").strip().lower()
            bots = db_load()["bots"]
            results = []
            for bid, b in bots.items():
                if q in bid.lower() or q in b.get("name", "").lower():
                    running = bid in RUNNING and RUNNING[bid]["proc"].poll() is None
                    results.append(
                        f"{G['bullet']} <code>{bid}</code> <b>{esc(b.get('name','?'))}</b> "
                        f"uid={b.get('owner')} "
                        f"{'▶ running' if running else '⏹ stopped'}"
                    )
            USER_STATES.pop(uid, None)
            reply = "\n".join(results[:10]) or f"<i>{sc('No bots found')}</i>"
            bot.reply_to(m, f"<b>🔍 {sc('Bot Search')}</b>\n{G['div_eq']}\n{reply}",
                         parse_mode="HTML")
            return

        if flow == "await_adm_whitelist":
            if not is_admin(uid):
                USER_STATES.pop(uid, None); return
            parts = (text or "").strip().split(None, 1)
            cmd = parts[0].lower() if parts else ""
            target = parts[1].strip() if len(parts) > 1 else ""
            wl = list(get_setting("scan_whitelist", []) or [])
            if cmd == "add" and target:
                if target not in wl:
                    wl.append(target)
                set_setting("scan_whitelist", wl)
                audit(uid, "whitelist_add", target)
                bot.reply_to(m, f"{G['ok']} <code>{esc(target)}</code> {sc('added to whitelist')}.",
                             parse_mode="HTML")
            elif cmd == "del" and target:
                if target in wl:
                    wl.remove(target)
                set_setting("scan_whitelist", wl)
                audit(uid, "whitelist_del", target)
                bot.reply_to(m, f"{G['ok']} <code>{esc(target)}</code> {sc('removed from whitelist')}.",
                             parse_mode="HTML")
            else:
                bot.reply_to(m, f"{G['no']} {sc('Use')}: <code>add uid</code> {sc('or')} <code>del uid</code>",
                             parse_mode="HTML")
            USER_STATES.pop(uid, None)
            return

        if flow == "await_adm_blacklist":
            if not is_admin(uid):
                USER_STATES.pop(uid, None); return
            parts = (text or "").strip().split(None, 1)
            cmd = parts[0].lower() if parts else ""
            domain = parts[1].strip() if len(parts) > 1 else ""
            bl = list(get_setting("domain_blacklist", []) or [])
            if cmd == "add" and domain:
                if domain not in bl:
                    bl.append(domain)
                set_setting("domain_blacklist", bl)
                audit(uid, "blacklist_add", domain)
                bot.reply_to(m, f"{G['ok']} <code>{esc(domain)}</code> {sc('added to blacklist')}.",
                             parse_mode="HTML")
            elif cmd == "del" and domain:
                if domain in bl:
                    bl.remove(domain)
                set_setting("domain_blacklist", bl)
                audit(uid, "blacklist_del", domain)
                bot.reply_to(m, f"{G['ok']} <code>{esc(domain)}</code> {sc('removed')}.",
                             parse_mode="HTML")
            else:
                bot.reply_to(m, f"{G['no']} {sc('Use')}: <code>add domain.com</code> {sc('or')} <code>del domain.com</code>",
                             parse_mode="HTML")
            USER_STATES.pop(uid, None)
            return

        if flow == "await_adm_notify_running":
            if not is_admin(uid):
                USER_STATES.pop(uid, None); return
            target_uids: List[str] = st.get("target_uids", [])
            msg_text = (text or "").strip()
            USER_STATES.pop(uid, None)
            if not msg_text:
                bot.reply_to(m, f"{G['no']} {sc('Empty message — cancelled')}."); return
            def _bg_nr() -> None:
                sent = fail = 0
                for t_uid in target_uids:
                    try:
                        bot.send_message(int(t_uid),
                                         f"<b>📢 {sc('Admin Message')}</b>\n{G['div']}\n{esc(msg_text)}",
                                         parse_mode="HTML")
                        sent += 1
                    except Exception:
                        fail += 1
                audit(uid, "notify_targeted", f"sent={sent} fail={fail}")
                try:
                    bot.send_message(uid, f"{G['ok']} {sc('Sent to')} {sent} {sc('users')} ({fail} {sc('failed')}).")
                except Exception:
                    pass
            threading.Thread(target=_bg_nr, daemon=True).start()
            bot.reply_to(m, f"{G['ok']} {sc('Sending to')} {len(target_uids)} {sc('users')}…")
            return

        if flow == "await_adm_quick_announce":
            if not is_owner(uid):
                USER_STATES.pop(uid, None); return
            msg_text = (text or "").strip()
            USER_STATES.pop(uid, None)
            if not msg_text or not ANNOUNCE_CHANNEL:
                bot.reply_to(m, f"{G['no']} {sc('No message or channel not configured')}."); return
            try:
                sent = bot.send_message(ANNOUNCE_CHANNEL,
                                        f"📣 <b>{BRAND_TAG}</b>\n{G['div']}\n{esc(msg_text)}",
                                        parse_mode="HTML")
                try:
                    bot.pin_chat_message(ANNOUNCE_CHANNEL, sent.message_id)
                except Exception:
                    pass
                audit(uid, "quick_announce", "")
                bot.reply_to(m, f"{G['ok']} {sc('Announced and pinned')}.")
            except Exception as _qe:
                bot.reply_to(m, f"{G['no']} {sc('Failed')}: <code>{esc(_qe)}</code>",
                             parse_mode="HTML")
            return

        # ─── MEGA ADVANCED PANEL FLOWS ────────────────────────────────────
        if flow == "await_adm_bc_set":
            if not is_admin(uid): USER_STATES.pop(uid, None); return
            key = state.get("bc_key", "")
            val = text.strip()
            # Try int conversion if it looks numeric
            try:
                val_store: Any = int(val)
            except ValueError:
                val_store = val
            set_setting(f"bc_{key}", val_store)
            audit(uid, f"bc_set_{key}", str(val_store)[:40])
            USER_STATES.pop(uid, None)
            bot.reply_to(m, f"{G['ok']} <b><code>{esc(key)}</code></b> = <code>{esc(str(val_store))}</code>",
                         parse_mode="HTML")
            return

        if flow == "await_adm_emoji_set":
            if not is_admin(uid): USER_STATES.pop(uid, None); return
            key = state.get("emoji_key", "")
            emoji_val = text.strip()
            USER_STATES.pop(uid, None)
            if not key:
                bot.reply_to(m, f"{G['no']} Bad state."); return
            if emoji_val == "-":
                custom = get_setting("custom_emojis", {}) or {}
                custom.pop(key, None)
                set_setting("custom_emojis", custom)
                bot.reply_to(m, f"{G['ok']} {sc('Reset')} <code>{esc(key)}</code> to default.", parse_mode="HTML")
            else:
                custom = get_setting("custom_emojis", {}) or {}
                custom[key] = emoji_val
                set_setting("custom_emojis", custom)
                audit(uid, f"emoji_set_{key}", emoji_val)
                bot.reply_to(m, f"{G['ok']} <code>{esc(key)}</code> = {emoji_val}", parse_mode="HTML")
            return

        if flow == "await_adm_tmpl_edit":
            if not is_admin(uid): USER_STATES.pop(uid, None); return
            key = state.get("tmpl_key", "")
            val = text.strip()
            USER_STATES.pop(uid, None)
            if not key:
                bot.reply_to(m, f"{G['no']} Bad state."); return
            set_setting(f"tmpl_{key}", val)
            audit(uid, f"tmpl_set_{key}", val[:40])
            bot.reply_to(m, f"{G['ok']} {sc('Template')} <code>{esc(key)}</code> {sc('updated')}.",
                         parse_mode="HTML")
            return

        if flow == "await_adm_ref_reward":
            if not is_admin(uid): USER_STATES.pop(uid, None); return
            USER_STATES.pop(uid, None)
            try:
                amount = int(text.strip())
                set_setting("referral_reward_amount", amount)
                audit(uid, "ref_reward_set", str(amount))
                bot.reply_to(m, f"{G['ok']} {sc('Referral reward set to')} {amount}৳")
            except ValueError:
                bot.reply_to(m, f"{G['no']} {sc('Please send a valid integer.')}")
            return

        if flow == "await_adm_ref_min_plan":
            if not is_admin(uid): USER_STATES.pop(uid, None); return
            plan = text.strip().lower()
            USER_STATES.pop(uid, None)
            if plan not in PLAN_LIMITS:
                bot.reply_to(m, f"{G['no']} {sc('Invalid plan')}. {sc('Valid')}: {', '.join(PLAN_LIMITS.keys())}"); return
            set_setting("referral_min_plan", plan)
            audit(uid, "ref_min_plan_set", plan)
            bot.reply_to(m, f"{G['ok']} {sc('Min plan for referrals')}: {plan}")
            return

        if flow == "await_adm_wh_set":
            if not is_admin(uid): USER_STATES.pop(uid, None); return
            url = text.strip()
            USER_STATES.pop(uid, None)
            if not url.startswith("https://"):
                bot.reply_to(m, f"{G['no']} {sc('Webhook URL must start with https://')}"); return
            try:
                bot.set_webhook(url)
                set_setting("webhook_url", url)
                audit(uid, "wh_set", url[:80])
                bot.reply_to(m, f"{G['ok']} {sc('Webhook set')}: <code>{esc(url)}</code>", parse_mode="HTML")
            except Exception as _whe:
                bot.reply_to(m, f"{G['no']} {sc('Failed')}: <code>{esc(_whe)}</code>", parse_mode="HTML")
            return

        if flow == "await_adm_rate_set":
            if not is_admin(uid): USER_STATES.pop(uid, None); return
            rate_key = state.get("rate_key", "")
            USER_STATES.pop(uid, None)
            try:
                parts = rate_key.split("_", 1)
                plan_key, metric = parts[0], parts[1] if len(parts) > 1 else ""
                val = int(text.strip())
                set_setting(f"rl_{plan_key}_{metric}", val)
                audit(uid, f"rate_set_{rate_key}", str(val))
                bot.reply_to(m, f"{G['ok']} <code>{esc(rate_key)}</code> = {val}", parse_mode="HTML")
            except Exception as _rse:
                bot.reply_to(m, f"{G['no']} {sc('Error')}: {_rse}")
            return

        if flow == "await_adm_goal_set":
            if not is_admin(uid): USER_STATES.pop(uid, None); return
            goal_type = state.get("goal_type", "monthly")
            USER_STATES.pop(uid, None)
            try:
                amount = int(text.strip())
                key = "rev_goal_monthly" if goal_type == "monthly" else "rev_goal_yearly"
                set_setting(key, amount)
                audit(uid, f"goal_set_{goal_type}", str(amount))
                bot.reply_to(m, f"{G['ok']} {goal_type.title()} {sc('goal set to')} {amount}৳")
            except ValueError:
                bot.reply_to(m, f"{G['no']} {sc('Please send a valid integer.')}")
            return

        if flow == "await_adm_sched_add":
            if not is_admin(uid): USER_STATES.pop(uid, None); return
            raw = text.strip()
            USER_STATES.pop(uid, None)
            # Format: "HH:MM daily Message" or "YYYY-MM-DD HH:MM once Message"
            parts = raw.split(" ", 2)
            try:
                if len(parts) < 3:
                    raise ValueError("Need at least 3 parts")
                if len(parts[0]) == 5 and parts[0].count(":") == 1:  # HH:MM daily ...
                    ttime, ttype, msg = parts[0], parts[1], parts[2]
                    if ttype not in ("daily", "once", "weekly"):
                        ttype = "daily"
                elif len(parts[0]) == 10:  # YYYY-MM-DD HH:MM once ...
                    rest = raw.split(" ", 3)
                    ttime = f"{rest[0]} {rest[1]}"
                    ttype = rest[2] if len(rest) > 2 else "once"
                    msg   = rest[3] if len(rest) > 3 else ""
                else:
                    raise ValueError("Bad format")
                tasks = get_setting("scheduled_tasks", []) or []
                new_task: Dict[str, Any] = {
                    "id":      secrets.token_hex(6),
                    "time":    ttime,
                    "type":    ttype,
                    "msg":     msg,
                    "enabled": True,
                    "created": ts_iso(),
                    "creator": uid,
                }
                tasks.append(new_task)
                set_setting("scheduled_tasks", tasks)
                audit(uid, "sched_add", f"{ttype}@{ttime}")
                bot.reply_to(m, f"{G['ok']} {sc('Scheduled task added')}: "
                                f"<code>{esc(ttype)} {esc(ttime)}: {esc(msg[:50])}</code>",
                             parse_mode="HTML")
            except Exception as _ste:
                bot.reply_to(m, f"{G['no']} {sc('Bad format. Use')}: <code>HH:MM daily Your message</code>",
                             parse_mode="HTML")
            return

        if flow == "await_adm_coupon_bulk":
            if not is_admin(uid): USER_STATES.pop(uid, None); return
            raw = text.strip()
            USER_STATES.pop(uid, None)
            # Format: count plan discount_pct [max_uses] [days_valid]
            parts = raw.split()
            try:
                count    = int(parts[0]) if parts else 1
                plan_key = parts[1] if len(parts) > 1 else "free"
                disc_pct = int(parts[2]) if len(parts) > 2 else 10
                max_uses = int(parts[3]) if len(parts) > 3 else 1
                days_val = int(parts[4]) if len(parts) > 4 else 30
                if plan_key not in PLAN_LIMITS:
                    bot.reply_to(m, f"{G['no']} {sc('Invalid plan')}."); return
                count = min(count, 100)  # cap at 100
                d = db_load()
                created_codes: List[str] = []
                expiry_ts = (now_utc() + timedelta(days=days_val)).isoformat()
                for _ in range(count):
                    code = secrets.token_urlsafe(8).upper()
                    d["coupons"][code] = {
                        "plan":       plan_key,
                        "pct":        disc_pct,
                        "max_uses":   max_uses,
                        "uses_left":  max_uses,
                        "expiry":     expiry_ts,
                        "created_by": uid,
                        "created_at": ts_iso(),
                    }
                    created_codes.append(code)
                db_save(d)
                audit(uid, "coupon_bulk", f"count={count} plan={plan_key} disc={disc_pct}%")
                codes_text = "\n".join(created_codes[:20])
                bot.reply_to(m, f"{G['ok']} <b>{count}</b> {sc('coupons created')}!\n"
                                f"<code>{esc(codes_text)}</code>"
                                + (f"\n<i>...and {count-20} more</i>" if count > 20 else ""),
                             parse_mode="HTML")
            except Exception as _cbe:
                bot.reply_to(m, f"{G['no']} {sc('Error')}: {_cbe}\n"
                                f"{sc('Format')}: <code>count plan discount_pct max_uses days_valid</code>",
                             parse_mode="HTML")
            return

        if flow == "await_adm_factory_reset":
            if not is_owner(uid): USER_STATES.pop(uid, None); return
            USER_STATES.pop(uid, None)
            if text.strip() != "CONFIRM RESET":
                bot.reply_to(m, f"{G['no']} {sc('Cancelled — must send exactly')} "
                                f"<code>CONFIRM RESET</code>.", parse_mode="HTML")
                return
            try:
                if SETTINGS_FILE.exists():
                    SETTINGS_FILE.write_text("{}", encoding="utf-8")
                audit(uid, "factory_reset", "settings wiped")
                bot.reply_to(m, f"♻️ {sc('Factory reset done — all settings wiped. Bot restart recommended.')}")
            except Exception as _fre:
                bot.reply_to(m, f"{G['no']} {sc('Error')}: {_fre}")
            return

        if flow == "await_adm_sub_extend":
            if not is_admin(uid): USER_STATES.pop(uid, None); return
            USER_STATES.pop(uid, None)
            parts = text.strip().split()
            try:
                target_uid = parts[0]
                extra_days = int(parts[1]) if len(parts) > 1 else 30
                d = db_load()
                u = d["users"].get(str(target_uid))
                if not u:
                    bot.reply_to(m, f"{G['no']} {sc('User not found')}: {esc(target_uid)}"); return
                cur_exp = u.get("plan_expiry")
                if cur_exp and cur_exp > ts_iso():
                    base = datetime.fromisoformat(cur_exp.replace("Z",""))
                else:
                    base = now_utc().replace(tzinfo=None)
                new_exp = (base + timedelta(days=extra_days)).isoformat()
                u["plan_expiry"] = new_exp
                db_save(d)
                audit(uid, "sub_extend", f"uid={target_uid} days={extra_days}")
                bot.reply_to(m, f"{G['ok']} {sc('Subscription extended by')} {extra_days} "
                                f"{sc('days. New expiry')}: {new_exp[:10]}")
                try:
                    bot.send_message(int(target_uid),
                                     f"🎁 {sc('Your subscription has been extended by')} "
                                     f"{extra_days} {sc('days by admin!')}")
                except Exception:
                    pass
            except Exception as _see:
                bot.reply_to(m, f"{G['no']} {sc('Error')}: {_see}\n"
                                f"{sc('Format')}: <code>uid days</code>")
            return

        if flow == "await_adm_sub_history":
            if not is_admin(uid): USER_STATES.pop(uid, None); return
            USER_STATES.pop(uid, None)
            target_uid = text.strip()
            d = db_load()
            u = d["users"].get(str(target_uid))
            if not u:
                bot.reply_to(m, f"{G['no']} {sc('User not found')}: {esc(target_uid)}"); return
            pays = [p for p in d["payments"]
                    if str(p.get("uid","")) == str(target_uid)
                    and p.get("status") == "approved"]
            pays.sort(key=lambda x: x.get("ts",""), reverse=True)
            rows = "\n".join(
                f"{G['bullet']} {str(p.get('ts','?'))[:10]} "
                f"<b>{p.get('plan','?')}</b> {p.get('amount','?')}৳"
                for p in pays[:15]
            ) or f"<i>{sc('No payment history')}</i>"
            cap = (
                f"<b>📋 {sc('Sub History')}: {esc(u.get('name','?'))}</b>\n"
                f"{G['div_eq']}\n"
                f"{bullet('Current Plan', u.get('plan','free'))}\n"
                f"{bullet('Expiry',       str(u.get('plan_expiry','—'))[:10])}\n"
                f"{G['div']}\n{rows}"
            )
            bot.reply_to(m, cap, parse_mode="HTML")
            return

        if flow == "await_adm_pay_number":
            if not is_admin(uid): USER_STATES.pop(uid, None); return
            pm_key = state.get("pm_key", "")
            new_num = text.strip()
            USER_STATES.pop(uid, None)
            if not pm_key or not new_num:
                bot.reply_to(m, f"{G['no']} {sc('Bad state.')}"); return
            set_setting(f"pm_number_{pm_key}", new_num)
            PAYMENT_METHODS.get(pm_key, {})["number"] = new_num
            audit(uid, f"pm_number_{pm_key}", new_num[:40])
            bot.reply_to(m, f"{G['ok']} {sc('Number updated for')} "
                            f"<b>{esc(PAYMENT_METHODS.get(pm_key,{}).get('name',pm_key))}</b>",
                         parse_mode="HTML")
            return

        if flow == "await_adm_bot_env_edit":
            if not is_admin(uid): USER_STATES.pop(uid, None); return
            bot_id = state.get("bot_id", "")
            raw    = text.strip()
            USER_STATES.pop(uid, None)
            b = find_bot(bot_id)
            if not b:
                bot.reply_to(m, f"{G['no']} {sc('Bot not found.')}", parse_mode="HTML"); return
            d = db_load()
            env = dict(b.get("env", {}))
            if raw.startswith("del "):
                del_key = raw[4:].strip()
                env.pop(del_key, None)
                action = f"del {del_key}"
            elif "=" in raw:
                k, v = raw.split("=", 1)
                k = k.strip(); v = v.strip()
                if k in SECRET_ENV_NAMES:
                    bot.reply_to(m, f"{G['no']} {sc('Cannot set secret env var via bot.')}"); return
                env[k] = v
                action = f"set {k}"
            else:
                bot.reply_to(m, f"{G['no']} {sc('Format')}: <code>KEY=value</code> {sc('or')} <code>del KEY</code>",
                             parse_mode="HTML"); return
            d["bots"][bot_id]["env"] = env
            db_save(d)
            audit(uid, f"bot_env_edit_{bot_id[:8]}", action)
            bot.reply_to(m, f"{G['ok']} {sc('Env updated')}: <code>{esc(action)}</code>",
                         parse_mode="HTML")
            return

    except Exception as e:
        traceback.print_exc()
        bot.reply_to(m, f"{G['no']} {sc('error')}: <code>{esc(e)}</code>", parse_mode="HTML")


# ═════════════════════════════════════════════════════════════════
# 22.5  APPROVAL SYSTEM (admin-gated bot uploads)
# ═════════════════════════════════════════════════════════════════
#
# When admin toggles "Approval Mode: ON", every uploaded bot is held
# until an admin Approves or Rejects it. While pending, the bot is
# NEVER auto-started, even if its files decrypt cleanly.
#
# storage layout:
#   settings.approval_required          : bool (default True)
#   settings.pending_uploads            : { bot_id -> { file_id, msg_id,
#                                                       chat_id, user_id, name,
#                                                       file_count, size,
#                                                       file_name, ts } }
# bot doc:
#   doc["approval_status"]   : "pending" | "approved" | "rejected" | None
#   doc["approval_reason"]   : str (filled when rejected)
# ═════════════════════════════════════════════════════════════════

def approval_required() -> bool:
    return bool(get_setting("approval_required", True))


def set_approval_required(on: bool) -> None:
    set_setting("approval_required", bool(on))


def _pending_load() -> Dict[str, Any]:
    return dict(get_setting("pending_uploads", {}) or {})


def _pending_save(d: Dict[str, Any]) -> None:
    set_setting("pending_uploads", d)


def pending_add(bot_id: str, info: Dict[str, Any]) -> None:
    p = _pending_load()
    p[bot_id] = info
    _pending_save(p)


def pending_remove(bot_id: str) -> Optional[Dict[str, Any]]:
    p = _pending_load()
    info = p.pop(bot_id, None)
    _pending_save(p)
    return info


def pending_list() -> List[Tuple[str, Dict[str, Any]]]:
    return list(_pending_load().items())


def is_bot_blocked_by_approval(b: Dict[str, Any]) -> bool:
    """Returns True if the bot is held in the approval queue."""
    return (b or {}).get("approval_status") == "pending"


def _send_approval_request_to_admins(b: Dict[str, Any], info: Dict[str, Any],
                                     forwarded_msg: Optional[types.Message]) -> None:
    """Forward actual uploaded document to every admin + summary + Approve/Reject."""
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn(f"{G['ok']}  {sc('Approve')}",
                                   callback_data=f"appr_ok_{b['_id']}"),
        Btn(f"{G['no']}  {sc('Reject')}",
                                   callback_data=f"appr_no_{b['_id']}"),
    )
    txt = (
        f"<b>{G['warn']} {sc('New bot upload — awaiting approval')}</b>\n"
        f"{G['div']}\n"
        f"{bullet('User',     '{} (@{})'.format(info.get('user_name') or '', info.get('user_username') or '-'))}\n"
        f"{bullet('User ID',  info.get('user_id'))}\n"
        f"{bullet('Bot Name', b.get('name'))}\n"
        f"{bullet('Bot ID',   b['_id'])}\n"
        f"{bullet('File',     info.get('file_name'))}\n"
        f"{bullet('Files',    info.get('file_count'))}\n"
        f"{bullet('Size',     fmt_bytes(info.get('size', 0)))}\n"
        f"{G['div']}"
    )
    targets: List[int] = []
    if OWNER_ID:
        targets.append(OWNER_ID)
    for uid_str in (db_load().get("admins") or {}).keys():
        try:
            uid_i = int(uid_str)
            if uid_i not in targets:
                targets.append(uid_i)
        except Exception:
            pass
    fid = None
    try:
        if forwarded_msg and getattr(forwarded_msg, "document", None):
            fid = forwarded_msg.document.file_id
    except Exception:
        fid = None
    for tgt in targets:
        try:
            if fid:
                try:
                    bot.forward_message(tgt, forwarded_msg.chat.id, forwarded_msg.message_id)
                except Exception:
                    pass
                try:
                    bot.send_document(tgt, fid, caption=f"📦 {esc(info.get('file_name') or b.get('name') or '')}"[:200])
                except Exception:
                    pass
        except Exception:
            pass
        try:
            bot.send_message(tgt, txt, parse_mode="HTML", reply_markup=kb)
        except Exception:
            pass



def approve_bot(bot_id: str, admin_uid: int) -> Dict[str, Any]:
    b = find_bot(bot_id)
    if not b:
        return {"ok": False, "error": "Bot not found."}
    pending_remove(bot_id)
    b["approval_status"] = "approved"
    b["approval_reason"] = ""
    b["status"] = "stopped"
    save_bot(b)
    audit(admin_uid, "approve_bot", f"bot={bot_id}")
    # Notify uploader
    try:
        owner = b.get("owner")
        if owner:
            bot.send_message(
                owner,
                f"<b>{G['ok']} {sc('Your bot was approved')}</b>\n"
                f"{bullet('Bot', b.get('name'))}\n"
                f"{sc('Starting it now')}…",
                parse_mode="HTML",
            )
    except Exception:
        pass
    # Auto-start in background
    def _bg() -> None:
        try:
            res = start_child(b)
            if not res.get("ok") and b.get("owner"):
                if _is_full_error(res):
                    _notify_pid_full(b["owner"], b.get("name", "?"),
                                     str(res.get("error", ""))[5:])
                    return
                try:
                    bot.send_message(
                        b["owner"],
                        f"<b>{G['no']} {sc('Auto-start failed after approval')}</b>\n"
                        f"{bullet('Error', esc(res.get('error', '')))}",
                        parse_mode="HTML",
                    )
                except Exception:
                    pass
        except Exception as e:
            print(f"[approve_bot bg] {e}")
    threading.Thread(target=_bg, daemon=True).start()
    return {"ok": True}


def reject_bot(bot_id: str, admin_uid: int, reason: str = "") -> Dict[str, Any]:
    b = find_bot(bot_id)
    if not b:
        return {"ok": False, "error": "Bot not found."}
    pending_remove(bot_id)
    b["approval_status"] = "rejected"
    b["approval_reason"] = reason or "rejected by admin"
    b["status"] = "rejected"
    save_bot(b)
    # Wipe the encrypted blobs + bot dir — rejected uploads should not
    # linger on disk.
    try:
        for f in b.get("enc_files") or []:
            try:
                Path(f.get("enc_path", "")).unlink(missing_ok=True)
            except Exception:
                pass
        rmrf(b.get("dir", ""))
    except Exception:
        pass
    # Remove the bot entry so the user's slot frees up
    try:
        db = db_load()
        db["bots"].pop(bot_id, None)
        db_save(db)
    except Exception:
        pass
    audit(admin_uid, "reject_bot", f"bot={bot_id} reason={reason}")
    try:
        owner = b.get("owner")
        if owner:
            bot.send_message(
                owner,
                f"<b>{G['no']} {sc('Your bot was rejected')}</b>\n"
                f"{bullet('Bot', b.get('name'))}\n"
                f"{bullet('Reason', reason or 'No reason given')}",
                parse_mode="HTML",
            )
    except Exception:
        pass
    return {"ok": True}


# ═════════════════════════════════════════════════════════════════
# 22.6  PHOTO CUSTOMIZATION (admin-uploaded menu banners)
# ═════════════════════════════════════════════════════════════════
#
# Admin clicks "Menu Photos" → picks a key (main / admin / plans / …)
# → next photo they send replaces that menu's banner. The PNG is saved
# to storage/photos/<key>.png (overwriting the auto-generated banner)
# and the cached file_id for that key is invalidated so the new image
# is uploaded on the next show_menu.

PHOTO_KEYS_FRIENDLY: Dict[str, str] = {
    "main":      "Main Menu",
    "admin":     "Admin Panel",
    "plans":     "Plans",
    "buy":       "Buy Plan",
    "wallet":    "Wallet",
    "bots":      "My Bots",
    "bot":       "Bot View",
    "upload":    "Upload Bot",
    "stats":     "Stats",
    "support":   "Support",
    "about":     "About",
    "broadcast": "Broadcast",
    "ticket":    "Tickets",
    "coupon":    "Coupons",
    "security":  "Security",
}


def replace_menu_photo(key: str, file_bytes: bytes) -> bool:
    """Persist an admin-uploaded photo as the banner for `key`.

    Custom photos are saved with a 'custom_' prefix so _build_local_photos()
    always picks them over the auto-generated fallback — even after a restart
    or a GitHub restore that overwrites the plain <key>.png.

    The bytes are ALSO mirrored to GitHub at storage/photos/custom_<key>.png
    immediately, so a fresh deploy or restart that wipes local storage can
    restore the admin-set banner via gh_restore_custom_photos()."""
    if key not in _PHOTO_SPECS:
        return False
    out_dir = DIRS["photos"]
    out_dir.mkdir(parents=True, exist_ok=True)
    # Save with custom_ prefix — this is the persistent marker
    custom_out = out_dir / f"custom_{key}.png"
    # Also overwrite the plain key.png so existing code paths work
    plain_out  = out_dir / f"{key}.png"
    try:
        custom_out.write_bytes(file_bytes)
        plain_out.write_bytes(file_bytes)
        PHOTOS[key] = str(custom_out)
        # Invalidate the cached file_id so the next send re-uploads.
        _PHOTO_FILE_IDS.pop(key, None)
        _PHOTO_FILE_IDS.pop(str(plain_out), None)
        _PHOTO_FILE_IDS.pop(str(custom_out), None)
        # ── Mirror to GitHub right away so it survives restarts ──────
        try:
            if gh_enabled():
                threading.Thread(
                    target=lambda: _gh_put_file(
                        f"storage/photos/custom_{key}.png",
                        file_bytes,
                        f"chore(photos): admin updated banner '{key}'",
                    ),
                    daemon=True,
                ).start()
        except Exception as _e:
            print(f"[replace_menu_photo] gh mirror skipped: {_e}")
        return True
    except Exception as e:
        print(f"[replace_menu_photo] {key}: {e}")
        return False


def gh_restore_custom_photos() -> Dict[str, Any]:
    """Restore admin-uploaded banner photos from GitHub. Runs on every boot
    (even when the local DB is non-empty) so a wiped storage/photos/ folder
    can be repopulated. Existing local custom_<key>.png files are kept;
    only missing or empty ones are pulled. Returns a small summary dict."""
    if not gh_enabled():
        return {"ok": False, "skip": True, "reason": "gh disabled"}
    out_dir = DIRS["photos"]
    out_dir.mkdir(parents=True, exist_ok=True)
    restored = 0
    failed: List[str] = []
    try:
        listing = _gh(
            "GET", _gh_repo_url("contents/storage/photos"),
            params={"ref": GH["branch"]},
        )
        if listing.status_code == 404:
            return {"ok": True, "restored": 0, "note": "no remote photos dir"}
        if listing.status_code != 200:
            return {"ok": False, "error": f"list http {listing.status_code}"}
        items = listing.json() or []
    except Exception as e:
        return {"ok": False, "error": str(e)}
    for it in items:
        try:
            name = (it or {}).get("name") or ""
            if not (name.startswith("custom_") and name.endswith(".png")):
                continue
            local = out_dir / name
            if local.exists() and local.stat().st_size > 1024:
                continue  # local copy already present
            r = _gh(
                "GET", _gh_repo_url(f"contents/storage/photos/{name}"),
                params={"ref": GH["branch"]},
            )
            if r.status_code != 200:
                failed.append(name); continue
            payload = r.json() or {}
            blob = base64.b64decode(payload.get("content") or "")
            if len(blob) < 1024:
                failed.append(name); continue
            local.write_bytes(blob)
            # Mirror onto plain <key>.png so legacy paths also resolve.
            key = name[len("custom_"):-len(".png")]
            plain = out_dir / f"{key}.png"
            try:
                plain.write_bytes(blob)
            except Exception:
                pass
            if key in _PHOTO_SPECS:
                PHOTOS[key] = str(local)
                _PHOTO_FILE_IDS.pop(key, None)
                _PHOTO_FILE_IDS.pop(str(local), None)
                _PHOTO_FILE_IDS.pop(str(plain), None)
            restored += 1
        except Exception as e:
            failed.append(f"{(it or {}).get('name','?')}:{e}")
    return {"ok": True, "restored": restored, "failed": failed}


# ─── security scan helper ─────────────────────────────────────────
def _run_security_scan(files_added: List[Tuple[str, bytes]],
                       uploader_uid: Optional[int] = None) -> Dict[str, Any]:
    """Scan gate neutralized: every upload gets APPROVE, nothing blocked."""
    return {"recommendation": "APPROVE", "verdict": "SAFE",
            "risk_score": 0, "summary": "Scan disabled — auto APPROVE.", "all_threats": [],
            "filename": files_added[0][0] if files_added else "?"}
    """Write uploaded files to a temp dir, run combined AI+pattern scan,
    return the worst-case result dict. Falls back to APPROVE if the
    scanner module is not available. Logs every scan to DB scan_log."""
    if not _SCANNER_OK or _scan_file is None:
        return {"recommendation": "APPROVE", "verdict": "SAFE",
                "risk_score": 0, "summary": "Scanner not available.", "all_threats": []}

    # Honour per-user whitelist — whitelisted users skip scanning
    wl = get_setting("scan_whitelist", []) or []
    if uploader_uid and str(uploader_uid) in wl:
        return {"recommendation": "APPROVE", "verdict": "SAFE",
                "risk_score": 0, "summary": "User is whitelisted — scan skipped.",
                "all_threats": []}

    tmp_dir = Path(tempfile.mkdtemp())
    worst: Optional[Dict[str, Any]] = None
    try:
        for rel, plain in files_added[:10]:  # scan up to 10 files
            safe_rel = Path(rel).name or "upload.bin"
            tmp_file = tmp_dir / safe_rel
            try:
                tmp_file.write_bytes(plain)
                # Use combined AI + pattern scan
                result = _combined_scan(str(tmp_file))
                if worst is None or result.get("risk_score", 0) > worst.get("risk_score", 0):
                    worst = result
            except Exception as e:
                print(f"[security] scan error for {safe_rel}: {e}")
                continue
    finally:
        shutil.rmtree(str(tmp_dir), ignore_errors=True)

    if worst is None:
        return {"recommendation": "APPROVE", "verdict": "SAFE",
                "risk_score": 0, "summary": "No scannable files.", "all_threats": []}

    # ── Log scan result to DB ─────────────────────────────────────
    try:
        log_entry = {
            "ts":         ts_iso(),
            "uid":        str(uploader_uid or "?"),
            "filename":   worst.get("filename", files_added[0][0] if files_added else "?"),
            "verdict":    worst.get("verdict", "UNKNOWN"),
            "risk_score": worst.get("risk_score", 0),
            "summary":    (worst.get("summary", "") or "")[:200],
        }
        d = db_load()
        d["scan_log"].append(log_entry)
        d["scan_log"] = d["scan_log"][-500:]   # keep last 500 entries
        db_save(d)
    except Exception:
        pass

    return worst


# ─── upload handler ───────────────────────────────────────────────
def _handle_bot_upload(m: types.Message) -> None:
    uid = m.from_user.id
    u = db_load()["users"][str(uid)]
    if len(list_user_bots(uid)) >= user_max_bots(u):
        bot.reply_to(m, f"{G['no']} {sc('You hit your bot slot limit')}. {sc('Upgrade or delete one')}.")
        return
    doc = m.document
    if not doc:
        return
    if doc.file_size and doc.file_size > MAX_UPLOAD_BYTES:
        bot.reply_to(m, f"{G['no']} {sc('File too big')} (>{MAX_UPLOAD_BYTES // (1024*1024)} Mʙ).")
        return
    fname = doc.file_name or "upload.bin"
    # Filename verifier removed — all names allowed, no suspicious block.
    try:
        f = bot.get_file(doc.file_id)
        raw = bot.download_file(f.file_path)
    except Exception as e:
        bot.reply_to(m, f"{G['no']} {sc('download error')}: <code>{esc(e)}</code>", parse_mode="HTML")
        return

    bot_id = secrets.token_hex(8)
    bot_dir = DIRS["sandbox"] / f"{uid}_{bot_id}"
    bot_dir.mkdir(parents=True, exist_ok=True)
    name = safe_name(Path(fname).stem)
    doc_db = {
        "_id": bot_id, "owner": uid, "name": name,
        "dir": str(bot_dir), "created": ts_iso(),
        "enc_files": [], "env": {}, "status": "stopped", "cron": {},
    }

    # Determine content: zip vs single file
    files_added: List[Tuple[str, bytes]] = []
    if fname.lower().endswith(".zip"):
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                for member in zf.infolist():
                    if member.is_dir():
                        continue
                    rel = member.filename.replace("\\", "/")
                    if rel.startswith("/") or ".." in rel.split("/"):
                        continue
                    try:
                        # path-traversal check
                        safe_path_join(bot_dir, rel)
                    except ValueError:
                        continue
                    files_added.append((rel, zf.read(member)))
        except zipfile.BadZipFile:
            bot.reply_to(m, f"{G['no']} {sc('not a valid zip')}")
            rmrf(bot_dir); return
    else:
        files_added.append((fname, raw))

    # ══ SECURITY SCAN ════════════════════════════════════════════
    # Runs BEFORE any file is saved, encrypted, or approved.
    _scan_msg = bot.reply_to(
        m,
        f"{G['shield']} {sc('Security scan in progress...')}",
        parse_mode="HTML",
    )
    scan      = _run_security_scan(files_added, uploader_uid=m.from_user.id)
    recommend = scan.get("recommendation", "APPROVE")
    risk      = scan.get("risk_score", 0)
    verdict   = scan.get("verdict", "SAFE")
    summary   = scan.get("summary", "")
    threats   = scan.get("all_threats") or []

    # Delete the "scanning..." notice
    try:
        bot.delete_message(m.chat.id, _scan_msg.message_id)
    except Exception:
        pass

    if recommend == "REJECT":
        # Hard block — wipe everything, alert user + admin
        rmrf(bot_dir)
        threat_lines = "\n".join(f"• {esc(t)}" for t in threats[:5])
        bot.reply_to(
            m,
            f"<b>🚫 {sc('File Blocked — Security Threat Detected')}</b>\n"
            f"{G['div']}\n"
            f"{bullet('File',       fname)}\n"
            f"{bullet('Risk Score', f'{risk}/100')}\n"
            f"{bullet('Verdict',    verdict)}\n"
            f"{G['div']}\n"
            f"<b>{sc('Threats found')}:</b>\n{threat_lines or sc('See admin alert')}",
            parse_mode="HTML",
        )
        notify_owner(
            f"<b>🚨 {sc('DANGEROUS FILE BLOCKED BY SCANNER')}</b>\n"
            f"{G['div']}\n"
            f"{bullet('User',    '{} (@{})'.format(m.from_user.first_name or '', m.from_user.username or '-'))}\n"
            f"{bullet('User ID', uid)}\n"
            f"{bullet('File',    fname)}\n"
            f"{bullet('Risk',    f'{risk}/100')}\n"
            f"{bullet('Verdict', verdict)}\n"
            f"<b>{sc('Top threats')}:</b>\n" +
            "\n".join(f"• {esc(t)}" for t in threats[:3])
        )
        audit(uid, "security_reject", f"file={fname} risk={risk} verdict={verdict}")
        return

    if recommend == "MANUAL_REVIEW":
        # Tag the bot record with scan info so admins see it in the approval panel
        doc_db["security_scan"] = {
            "verdict": verdict, "risk_score": risk, "summary": summary,
        }
    # ══ END SECURITY SCAN ════════════════════════════════════════

    # encrypt and store each
    for rel, plain in files_added:
        meta = store_uploaded_file(m.from_user, rel, plain)
        doc_db["enc_files"].append({
            "key_id": meta["key_id"],
            "enc_path": meta["path"],
            "filename": Path(rel).name,
            "rel_path": rel,
        })

    # NOTE: We deliberately do NOT push to GitHub right after upload.
    # Most upload failures are caught only when the bot starts running,
    # so we wait until the bot has been running for >= 10 minutes
    # (see `gh_uptime_backup_loop`) before backing up. This keeps the
    # backup repo clean of broken/test uploads.
    doc_db["gh_synced_at"] = 0  # reset; loop will re-sync once stable
    total_size = sum(len(p) for _, p in files_added)

    # ── Approval gate ───────────────────────────────────────────
    needs_approval = approval_required() and not is_admin(uid) and OWNER_ID > 0
    if needs_approval:
        doc_db["approval_status"] = "pending"
        doc_db["status"] = "pending_approval"
    save_bot(doc_db)
    db = db_load()
    db["users"][str(uid)]["stats"]["bots_uploaded"] = int(
        db["users"][str(uid)]["stats"].get("bots_uploaded", 0)) + 1
    db_save(db)
    USER_STATES.pop(uid, None)

    if needs_approval:
        info = {
            "user_id":       uid,
            "user_name":     m.from_user.first_name or "",
            "user_username": m.from_user.username or "",
            "chat_id":       m.chat.id,
            "msg_id":        m.message_id,
            "file_name":     fname,
            "file_count":    len(files_added),
            "size":          total_size,
            "ts":            ts_iso(),
        }
        pending_add(bot_id, info)
        try:
            _send_approval_request_to_admins(doc_db, info, m)
        except Exception as e:
            print(f"[approval notify] {e}")
        bot.reply_to(
            m,
            f"<b>{G['warn']} {sc('Pending admin approval')}</b>\n"
            f"{G['div']}\n"
            f"{bullet('Bot Name', name)}\n"
            f"{bullet('Files',    len(files_added))}\n"
            f"{bullet('Size',     fmt_bytes(total_size))}\n"
            f"{G['div']}\n"
            f"{sc('Your bot will start automatically once an admin approves it')}.",
            parse_mode="HTML",
        )
        return

    # File forward disabled — owner sees only the notification summary below.

    notify_owner(
        f"<b>{G['upload']} ɴᴇᴡ ʙᴏᴛ ᴜᴘʟᴏᴀᴅ</b>\n"
        f"{G['div']}\n"
        f"{bullet('File',     fname)}\n"
        f"{bullet('User',     '{} (@{})'.format(m.from_user.first_name or '', m.from_user.username or '-'))}\n"
        f"{bullet('User ID',  uid)}\n"
        f"{bullet('Bot Name', name)}\n"
        f"{bullet('Files',    len(files_added))}\n"
        f"{bullet('Size',     fmt_bytes(total_size))}\n"
        f"{G['div']}"
    )

    kind, _ = detect_entry(bot_dir)  # speculative — might be encrypted-only

    def _make_bar(pct: int, status: str, kind_str: str = "") -> str:
        filled = int(pct / 5)
        bar    = "▓" * filled + "░" * (20 - filled)
        return (
            f"<b>{G['ok']} {sc('Bot stored encrypted')}</b>\n"
            f"{bullet('Name',  name)}\n"
            f"{bullet('Files', len(files_added))}\n"
            f"{bullet('Kind',  kind_str or kind or 'auto-detect on start')}\n"
            f"<code>{bar} {pct}%</code>\n"
            f"{status}"
        )

    # Ek message bhejo — phir edit karte rahenge (spam nahi hoga)
    sent   = bot.reply_to(m, _make_bar(0, sc("Starting...")), parse_mode="HTML")
    msg_id = sent.message_id
    cid    = m.chat.id

    def _edit(pct: int, status: str, kind_str: str = "") -> None:
        try:
            bot.edit_message_text(
                _make_bar(pct, status, kind_str),
                chat_id=cid, message_id=msg_id,
                parse_mode="HTML",
            )
        except Exception:
            pass

    # ── auto-start the freshly uploaded bot ──────────────────────
    def _bg_start(doc: Dict[str, Any]) -> None:
        try:
            _edit(10, sc("Decrypting files..."))
            time.sleep(0.8)
            _edit(30, sc("Installing dependencies..."))
            time.sleep(0.8)
            _edit(50, sc("Setting up environment..."))
            time.sleep(0.8)
            _edit(70, sc("Launching bot..."))
            res = start_child(doc)
            if res.get("ok"):
                _edit(100,
                      f"<b>{G['play']} {sc('Bot is running!')}</b>",
                      res.get("kind", ""))
                time.sleep(1.5)
                # loading msg delete karo
                try:
                    bot.delete_message(cid, msg_id)
                except Exception:
                    pass
                # My Bots menu bhejo
                bots = list_user_bots(uid)
                u = db_load()["users"][str(uid)]
                cap = (
                    f"<b>{G['diamond']} {sc('Your Bots')}</b>\n"
                    f"{G['div_eq']}\n"
                    f"{bullet('Slots', f'{len(bots)} / {user_max_bots(u)}')}\n"
                )
                kb = types.InlineKeyboardMarkup()
                for b in sorted(bots, key=lambda x: x.get("name", "")):
                    running = b.get("status") == "running"
                    mark = G["play"] if running else G["stop"]
                    kb.add(Btn(
                        f"{mark}  {sc(b['name'])[:30]}",
                        callback_data=f"bot_view_{b['_id']}"))
                kb.add(
                    Btn(f"{G['plus']}  {sc('Upload')}",   callback_data="menu_upload", style="success"),
                    Btn(f"{G['back']}  {sc('Main Menu')}", callback_data="menu_main", style="primary"),
                )
                bot.send_message(cid, cap + FOOTER, parse_mode="HTML", reply_markup=kb)
            else:
                if _is_full_error(res):
                    _edit(0, f"<b>⏳ {sc('Current all VMs are full')}</b>\n{sc('Check back later, we will add new VMs within 24 hours')}.")
                    _notify_pid_full(uid, name, str(res.get("error", ""))[5:])
                else:
                    _edit(0,
                          f"<b>{G['no']} {sc('Auto-start failed')}</b>\n"
                          f"{bullet('Error', esc(res.get('error', '')))}\n"
                          f"{sc('Open My Bots → Live Logs to see why')}.")
        except Exception as e:
            try:
                _edit(0, f"{G['no']} {sc('Auto-start error')}: <code>{esc(str(e))}</code>")
            except Exception:
                pass

    threading.Thread(target=_bg_start, args=(doc_db,), daemon=True).start()


# ─── env vars flow ────────────────────────────────────────────────
def _handle_env_kv(m: types.Message, st: Dict[str, Any]) -> None:
    text = m.text.strip()
    if "=" not in text:
        bot.reply_to(m, f"{G['no']} {sc('Use')} <code>Kᴇʏ=Vᴀʟᴜᴇ</code>.", parse_mode="HTML"); return
    key, _, value = text.partition("=")
    key = key.strip(); value = value.strip()
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
        bot.reply_to(m, f"{G['no']} {sc('Invalid key')}."); return
    if key in SECRET_ENV_NAMES:
        bot.reply_to(m, f"{G['no']} {sc('That env name is protected')}."); return
    b = find_bot(st["bot_id"])
    if not b:
        bot.reply_to(m, f"{G['no']} {sc('Bot not found')}."); return
    env = b.get("env") or {}
    env[key] = value
    b["env"] = env
    save_bot(b)
    USER_STATES.pop(m.from_user.id, None)
    bot.reply_to(m, f"{G['ok']} {sc('Saved')} <code>{esc(key)}</code>", parse_mode="HTML")


# ─── pip install flow ─────────────────────────────────────────────
def _handle_pip_install(m: types.Message, st: Dict[str, Any]) -> None:
    text = (m.text or "").strip()
    USER_STATES.pop(m.from_user.id, None)
    if not text:
        bot.reply_to(m, f"{G['no']} {sc('Nothing to install')}."); return
    # only allow safe package spec characters; block flags/shell metas
    pkgs = [p for p in text.split() if p]
    bad = [p for p in pkgs if not re.match(r"^[A-Za-z0-9_\-\.\[\]=<>!~,+]+$", p) or p.startswith("-")]
    if bad:
        bot.reply_to(
            m,
            f"{G['no']} {sc('Invalid package spec')}: <code>{esc(' '.join(bad))}</code>",
            parse_mode="HTML",
        ); return
    if len(pkgs) > 15:
        bot.reply_to(m, f"{G['no']} {sc('Too many packages at once (max 15)')}."); return
    b = find_bot(st["bot_id"])
    if not b:
        bot.reply_to(m, f"{G['no']} {sc('Bot not found')}."); return
    if b["owner"] != m.from_user.id and not is_admin(m.from_user.id):
        bot.reply_to(m, f"{G['no']} {sc('Not yours')}."); return
    # Use the bot's own sandbox dir — installing into a fixed `ROOT/bots/...`
    # used to NameError out, then fall back to root site-packages, which on
    # most hosts requires sudo. `--target deps_dir` keeps everything in the
    # bot's own folder so no permissions are ever needed.
    bot_dir = Path(b["dir"])
    deps_dir = bot_dir / ".deps"
    deps_dir.mkdir(parents=True, exist_ok=True)
    status = bot.reply_to(
        m,
        f"{G['refresh']} {sc('Installing')} <code>{esc(' '.join(pkgs))}</code> ...",
        parse_mode="HTML",
    )
    pip_env = _pip_env(deps_dir)
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "install",
             "--target", str(deps_dir), *_PIP_BASE_FLAGS] + pkgs,
            capture_output=True, text=True, timeout=180, env=pip_env,
        )
        ok = (proc.returncode == 0)
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        tail = "\n".join([ln for ln in out.splitlines() if ln.strip()][-10:])[:1500]
        head = f"{G['ok']} {sc('Installed')}" if ok else f"{G['no']} {sc('Install failed')}"
        try:
            bot.edit_message_text(
                f"<b>{head}</b>\n"
                f"{G['div']}\n"
                f"<b>{sc('Packages')}:</b> <code>{esc(' '.join(pkgs))}</code>\n"
                f"<pre>{esc(tail) or '(no output)'}</pre>",
                chat_id=status.chat.id, message_id=status.message_id,
                parse_mode="HTML",
            )
        except Exception:
            bot.send_message(m.chat.id, f"{head}\n<pre>{esc(tail)}</pre>", parse_mode="HTML")
        audit(m.from_user.id, "pip_install",
              f"bot={b['_id']} pkgs={' '.join(pkgs)} rc={proc.returncode}")
    except subprocess.TimeoutExpired:
        bot.send_message(m.chat.id, f"{G['no']} {sc('Install timed out after 180s')}.")
    except Exception as e:
        bot.send_message(m.chat.id, f"{G['no']} {sc('Install error')}: <code>{esc(str(e))}</code>", parse_mode="HTML")


# ─── cron flow ────────────────────────────────────────────────────
def _handle_cron(m: types.Message, st: Dict[str, Any]) -> None:
    text = m.text.strip().lower()
    b = find_bot(st["bot_id"])
    if not b:
        bot.reply_to(m, f"{G['no']} {sc('Bot not found')}."); return
    if text == "off":
        b["cron"] = {}; save_bot(b); USER_STATES.pop(m.from_user.id, None)
        bot.reply_to(m, f"{G['ok']} {sc('Cron disabled')}"); return
    cron = b.get("cron") or {}
    for tok in text.split():
        if "=" not in tok:
            continue
        k, v = tok.split("=", 1)
        if k not in {"restart", "backup"}:
            continue
        try:
            iv = int(v)
        except Exception:
            continue
        if iv <= 0:
            continue
        cron[f"{k}_hours"] = iv
    b["cron"] = cron
    save_bot(b)
    USER_STATES.pop(m.from_user.id, None)
    bot.reply_to(m, f"{G['ok']} {sc('Cron updated')}: <code>{esc(json.dumps(cron))}</code>",
                 parse_mode="HTML")


# ─── admin: find user ─────────────────────────────────────────────
def _handle_admin_finduser(m: types.Message) -> None:
    if not is_admin(m.from_user.id):
        return
    USER_STATES.pop(m.from_user.id, None)
    text = m.text.strip()
    if not text.lstrip("@").lstrip("-").isdigit() and not text.startswith("@"):
        return
    d = db_load()
    target = None
    if text.startswith("@"):
        for u in d["users"].values():
            if (u.get("username") or "").lower() == text[1:].lower():
                target = u; break
    else:
        try:
            target = d["users"].get(str(int(text)))
        except Exception:
            target = None
    if not target:
        bot.reply_to(m, f"{G['no']} {sc('No such user')}."); return
    bots = list_user_bots(target["_id"])
    txt = (
        f"<b>{G['user']} {sc('User')} {target['_id']}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Name',     target.get('name'))}\n"
        f"{bullet('Username', '@' + (target.get('username') or '—'))}\n"
        f"{bullet('Plan',     PLAN_LIMITS.get(target.get('plan'), {}).get('name'))}\n"
        f"{bullet('Until',    fmt_ts(target.get('plan_expires')))}\n"
        f"{bullet('Wallet',   '{}$'.format(target.get('wallet', 0)))}\n"
        f"{bullet('Banned',   target.get('banned'))}\n"
        f"{bullet('KYC',      target.get('kyc'))}\n"
        f"{bullet('Bots',     len(bots))}\n"
        f"{bullet('Joined',   fmt_ts(target.get('joined')))}\n"
        f"{bullet('LastSeen', fmt_ts(target.get('last_seen')))}\n"
        f"{bullet('Note',     d.get('notes', {}).get(str(target['_id']), '—'))}\n"
        f"{G['div']}{FOOTER}"
    )
    bot.reply_to(m, txt, parse_mode="HTML", reply_markup=back_admin_kb())


# ─── admin: ban / unban ──────────────────────────────────────────
def _handle_ban_cmd(m: types.Message) -> None:
    if not is_admin(m.from_user.id):
        return
    if not admin_can(m.from_user.id, "ban_user"):
        bot.reply_to(m, f"{G['no']} {sc('insufficient permission')}"); return
    USER_STATES.pop(m.from_user.id, None)
    parts = m.text.split(maxsplit=2)
    if len(parts) < 2:
        bot.reply_to(m, f"{G['no']} {sc('format')}: <code>Bᴀɴ &lt;Uɪᴅ&gt; &lt;Rᴇᴀꜱᴏɴ&gt;</code>",
                     parse_mode="HTML"); return
    op = parts[0].lower()
    try:
        uid = int(parts[1])
    except Exception:
        bot.reply_to(m, f"{G['no']} {sc('bad uid')}"); return
    reason = parts[2] if len(parts) > 2 else ""
    d = db_load()
    if str(uid) not in d["users"]:
        bot.reply_to(m, f"{G['no']} {sc('no such user')}"); return
    if op == "ban":
        d["users"][str(uid)]["banned"] = True
        d["users"][str(uid)]["ban_reason"] = reason
        db_save(d)
        audit(m.from_user.id, "ban_user", f"uid={uid} reason={reason}")
        try:
            bot.send_message(uid,
                             f"<b>{G['no']} {sc('You have been banned')}</b>\n{bullet('Reason', reason)}",
                             parse_mode="HTML")
        except Exception:
            pass
        bot.reply_to(m, f"{G['ok']} {sc('banned')} {uid}"); return
    if op == "unban":
        d["users"][str(uid)]["banned"] = False
        d["users"][str(uid)]["ban_reason"] = ""
        db_save(d)
        audit(m.from_user.id, "unban_user", f"uid={uid}")
        try:
            bot.send_message(uid,
                             f"<b>{G['ok']} {sc('You have been unbanned')}</b>",
                             parse_mode="HTML")
        except Exception:
            pass
        bot.reply_to(m, f"{G['ok']} {sc('unbanned')} {uid}"); return


# ─── admin: give plan ─────────────────────────────────────────────
def _handle_giveplan_cmd(m: types.Message) -> None:
    if not is_admin(m.from_user.id):
        return
    if not admin_can(m.from_user.id, "give_plan"):
        bot.reply_to(m, f"{G['no']} {sc('insufficient permission')}"); return
    USER_STATES.pop(m.from_user.id, None)
    parts = m.text.split()
    if len(parts) < 2:
        bot.reply_to(m, f"{G['no']} {sc('format')}: <code>Uɪᴅ Pʟᴀɴ [Dᴀʏꜱ]</code>",
                     parse_mode="HTML"); return
    try:
        uid = int(parts[0])
    except Exception:
        bot.reply_to(m, f"{G['no']} {sc('bad uid')}"); return
    plan = parts[1]
    if plan not in PLAN_LIMITS:
        bot.reply_to(m, f"{G['no']} {sc('bad plan')}"); return
    days = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None
    if not grant_plan(uid, plan, days=days):
        bot.reply_to(m, f"{G['no']} {sc('failed')}"); return
    audit(m.from_user.id, "give_plan", f"uid={uid} plan={plan} days={days}")
    bot.reply_to(m, f"{G['ok']} {sc('granted')} {plan} {sc('to')} {uid}")


# ─── admin: broadcast ─────────────────────────────────────────────
def _handle_broadcast(m: types.Message) -> None:
    if not is_admin(m.from_user.id):
        return
    USER_STATES.pop(m.from_user.id, None)
    text = m.text or ""
    target_plan: Optional[str] = None
    schedule_at: Optional[datetime] = None

    # parse first-line directives
    while True:
        head, _, rest = text.partition("\n")
        head = head.strip()
        if head.startswith("plan:"):
            target_plan = head.split(":", 1)[1].strip().lower()
            text = rest
        elif head.startswith("at:"):
            try:
                schedule_at = datetime.strptime(head[3:].strip(),
                                                "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
            except Exception:
                bot.reply_to(m, f"{G['no']} {sc('bad time format, use YYYY-MM-DD HH:MM UTC')}")
                return
            text = rest
        else:
            break

    text = text.strip()
    if not text:
        bot.reply_to(m, f"{G['no']} {sc('empty broadcast')}"); return

    if schedule_at:
        d = db_load()
        d["scheduled_broadcasts"].append({
            "at": schedule_at.isoformat(),
            "text": text,
            "plan": target_plan,
            "by": m.from_user.id,
        })
        db_save(d)
        audit(m.from_user.id, "broadcast_schedule",
              f"at={schedule_at.isoformat()} plan={target_plan}")
        bot.reply_to(m, f"{G['ok']} {sc('scheduled for')} {fmt_ts(schedule_at.isoformat())}")
        return

    sent, skipped = _send_broadcast(text, target_plan)
    audit(m.from_user.id, "broadcast", f"sent={sent} skipped={skipped} plan={target_plan}")
    bot.reply_to(m, f"{G['ok']} {sc('broadcast done')} — Sᴇɴᴛ {sent}, Sᴋɪᴘᴘᴇᴅ {skipped}")


def _send_broadcast(text: str, target_plan: Optional[str]) -> Tuple[int, int]:
    sent = skipped = 0
    d = db_load()
    for u in d["users"].values():
        if u.get("banned"):
            skipped += 1; continue
        if target_plan and u.get("plan") != target_plan:
            skipped += 1; continue
        try:
            bot.send_message(int(u["_id"]), text, parse_mode="HTML",
                             disable_web_page_preview=True)
            sent += 1
            time.sleep(0.04)  # gentle throttle
        except Exception:
            skipped += 1
    return sent, skipped


# ─── coupons ──────────────────────────────────────────────────────
def _handle_coupon_user(m: types.Message) -> None:
    USER_STATES.pop(m.from_user.id, None)
    code = m.text.strip().upper()
    d = db_load()
    c = d["coupons"].get(code)
    if not c or int(c.get("uses_left", 0)) <= 0:
        bot.reply_to(m, f"{G['no']} {sc('invalid or expired code')}"); return
    pct = int(c.get("percent", 0))
    u = d["users"][str(m.from_user.id)]
    u["wallet"] = int(u.get("wallet", 0)) + pct  # treat % as wallet credit (simple)
    c["uses_left"] = int(c["uses_left"]) - 1
    db_save(d)
    bot.reply_to(m, f"{G['ok']} {sc('redeemed')} +{pct}\u09F3 {sc('to wallet')}")


def _handle_coupon_admin(m: types.Message) -> None:
    if not is_admin(m.from_user.id):
        return
    USER_STATES.pop(m.from_user.id, None)
    parts = m.text.split()
    if len(parts) < 2:
        bot.reply_to(m, f"{G['no']} {sc('format')}: <code>Aᴅᴅ Cᴏᴅᴇ Pᴄᴛ Uꜱᴇꜱ</code> | <code>Dᴇʟ Cᴏᴅᴇ</code>",
                     parse_mode="HTML"); return
    op = parts[0].lower()
    d = db_load()
    if op == "add" and len(parts) >= 4:
        code = parts[1].upper()
        try:
            pct = int(parts[2]); uses = int(parts[3])
        except Exception:
            bot.reply_to(m, f"{G['no']} {sc('bad numbers')}"); return
        d["coupons"][code] = {"percent": pct, "uses_left": uses}
        db_save(d)
        audit(m.from_user.id, "coupon_add", f"code={code} pct={pct} uses={uses}")
        bot.reply_to(m, f"{G['ok']} {sc('added')} {code}"); return
    if op == "del" and len(parts) >= 2:
        code = parts[1].upper()
        if d["coupons"].pop(code, None):
            db_save(d)
            audit(m.from_user.id, "coupon_del", f"code={code}")
            bot.reply_to(m, f"{G['ok']} {sc('removed')} {code}"); return
        bot.reply_to(m, f"{G['no']} {sc('no such code')}"); return


# ─── admin: admins ───────────────────────────────────────────────
def _handle_admin_admins(m: types.Message) -> None:
    if not is_owner(m.from_user.id):
        return
    USER_STATES.pop(m.from_user.id, None)
    parts = m.text.split()
    if len(parts) < 2:
        return
    op = parts[0].lower()
    d = db_load()
    if op == "add" and len(parts) >= 3:
        try:
            uid = int(parts[1])
        except Exception:
            bot.reply_to(m, f"{G['no']} {sc('bad uid')}"); return
        role = parts[2]
        if role not in {"view-only", "manage-users", "full-access"}:
            bot.reply_to(m, f"{G['no']} {sc('bad role')}"); return
        d["admins"][str(uid)] = {"role": role, "added": ts_iso(), "by": m.from_user.id}
        db_save(d)
        audit(m.from_user.id, "admin_add", f"uid={uid} role={role}")
        bot.reply_to(m, f"{G['ok']} {sc('added admin')} {uid} ({role})"); return
    if op == "del" and len(parts) >= 2:
        try:
            uid = int(parts[1])
        except Exception:
            bot.reply_to(m, f"{G['no']} {sc('bad uid')}"); return
        if d["admins"].pop(str(uid), None):
            db_save(d)
            audit(m.from_user.id, "admin_del", f"uid={uid}")
            bot.reply_to(m, f"{G['ok']} {sc('removed')} {uid}"); return


# ─── tickets ──────────────────────────────────────────────────────
def _handle_ticket_subject(m: types.Message) -> None:
    USER_STATES[m.from_user.id] = {"flow": "await_ticket_body", "subject": m.text.strip()[:120]}
    bot.reply_to(m, f"{G['ticket']} {sc('Now send the ticket body')}.")


def _handle_ticket_body(m: types.Message, st: Dict[str, Any]) -> None:
    subject = st.get("subject") or "Support"
    d = db_load()
    tid = rand_token(6)
    d["tickets"][tid] = {
        "id": tid, "uid": m.from_user.id, "subject": subject, "status": "open",
        "messages": [{"from": "user", "text": m.text, "ts": ts_iso()}],
        "opened_at": ts_iso(),
    }
    db_save(d)
    USER_STATES.pop(m.from_user.id, None)
    bot.reply_to(m, f"<b>{G['ok']} {sc('Ticket opened')} #{tid}</b>", parse_mode="HTML")
    notify_owner(
        f"<b>{G['ticket']} ɴᴇᴡ ᴛɪᴄᴋᴇᴛ #{tid}</b>\n"
        f"{bullet('From', m.from_user.id)}\n"
        f"{bullet('Subject', subject)}\n"
        f"{bullet('Body', m.text[:400])}"
    )


def _handle_ticket_reply(m: types.Message, st: Dict[str, Any]) -> None:
    tid = st.get("tid")
    d = db_load()
    t = d["tickets"].get(tid)
    if not t:
        USER_STATES.pop(m.from_user.id, None); return
    if t["uid"] != m.from_user.id and not is_admin(m.from_user.id):
        USER_STATES.pop(m.from_user.id, None); return
    who = "admin" if is_admin(m.from_user.id) and t["uid"] != m.from_user.id else "user"
    t.setdefault("messages", []).append({"from": who, "text": m.text, "ts": ts_iso()})
    db_save(d)
    USER_STATES.pop(m.from_user.id, None)
    target = OWNER_ID if who == "user" else t["uid"]
    try:
        bot.send_message(
            target,
            f"<b>{G['ticket']} {sc('Ticket')} #{tid}</b> — {sc(who + ' replied')}\n"
            f"{esc(m.text)[:1000]}",
            parse_mode="HTML",
        )
    except Exception:
        pass
    bot.reply_to(m, f"{G['ok']} {sc('reply sent')}")


# ─── payment proof ───────────────────────────────────────────────
def _handle_payment_proof(m: types.Message, st: Dict[str, Any]) -> None:
    method = st.get("method") or "unknown"
    plan = st.get("plan")
    p = PLAN_LIMITS.get(plan or "")
    pid = rand_token(8)
    d = db_load()
    d["payments"].append({
        "id": pid, "uid": m.from_user.id, "method": method, "plan": plan,
        "amount": (p or {}).get("price", 0),
        "status": "pending", "ts": ts_iso(),
        "telegram_msg_id": m.message_id,
    })
    db_save(d)
    USER_STATES.pop(m.from_user.id, None)
    # forward proof to owner
    try:
        bot.forward_message(OWNER_ID, m.chat.id, m.message_id)
    except Exception:
        pass
    notify_owner(
        f"<b>{G['wallet']} ɴᴇᴡ ᴘᴀʏᴍᴇɴᴛ ᴘʀᴏᴏғ</b>\n"
        f"{bullet('ID',     pid)}\n"
        f"{bullet('From',   m.from_user.id)}\n"
        f"{bullet('Method', method)}\n"
        f"{bullet('Plan',   plan or '—')}\n"
        f"{bullet('Amount', '{}$'.format((p or {}).get('price', 0)))}\n"
        f"{sc('Tap below to approve or reject')}.",
    )
    kb = types.InlineKeyboardMarkup()
    kb.add(
        Btn(f"{G['ok']}  {sc('Approve')}", callback_data=f"payapprove_{pid}"),
        Btn(f"{G['no']}  {sc('Reject')}",  callback_data=f"payreject_{pid}"),
    )
    try:
        bot.send_message(OWNER_ID, f"<b>{sc('Decide')} #{pid}</b>",
                         parse_mode="HTML", reply_markup=kb)
    except Exception:
        pass
    bot.reply_to(m, f"<b>{G['ok']} {sc('proof received')}</b>\n#{pid} — {sc('await admin')}",
                 parse_mode="HTML")


def _handle_payment_proof_text(m: types.Message, st: Dict[str, Any]) -> None:
    # text-only proofs (e.g. tx ids)
    _handle_payment_proof(m, st)


def _handle_topup_proof(m: types.Message) -> None:
    pid = rand_token(8)
    cap = (m.caption or m.text or "").strip()
    amt = 0
    if cap.isdigit():
        amt = int(cap)
    else:
        ms = re.search(r"\d+", cap)
        if ms:
            amt = int(ms.group(0))
    d = db_load()
    d["payments"].append({
        "id": pid, "uid": m.from_user.id, "method": "topup", "plan": None,
        "amount": amt, "status": "pending", "ts": ts_iso(),
        "telegram_msg_id": m.message_id, "kind": "wallet_topup",
    })
    db_save(d)
    USER_STATES.pop(m.from_user.id, None)
    try:
        bot.forward_message(OWNER_ID, m.chat.id, m.message_id)
    except Exception:
        pass
    kb = types.InlineKeyboardMarkup()
    kb.add(
        Btn(f"{G['ok']}  {sc('Approve')}", callback_data=f"payapprove_{pid}"),
        Btn(f"{G['no']}  {sc('Reject')}",  callback_data=f"payreject_{pid}"),
    )
    notify_owner(
        f"<b>{G['wallet']} ᴡᴀʟʟᴇᴛ ᴛᴏᴘᴜᴘ</b>\n"
        f"{bullet('ID',     pid)}\n"
        f"{bullet('From',   m.from_user.id)}\n"
        f"{bullet('Amount', '{}$'.format(amt))}"
    )
    try:
        bot.send_message(OWNER_ID, f"<b>{sc('Decide')} #{pid}</b>",
                         parse_mode="HTML", reply_markup=kb)
    except Exception:
        pass
    bot.reply_to(m, f"<b>{G['ok']} {sc('top-up proof received')}</b>", parse_mode="HTML")


def action_payment_approve(call: types.CallbackQuery, pid: str) -> None:
    if not admin_only_call(call, "approve_payment"):
        return
    d = db_load()
    pay = next((x for x in d["payments"] if x.get("id") == pid), None)
    if not pay:
        ack(call, "Not found"); return
    # Idempotency: rapid double-tap on Approve must not credit twice or
    # grant the plan twice. Refuse if status is already a terminal one.
    if pay.get("status") in ("approved", "rejected"):
        ack(call, f"Already {pay['status']}.")
        return
    loading(call, "Approving payment")
    pay["status"] = "approved"
    pay["approved_by"] = call.from_user.id
    pay["approved_at"] = ts_iso()
    db_save(d)
    if pay.get("kind") == "wallet_topup":
        u = d["users"].get(str(pay["uid"]))
        if u:
            u["wallet"] = int(u.get("wallet", 0)) + int(pay.get("amount", 0))
            db_save(d)
            try:
                bot.send_message(pay["uid"],
                                 f"<b>{G['ok']} {sc('Wallet credited')}</b>\n"
                                 f"{bullet('Amount', '{}$'.format(pay['amount']))}",
                                 parse_mode="HTML")
            except Exception:
                pass
    elif pay.get("plan"):
        grant_plan(pay["uid"], pay["plan"])
        post_announcement(
            f"<b>{G['spark']} ɴᴇᴡ ᴀᴄᴛɪᴠᴀᴛɪᴏɴ</b>\n"
            f"{bullet('Plan', PLAN_LIMITS[pay['plan']]['name'])}\n"
            f"{bullet('User', '@hidden')}"
        )
    audit(call.from_user.id, "pay_approve", f"pid={pid}")
    ack(call, "Approved")
    try:
        bot.edit_message_text(f"<b>{G['ok']} {sc('Approved')} #{pid}</b>",
                              chat_id=call.message.chat.id,
                              message_id=call.message.message_id, parse_mode="HTML")
    except Exception:
        pass


def action_payment_reject(call: types.CallbackQuery, pid: str) -> None:
    if not admin_only_call(call, "approve_payment"):
        return
    d = db_load()
    pay = next((x for x in d["payments"] if x.get("id") == pid), None)
    if not pay:
        ack(call, "Not found"); return
    if pay.get("status") in ("approved", "rejected"):
        ack(call, f"Already {pay['status']}.")
        return
    loading(call, "Rejecting payment")
    pay["status"] = "rejected"
    pay["rejected_by"] = call.from_user.id
    pay["rejected_at"] = ts_iso()
    db_save(d)
    audit(call.from_user.id, "pay_reject", f"pid={pid}")
    try:
        bot.send_message(pay["uid"],
                         f"<b>{G['no']} {sc('Payment rejected')}</b> #{pid}\n"
                         f"{sc('Contact')} {SUPPORT_USR}",
                         parse_mode="HTML")
    except Exception:
        pass
    ack(call, "Rejected")
    try:
        bot.edit_message_text(f"<b>{G['no']} {sc('Rejected')} #{pid}</b>",
                              chat_id=call.message.chat.id,
                              message_id=call.message.message_id, parse_mode="HTML")
    except Exception:
        pass


# ─── gift plan flow ───────────────────────────────────────────────
def _handle_gift_target(m: types.Message, st: Dict[str, Any]) -> None:
    try:
        tgt = int(m.text.strip())
    except Exception:
        bot.reply_to(m, f"{G['no']} {sc('bad uid')}"); return
    d = db_load()
    if str(tgt) not in d["users"]:
        bot.reply_to(m, f"{G['no']} {sc('user not found')}"); return
    USER_STATES[m.from_user.id] = {"flow": "await_gift_confirm", "target": tgt}
    bot.reply_to(
        m,
        f"<b>{G['warn']} {sc('Confirm gift')}</b>\n"
        f"{bullet('To',   tgt)}\n"
        f"{bullet('Plan', d['users'][str(m.from_user.id)].get('plan'))}\n"
        f"{sc('Send')} <code>YES</code> {sc('to confirm or anything else to cancel')}.",
        parse_mode="HTML",
    )


def _handle_gift_confirm(m: types.Message, st: Dict[str, Any]) -> None:
    USER_STATES.pop(m.from_user.id, None)
    if (m.text or "").strip().upper() != "YES":
        bot.reply_to(m, f"{G['no']} {sc('cancelled')}"); return
    tgt = int(st["target"])
    d = db_load()
    me = d["users"][str(m.from_user.id)]
    if me.get("plan") in ("free", None):
        bot.reply_to(m, f"{G['no']} {sc('no active plan to gift')}"); return
    plan = me["plan"]; exp = me.get("plan_expires")
    me["plan"] = "free"; me["plan_expires"] = None
    if str(tgt) in d["users"]:
        d["users"][str(tgt)]["plan"] = plan
        d["users"][str(tgt)]["plan_expires"] = exp
    db_save(d)
    audit(m.from_user.id, "plan_gift", f"to={tgt} plan={plan}")
    bot.reply_to(m, f"{G['ok']} {sc('plan gifted to')} {tgt}")
    try:
        bot.send_message(tgt,
                         f"<b>{G['spark']} {sc('You received a gift plan')}</b>\n"
                         f"{bullet('Plan', PLAN_LIMITS[plan]['name'])}",
                         parse_mode="HTML")
    except Exception:
        pass


# ═════════════════════════════════════════════════════════════════
# 23. SCHEDULER  (background loops)
# ═════════════════════════════════════════════════════════════════

def cron_runner() -> None:
    """Every minute: cron jobs, expiry reminders, scheduled broadcasts, downgrades."""
    last_per_bot: Dict[str, Dict[str, float]] = {}
    while True:
        try:
            now = time.time()
            d = db_load()

            # plan expiry + reminders
            downgrade_expired_users()
            expiry_reminders()

            # scheduled broadcasts
            sb = d.get("scheduled_broadcasts", [])
            kept: List[Dict[str, Any]] = []
            for b in sb:
                try:
                    when = datetime.fromisoformat(str(b["at"]).replace("Z", "+00:00"))
                except Exception:
                    continue
                if when <= now_utc():
                    _send_broadcast(b["text"], b.get("plan"))
                    audit(b.get("by", 0), "broadcast_run", "scheduled")
                else:
                    kept.append(b)
            if len(kept) != len(sb):
                d["scheduled_broadcasts"] = kept
                db_save(d)

            # per-bot cron (restart / backup)
            for bid, bdoc in db_load()["bots"].items():
                cron = bdoc.get("cron") or {}
                last = last_per_bot.setdefault(bid, {})
                if cron.get("restart_hours"):
                    iv = int(cron["restart_hours"]) * 3600
                    if now - last.get("restart", 0) >= iv:
                        try:
                            restart_child(bdoc)
                        except Exception:
                            pass
                        last["restart"] = now
                if cron.get("backup_hours"):
                    iv = int(cron["backup_hours"]) * 3600
                    if now - last.get("backup", 0) >= iv:
                        try:
                            res = gh_backup_now()
                            if not res.get("ok"):
                                print(f"[cron] backup failed: {res.get('error')}",
                                      flush=True)
                        except Exception as e:
                            print(f"[cron] backup error: {e}", flush=True)
                            traceback.print_exc()
                        last["backup"] = now

            # ── auto backup — sirf tab jab koi bot 10+ min se online ho ──
            should_backup = False
            for bid, rinfo in list(RUNNING.items()):
                started_ms = rinfo.get("started", 0)
                online_sec = (time.time() * 1000 - started_ms) / 1000
                if online_sec >= 600:  # 10 min = 600 sec
                    should_backup = True
                    break
            if should_backup:
                try:
                    res = gh_backup_now()
                    if res.get("ok"):
                        print("[cron] auto backup ok", flush=True)
                    else:
                        print(f"[cron] auto backup failed: {res.get('error')}", flush=True)
                except Exception as e:
                    print(f"[cron] auto backup error: {e}", flush=True)

        except Exception:
            traceback.print_exc()
        time.sleep(60)


# ═════════════════════════════════════════════════════════════════
# 24. BOOTSTRAP / MAIN
# ═════════════════════════════════════════════════════════════════

def banner() -> None:
    line = "=" * 64
    print(line)
    print(f"   {BRAND_TAG}")
    print(f"   uptime port : {KEEPALIVE_PORT}")
    print(f"   owner id    : {OWNER_ID}")
    print(f"   github keys : {'GitHub' if KEYRING.gh_enabled() else 'local cache'}")
    print(f"   github bkp  : {'on' if gh_enabled() else 'off'}")
    print(f"   announcements: {ANNOUNCE_CHANNEL or '—'}")
    print(line)


def _acquire_singleton_lock() -> Optional[Any]:
    """Best-effort single-instance guard. Prevents two local copies of the
    panel from running on the same machine (which would otherwise both poll
    the same token and deliver every callback twice). Returns the file
    handle to keep alive for the lifetime of the process, or None on
    platforms where fcntl isn't available (e.g. Windows)."""
    try:
        import fcntl
    except ImportError:
        return None
    lock_path = DIRS["data"] / "panel.lock"
    try:
        fh = open(lock_path, "w")
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        fh.write(str(os.getpid()))
        fh.flush()
        return fh
    except OSError:
        sys.exit(
            "[x] another panel instance is already running on this machine "
            f"(see {lock_path}). Stop it first, otherwise every button press "
            "will be processed twice."
        )


def main() -> int:
    banner()
    global _LOCK_FH_KEEPALIVE
    _LOCK_FH_KEEPALIVE = _acquire_singleton_lock()
    # restore previously auto-claimed owner (when OWNER_ID env is unset)
    global OWNER_ID, BRAND_TAG, ANNOUNCE_CHANNEL
    stored_owner = int(get_setting("owner_id", 0) or 0)
    if stored_owner > 0:
        # An admin transfer takes precedence; otherwise the env-var
        # owner is the source of truth.
        OWNER_ID = stored_owner if OWNER_ID <= 0 or stored_owner != OWNER_ID else OWNER_ID
        if OWNER_ID <= 0:
            OWNER_ID = stored_owner
    # restore admin-edited brand & announce channel
    bt = get_setting("brand_tag", None)
    if isinstance(bt, str) and bt:
        BRAND_TAG = bt
    ac = get_setting("announce_channel", None)
    if isinstance(ac, str):
        ANNOUNCE_CHANNEL = ac
    gh_load_config()
    GH["autoEnabled"] = bool(get_setting("github_auto_enabled", True))

    # restore from GitHub if storage is empty
    try:
        res = gh_auto_restore_on_boot()
        if res and res.get("ok"):
            print(f"[boot] restored backup ({fmt_bytes(res.get('sizeBytes', 0))})")
    except Exception:
        pass

    # background services
    threading.Thread(target=gh_auto_loop, daemon=True).start()
    threading.Thread(target=gh_uptime_backup_loop, daemon=True,
                     name="gh-uptime-backup").start()
    threading.Thread(target=cron_runner, daemon=True).start()
    threading.Thread(target=_verify_state_janitor, daemon=True,
                     name="verify-janitor").start()
    threading.Thread(target=_sched_check_and_run, daemon=True,
                     name="scheduler").start()
    _start_keepalive()

    # set bot commands
    try:
        bot.set_my_commands([
            types.BotCommand("start",  "open main menu"),
            types.BotCommand("menu",   "main menu"),
            types.BotCommand("help",   "show help"),
            types.BotCommand("id",     "show your user id"),
            types.BotCommand("cancel", "cancel current action"),
        ])
    except Exception:
        pass

    notify_owner(
        f"<b>{G['ok']} {sc('Panel online')}</b>\n"
        f"{bullet('Brand',  BRAND_TAG)}\n"
        f"{bullet('Started', fmt_ts(ts_iso()))}\n"
        f"{bullet('Users',  len(db_load()['users']))}\n"
        f"{bullet('Bots',   len(db_load()['bots']))}"
    )

    # autostart bots that were marked running
    for b in db_load()["bots"].values():
        if b.get("status") == "running":
            try:
                start_child(b)
            except Exception:
                pass

    # ── clear any leftover webhook so polling is the only delivery path ──
    # If a webhook is still registered for this token (from a previous host
    # or a different deployment), Telegram will keep posting updates to it
    # AND deliver them to our polling loop, causing every callback to fire
    # 2-3 times. drop_pending_updates also clears the backlog so we start
    # fresh.
    try:
        bot.remove_webhook()
        try:
            bot.delete_webhook(drop_pending_updates=False)
        except Exception:
            pass
        print("[bot] webhook cleared")
    except Exception as e:
        print(f"[bot] webhook clear warning: {e}")

    print("[bot] polling...")
    while True:
        try:
            bot.infinity_polling(skip_pending=False, timeout=30, long_polling_timeout=25, allowed_updates=["message", "callback_query"])
        except KeyboardInterrupt:
            print("\n[bot] stopping...")
            for bid in list(RUNNING.keys()):
                stop_child(bid, manual=False)
            return 0
        except Exception as e:
            print(f"[bot] poll error: {e}")
            time.sleep(5)


# NOTE: entrypoint stays at the bottom of this file so runtime hooks
# defined further down get registered BEFORE main() starts polling.

# ═══════════════════════════════════════════════════════════════════════════════
# ██████████████  ULTRA-ADVANCED HELP & ANALYTICS SYSTEM  ██████████████████████
# ═══════════════════════════════════════════════════════════════════════════════

_HELP_PAGES = {
    "main": {
        "title": "📚 Help Centre",
        "text": (
            "Welcome to <b>Simran Hosting Bot</b>\n\n"
            "<b>Quick Start</b>\n"
            "1. Register with /start\n"
            "2. Upload your .py or .zip file\n"
            "3. Set BOT_TOKEN env var\n"
            "4. Press Start\n\n"
            "<b>Commands</b>\n"
            "/start /menu /help /id /cancel /status /profile /plans /pay /refer /coupon"
        ),
        "subs": ["upload", "manage", "plans", "github", "referral"],
    },
    "upload": {
        "title": "📤 Uploading Bots",
        "text": (
            "<b>Method 1:</b> Send .py directly\n"
            "<b>Method 2:</b> Send .zip (main file = main.py or bot.py)\n"
            "<b>Method 3:</b> GitHub File Browser\n\n"
            "<b>Limits:</b> max upload size per plan, .py/.js/.zip allowed"
        ),
    },
    "manage": {
        "title": "🤖 Managing Bots",
        "text": (
            "My Bots → select → Start/Stop/Restart\n"
            "View logs in real time (last 500 lines ring buffer)\n"
            "Download source as ZIP any time\n"
            "Crash auto-restart (configurable max retries)"
        ),
    },
    "plans": {
        "title": "💳 Plans & Billing",
        "text": (
            "Free: 1 bot, 50 MB\n"
            "Basic: 3 bots, 100 MB\n"
            "Pro: 10 bots, 500 MB\n"
            "Ultra: unlimited bots, 2 GB\n\n"
            "Pay via UPI/Crypto/PayPal → send proof → admin approves"
        ),
    },
    "github": {
        "title": "🐙 GitHub Integration",
        "text": (
            "Admin → GitHub → enter PAT + repo\n"
            "Auto-backup on start/stop/every N minutes\n"
            "GitHub Browser: browse any public repo, deploy files as bots"
        ),
    },
    "referral": {
        "title": "👥 Referral System",
        "text": (
            "Share your link, earn credits per sign-up\n"
            "Menu → Refer & Earn → copy link\n"
            "Admin configures reward amount and min plan requirement"
        ),
    },
}


def render_help_page(chat_id, page, call=None):
    data = _HELP_PAGES.get(page, _HELP_PAGES["main"])
    cap  = (
        f"<b>{data['title']}</b>\n"
        f"{G['div_eq']}\n"
        f"{data['text']}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    for sub in data.get("subs", []):
        sd = _HELP_PAGES.get(sub, {})
        if sd:
            kb.add(Btn(sd["title"], callback_data=f"help_{sub}", style="primary"))
    kb.add(Btn(f"{G['back']}  Mᴀɪɴ Hᴇʟᴘ", callback_data="help_main", style="primary"))
    photo = PHOTOS.get("main", PHOTOS.get("admin"))
    if call:
        show_menu(call.message.chat.id, photo, cap, kb, call=call)
    else:
        bot.send_photo(chat_id, photo, caption=cap, reply_markup=kb, parse_mode="HTML")


# ─── Analytics Helpers ──────────────────────────────────────────────────────

def _analytics_daily_signups(days=30):
    d = db_load()
    from datetime import timedelta
    cutoff = (now_utc() - timedelta(days=days))
    counts = {}
    for u in d["users"].values():
        joined = u.get("joined", "")
        if joined:
            try:
                from datetime import datetime, timezone
                dt = datetime.fromisoformat(joined)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if dt >= cutoff:
                    day = dt.strftime("%Y-%m-%d")
                    counts[day] = counts.get(day, 0) + 1
            except Exception:
                pass
    return dict(sorted(counts.items()))


def _analytics_plan_distribution(d=None):
    if d is None:
        d = db_load()
    dist = {}
    for u in d["users"].values():
        plan = u.get("plan", "free") or "free"
        dist[plan] = dist.get(plan, 0) + 1
    return dist


def _analytics_bot_status_dist(d=None):
    if d is None:
        d = db_load()
    dist = {}
    for b in d["bots"].values():
        s = b.get("status", "stopped")
        dist[s] = dist.get(s, 0) + 1
    return dist


def _analytics_top_referrers(n=10):
    d = db_load()
    rows = [(uid, u.get("name", uid), len(u.get("referrals", [])))
            for uid, u in d["users"].items() if u.get("referrals")]
    rows.sort(key=lambda x: x[2], reverse=True)
    return rows[:n]


def _analytics_avg_bots_per_user():
    d = db_load()
    if not d["users"]:
        return 0.0
    counts = {}
    for b in d["bots"].values():
        uid = str(b.get("owner", ""))
        counts[uid] = counts.get(uid, 0) + 1
    return round(sum(counts.values()) / len(d["users"]), 2)


def _rev_total():
    d = db_load()
    return sum(float(tx.get("amount", 0))
               for u in d["users"].values()
               for tx in u.get("transactions", [])
               if tx.get("type") in ("payment", "upgrade", "renewal"))


def _rev_this_month():
    d = db_load()
    month = now_utc().strftime("%Y-%m")
    return sum(float(tx.get("amount", 0))
               for u in d["users"].values()
               for tx in u.get("transactions", [])
               if tx.get("ts", "").startswith(month)
               and tx.get("type") in ("payment", "upgrade", "renewal"))


def _rev_by_plan():
    d = db_load()
    by_plan = {}
    for u in d["users"].values():
        for tx in u.get("transactions", []):
            if tx.get("type") in ("payment", "upgrade", "renewal"):
                pl = tx.get("plan", "unknown")
                by_plan[pl] = by_plan.get(pl, 0.0) + float(tx.get("amount", 0))
    return by_plan


def _rev_goal_progress():
    goal       = float(get_setting("revenue_goal", 0) or 0)
    this_month = _rev_this_month()
    pct        = round(this_month / goal * 100, 1) if goal > 0 else 0
    return {
        "goal":      goal,
        "achieved":  this_month,
        "remaining": max(0.0, goal - this_month),
        "pct":       pct,
    }


def _rev_projected_monthly():
    day = now_utc().day or 1
    return round(_rev_this_month() / day * 30, 2)


# ─── Notification Queue ─────────────────────────────────────────────────────

_NOTIFICATION_QUEUE = []
_NOTIF_LOCK = threading.Lock()


def _notif_enqueue(uid, msg, parse_mode="HTML"):
    with _NOTIF_LOCK:
        _NOTIFICATION_QUEUE.append({"uid": uid, "msg": msg, "pm": parse_mode})


def _notif_flush_queue():
    with _NOTIF_LOCK:
        batch = list(_NOTIFICATION_QUEUE)
        _NOTIFICATION_QUEUE.clear()
    for item in batch:
        try:
            bot.send_message(item["uid"], item["msg"], parse_mode=item["pm"])
        except Exception:
            pass


def _notif_runner():
    while True:
        try:
            _notif_flush_queue()
        except Exception:
            pass
        time.sleep(5)


# ─── Rate Limiter ───────────────────────────────────────────────────────────

_RATE_BUCKETS = {}
_RATE_LOCK    = threading.Lock()


def _rate_check(uid, action="msg"):
    cfg = {
        "msg":       (_rl_get("msg_per_min"),        60),
        "callback":  (_rl_get("cb_per_min"),         60),
        "upload":    (_rl_get("upload_per_hour"),   3600),
        "start_bot": (_rl_get("bot_start_per_hour"),3600),
    }
    limit, window = cfg.get(action, (60, 60))
    key = f"{uid}:{action}"
    now = time.time()
    with _RATE_LOCK:
        bucket = _RATE_BUCKETS.get(key, {"count": 0, "window_start": now})
        if now - bucket["window_start"] > window:
            bucket = {"count": 0, "window_start": now}
        bucket["count"] += 1
        _RATE_BUCKETS[key] = bucket
        return bucket["count"] <= limit


def _rate_cleanup_loop():
    while True:
        time.sleep(300)
        now = time.time()
        with _RATE_LOCK:
            stale = [k for k, v in _RATE_BUCKETS.items() if now - v["window_start"] > 7200]
            for k in stale:
                _RATE_BUCKETS.pop(k, None)


# ─── Plan Enforcement ───────────────────────────────────────────────────────

def _plan_enforce_bot_limit(uid):
    d = db_load()
    u = d["users"].get(str(uid), {})
    plan   = u.get("plan", "free") or "free"
    limits = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])
    max_b  = limits.get("bots", 1)
    if max_b == -1:
        return True, ""
    cur = sum(1 for b in d["bots"].values() if str(b.get("owner")) == str(uid))
    if cur >= max_b:
        return False, f"Plan limit: {max_b} bots. You have {cur}. Upgrade to add more."
    return True, ""


def _plan_enforce_upload_size(uid, size_bytes):
    d = db_load()
    u = d["users"].get(str(uid), {})
    plan   = u.get("plan", "free") or "free"
    limits = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])
    max_mb = limits.get("max_upload_mb", 50)
    if max_mb == -1:
        return True, ""
    if size_bytes > max_mb * 1024 * 1024:
        return False, f"File {fmt_bytes(size_bytes)} > plan limit {max_mb} MB. Upgrade!"
    return True, ""


def _plan_check_expiry(uid):
    d = db_load()
    u = d["users"].get(str(uid), {})
    plan    = u.get("plan", "free") or "free"
    expires = u.get("plan_expires")
    if plan == "free" or not expires:
        return True
    if expires < ts_iso():
        u["plan"]         = "free"
        u["plan_expires"] = None
        u.setdefault("transactions", []).append({
            "type": "downgrade", "ts": ts_iso(), "from_plan": plan, "reason": "expired"
        })
        db_save(d)
        _notif_enqueue(uid,
            f"<b>{G['warn']} Plan expired</b>\n"
            f"Your <b>{plan}</b> plan expired. Downgraded to Free.",
            parse_mode="HTML"
        )
        return False
    return True


# ─── Webhook Delivery ───────────────────────────────────────────────────────

def _wh_deliver(event, payload):
    url    = get_setting("webhook_url", "")
    if not url:
        return
    secret = get_setting("webhook_secret", "") or ""
    import json as _json
    body   = _json.dumps({"event": event, "payload": payload, "ts": ts_iso()})
    headers = {"Content-Type": "application/json"}
    if secret:
        import hmac, hashlib
        headers["X-Webhook-Signature"] = hmac.new(
            secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    try:
        import urllib.request as _ur
        req = _ur.Request(url, data=body.encode(), headers=headers, method="POST")
        with _ur.urlopen(req, timeout=10) as r:
            status = r.status
        _wh_log(event, status)
    except Exception as e:
        _wh_log(event, f"error:{e}")


def _wh_log(event, status):
    log = get_setting("webhook_log", []) or []
    log.append({"event": event, "ts": ts_iso(), "status": str(status)})
    if len(log) > 100:
        log = log[-100:]
    set_setting("webhook_log", log)


def _wh_fire(event, payload):
    if not get_setting("webhook_enabled", False):
        return
    threading.Thread(target=_wh_deliver, args=(event, payload), daemon=True).start()


# ─── Subscription Engine ────────────────────────────────────────────────────

def _sub_check_all_expiries():
    d = db_load()
    downgraded = []
    for uid_s, u in d["users"].items():
        plan    = u.get("plan", "free") or "free"
        expires = u.get("plan_expires")
        if plan != "free" and expires and expires < ts_iso():
            old = plan
            u["plan"] = "free"; u["plan_expires"] = None
            u.setdefault("transactions", []).append({
                "type": "downgrade", "ts": ts_iso(), "from_plan": old, "reason": "expired"})
            downgraded.append((int(uid_s), old))
    if downgraded:
        db_save(d)
        for uid, op in downgraded:
            try:
                bot.send_message(uid,
                    f"<b>{G['warn']} Plan Expired</b>\n{op} → Free. Renew to restore.",
                    parse_mode="HTML")
            except Exception:
                pass
    return downgraded


def _sub_renewal_reminders():
    d = db_load()
    from datetime import timedelta
    threshold = (now_utc() + timedelta(days=3)).isoformat()
    sent = 0
    for uid_s, u in d["users"].items():
        plan    = u.get("plan", "free") or "free"
        expires = u.get("plan_expires", "")
        if plan == "free" or not expires:
            continue
        if ts_iso() < expires <= threshold:
            today = now_utc().strftime("%Y-%m-%d")
            if u.get("last_renewal_reminder") == today:
                continue
            try:
                bot.send_message(int(uid_s),
                    f"<b>{G['warn']} Plan Expiring Soon</b>\n"
                    f"{bullet('Plan', plan)}\n{bullet('Expires', expires[:10])}\n"
                    f"Renew now to avoid downtime!", parse_mode="HTML")
                u["last_renewal_reminder"] = today
                sent += 1
            except Exception:
                pass
    if sent:
        db_save(d)
    return sent


def _sub_reminder_loop():
    while True:
        time.sleep(3600)
        try:
            _sub_check_all_expiries()
        except Exception:
            pass
        try:
            _sub_renewal_reminders()
        except Exception:
            pass


# ─── Coupon Engine ──────────────────────────────────────────────────────────

def _coupon_validate(code, uid):
    d = db_load()
    c = d.get("coupons", {}).get(code.upper())
    if not c:
        return False, "Invalid coupon code.", {}
    if c.get("expiry") and c["expiry"] < ts_iso():
        return False, "Coupon expired.", {}
    uses_left = c.get("uses_left")
    if uses_left is not None and uses_left <= 0:
        return False, "No uses remaining.", {}
    if uid in c.get("used_by", []):
        return False, "Already used.", {}
    return True, "", c


def _coupon_redeem(code, uid):
    valid, err, c = _coupon_validate(code, uid)
    if not valid:
        return False, err, 0.0
    d    = db_load()
    coup = d.setdefault("coupons", {}).setdefault(code.upper(), c)
    coup.setdefault("used_by", []).append(uid)
    if coup.get("uses_left") is not None:
        coup["uses_left"] = max(0, coup["uses_left"] - 1)
    db_save(d)
    discount = float(c.get("discount_pct", 0))
    flat     = float(c.get("discount_flat", 0))
    _wh_fire("coupon_redeemed", {"code": code.upper(), "uid": uid,
                                  "discount_pct": discount, "discount_flat": flat})
    return True, f"Coupon applied! Discount: {discount}% / flat {flat}", discount


# ─── File Manager ───────────────────────────────────────────────────────────

def _fm_list_bot_files(bot_id):
    b = find_bot(bot_id)
    if not b:
        return []
    sbox = Path(b.get("sandbox", ""))
    if not sbox.exists():
        return []
    result = []
    try:
        for p in sorted(sbox.rglob("*")):
            if p.is_file():
                result.append({
                    "name": str(p.relative_to(sbox)),
                    "size": p.stat().st_size,
                })
    except Exception:
        pass
    return result


def _fm_read_file(bot_id, rel_path, max_bytes=32768):
    b = find_bot(bot_id)
    if not b:
        return "", False
    sbox   = Path(b.get("sandbox", ""))
    target = (sbox / rel_path).resolve()
    try:
        target.relative_to(sbox.resolve())
    except ValueError:
        return "Access denied.", False
    if not target.exists():
        return "File not found.", False
    data = target.read_bytes()
    trunc = len(data) > max_bytes
    return data[:max_bytes].decode("utf-8", errors="replace"), trunc


def _fm_write_file(bot_id, rel_path, content):
    b = find_bot(bot_id)
    if not b:
        return False
    sbox   = Path(b.get("sandbox", ""))
    target = (sbox / rel_path).resolve()
    try:
        target.relative_to(sbox.resolve())
    except ValueError:
        return False
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        target.write_text(content, encoding="utf-8")
        return True
    except Exception:
        return False


def _fm_zip_sandbox(bot_id):
    import zipfile as _zf
    b = find_bot(bot_id)
    if not b:
        return None
    sbox = Path(b.get("sandbox", ""))
    if not sbox.exists():
        return None
    zip_path = DIRS["tmp"] / f"{bot_id}_export_{int(time.time())}.zip"
    try:
        with _zf.ZipFile(zip_path, "w", _zf.ZIP_DEFLATED) as z:
            for p in sbox.rglob("*"):
                if p.is_file():
                    z.write(p, p.relative_to(sbox))
        return zip_path
    except Exception:
        return None


# ─── Broadcast Engine ───────────────────────────────────────────────────────

_BROADCAST_ACTIVE = {}


def _broadcast_job(job_id, uids, msg, parse_mode="HTML", delay=0.05):
    _BROADCAST_ACTIVE[job_id] = {"total": len(uids), "sent": 0, "failed": 0, "done": False}
    for uid in uids:
        try:
            bot.send_message(uid, msg, parse_mode=parse_mode)
            _BROADCAST_ACTIVE[job_id]["sent"] += 1
        except Exception:
            _BROADCAST_ACTIVE[job_id]["failed"] += 1
        time.sleep(delay)
    _BROADCAST_ACTIVE[job_id]["done"] = True


def _broadcast_start(uids, msg, parse_mode="HTML"):
    import random, string
    job_id = "bc_" + "".join(random.choices(string.ascii_lowercase, k=8))
    threading.Thread(target=_broadcast_job, args=(job_id, uids, msg, parse_mode),
                     daemon=True, name=f"broadcast-{job_id}").start()
    return job_id


# ─── Metrics ────────────────────────────────────────────────────────────────

_METRICS = {
    "messages_received": 0, "callbacks_received": 0, "bot_starts": 0,
    "bot_stops": 0, "bot_crashes": 0, "uploads": 0, "errors": 0,
    "commands": 0, "plan_upgrades": 0, "payments_received": 0,
}
_METRICS_LOCK = threading.Lock()


def _metric(key, n=1):
    with _METRICS_LOCK:
        _METRICS[key] = _METRICS.get(key, 0) + n


def _metrics_snapshot():
    with _METRICS_LOCK:
        return dict(_METRICS)


def _metrics_persist_loop():
    while True:
        time.sleep(300)
        try:
            snap = _metrics_snapshot()
            existing = get_setting("metrics_total", {}) or {}
            for k, v in snap.items():
                existing[k] = existing.get(k, 0) + v
            set_setting("metrics_total", existing)
            with _METRICS_LOCK:
                for k in _METRICS:
                    _METRICS[k] = 0
        except Exception:
            pass


# ─── Security Engine ────────────────────────────────────────────────────────

def _security_scan_code(content):
    patterns = [
        "os.system", "subprocess.call", "eval(compile", "__import__('os').system",
        "open('/etc/passwd')", "/proc/self/environ", "exec(base64",
    ]
    warnings_found = []
    for i, line in enumerate(content.split("\n"), 1):
        for pat in patterns:
            if pat in line:
                warnings_found.append(f"Line {i}: {pat}")
    return warnings_found


def _security_audit_log(uid, action, detail="", risk="low"):
    entry = {"uid": uid, "action": action, "detail": detail, "risk": risk, "ts": ts_iso()}
    log = get_setting("security_audit_log", []) or []
    log.append(entry)
    if len(log) > 500:
        log = log[-500:]
    set_setting("security_audit_log", log)
    if risk in ("high", "critical"):
        try:
            notify_owner(
                f"<b>{G['warn']} Security Alert [{risk.upper()}]</b>\n"
                f"{bullet('User', uid)}\n{bullet('Action', action)}\n"
                f"{bullet('Detail', esc(str(detail)[:200]))}"
            )
        except Exception:
            pass


def _security_detect_token_leak(content):
    import re
    return bool(re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}", re.MULTILINE).search(content))


# ─── Template Engine ────────────────────────────────────────────────────────

def _tmpl_render(key, ctx):
    templates = get_setting("message_templates", {}) or {}
    template  = templates.get(key) or _MESSAGE_TEMPLATES.get(key, "")
    if not template:
        return ""
    try:
        return template.format_map(ctx)
    except (KeyError, ValueError):
        return template


def _tmpl_list():
    return {**dict(_MESSAGE_TEMPLATES), **(get_setting("message_templates", {}) or {})}


def _tmpl_reset_one(key):
    templates = get_setting("message_templates", {}) or {}
    if key in templates:
        del templates[key]
        set_setting("message_templates", templates)
        return True
    return False


# ─── User Profile Engine ────────────────────────────────────────────────────

def _user_activity_score(uid):
    d = db_load()
    u = d["users"].get(str(uid), {})
    score = 0
    score += sum(1 for b in d["bots"].values() if str(b.get("owner")) == str(uid)) * 10
    score += {"free": 0, "basic": 20, "pro": 50, "ultra": 100}.get(
        u.get("plan", "free") or "free", 0)
    score += len(u.get("referrals", [])) * 15
    joined = u.get("joined", "")
    if joined:
        try:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(joined)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            score += min((now_utc() - dt).days, 365)
        except Exception:
            pass
    return score


def _user_get_badges(uid):
    d = db_load()
    u = d["users"].get(str(uid), {})
    badges = []
    plan   = u.get("plan", "free") or "free"
    if plan == "ultra":   badges.append("💎 Ultra Member")
    elif plan == "pro":   badges.append("🥇 Pro Member")
    elif plan == "basic": badges.append("🥈 Basic Member")
    bot_count = sum(1 for b in d["bots"].values() if str(b.get("owner")) == str(uid))
    if bot_count >= 10: badges.append("🤖 Bot Master (10+)")
    elif bot_count >= 5: badges.append("🤖 Bot Expert (5+)")
    elif bot_count >= 1: badges.append("🤖 Bot Hoster")
    refs = len(u.get("referrals", []))
    if refs >= 50:  badges.append("👑 Referral King (50+)")
    elif refs >= 10: badges.append("🌟 Top Referrer (10+)")
    elif refs >= 1:  badges.append("👥 Referrer")
    if _user_activity_score(uid) >= 200: badges.append("🔥 Power User")
    return badges


def _user_profile_card(uid):
    d    = db_load()
    u    = d["users"].get(str(uid), {})
    if not u:
        return "User not found."
    plan   = u.get("plan", "free") or "free"
    p_lim  = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])
    bots   = sum(1 for b in d["bots"].values() if str(b.get("owner")) == str(uid))
    run    = sum(1 for b in d["bots"].values()
                 if str(b.get("owner")) == str(uid) and b.get("status") == "running")
    badges = _user_get_badges(uid)
    score  = _user_activity_score(uid)
    return (
        f"<b>👤 {esc(u.get('name', str(uid)))}</b>\n"
        f"{G['div_eq']}\n"
        + bullet("UID", uid) + "\n"
        + bullet("Plan", p_lim.get("name", plan)) + "\n"
        + bullet("Bots", f"{bots} ({run} running)") + "\n"
        + bullet("Score", score) + "\n"
        + bullet("Badges", len(badges)) + "\n"
        + G["div"] + "\n"
        + "\n".join(f"  • {b}" for b in badges)
    )


# ─── Revenue Engine ─────────────────────────────────────────────────────────

def _rev_projected_monthly():
    day = now_utc().day or 1
    return round(_rev_this_month() / day * 30, 2)


# ─── Leaderboard Engine ─────────────────────────────────────────────────────

def _lb_top_by_bots(n=10):
    d = db_load()
    counts = {}
    for b in d["bots"].values():
        uid = str(b.get("owner", ""))
        counts[uid] = counts.get(uid, 0) + 1
    rows = [(uid, d["users"].get(uid, {}).get("name", uid), cnt)
            for uid, cnt in counts.items()]
    rows.sort(key=lambda x: x[2], reverse=True)
    return rows[:n]


def _lb_top_by_referrals(n=10):
    d = db_load()
    rows = [(uid, u.get("name", uid), len(u.get("referrals", [])))
            for uid, u in d["users"].items() if u.get("referrals")]
    rows.sort(key=lambda x: x[2], reverse=True)
    return rows[:n]


def _lb_top_by_revenue(n=10):
    d = db_load()
    rev = {}
    for uid, u in d["users"].items():
        total = sum(float(tx.get("amount", 0))
                    for tx in u.get("transactions", [])
                    if tx.get("type") in ("payment", "upgrade", "renewal"))
        if total > 0:
            rev[uid] = (u.get("name", uid), total)
    rows = [(uid, name, amt) for uid, (name, amt) in rev.items()]
    rows.sort(key=lambda x: x[2], reverse=True)
    return rows[:n]


def _lb_top_by_score(n=10):
    d = db_load()
    rows = [(uid, u.get("name", uid), _user_activity_score(int(uid)))
            for uid, u in d["users"].items()]
    rows.sort(key=lambda x: x[2], reverse=True)
    return rows[:n]


# ─── Language Engine ────────────────────────────────────────────────────────

_TRANSLATIONS = {
    "en": {"welcome": "Welcome to {brand}!", "plan_expired": "Your plan has expired.",
           "bot_started": "Bot {name} is now running!", "bot_crashed": "Bot {name} crashed.",
           "payment_received": "Payment received! Plan will be updated shortly.",
           "referral_earned": "You earned {amount} credits for referring {user}!"},
    "hi": {"welcome": "{brand} में आपका स्वागत है!", "plan_expired": "आपका प्लान समाप्त हो गया।",
           "bot_started": "बॉट {name} चल रहा है!", "bot_crashed": "बॉट {name} क्रैश हो गया।",
           "payment_received": "भुगतान प्राप्त हुआ!", "referral_earned": "{user} रेफर पर {amount} क्रेडिट मिले!"},
    "ru": {"welcome": "Добро пожаловать в {brand}!", "plan_expired": "Срок плана истёк.",
           "bot_started": "Бот {name} запущен!", "bot_crashed": "Бот {name} упал.",
           "payment_received": "Платёж получен!", "referral_earned": "Заработано {amount} кредитов за {user}!"},
    "ar": {"welcome": "مرحباً في {brand}!", "plan_expired": "انتهت صلاحية خطتك.",
           "bot_started": "البوت {name} يعمل الآن!", "bot_crashed": "تعطل البوت {name}.",
           "payment_received": "تم استلام الدفعة!", "referral_earned": "ربحت {amount} رصيداً لإحالة {user}!"},
    "es": {"welcome": "¡Bienvenido a {brand}!", "plan_expired": "Tu plan ha expirado.",
           "bot_started": "¡El bot {name} está activo!", "bot_crashed": "El bot {name} falló.",
           "payment_received": "¡Pago recibido!", "referral_earned": "¡Ganaste {amount} créditos por referir a {user}!"},
    "tr": {"welcome": "{brand}'e hoş geldiniz!", "plan_expired": "Planın süresi doldu.",
           "bot_started": "{name} botu çalışıyor!", "bot_crashed": "{name} botu çöktü.",
           "payment_received": "Ödeme alındı!", "referral_earned": "{user} için {amount} kredi kazandın!"},
}


def _lang_get_user(uid):
    d = db_load()
    return d["users"].get(str(uid), {}).get("lang", get_setting("ui_language", "en") or "en")


def _lang_set_user(uid, lang):
    d = db_load()
    if str(uid) in d["users"]:
        d["users"][str(uid)]["lang"] = lang
        db_save(d)


def _tr(uid, key, **ctx):
    lang  = _lang_get_user(uid)
    texts = _TRANSLATIONS.get(lang, _TRANSLATIONS["en"])
    tmpl  = texts.get(key) or _TRANSLATIONS["en"].get(key, key)
    try:
        return tmpl.format(**ctx)
    except (KeyError, ValueError):
        return tmpl


# ─── Feature Flags Engine ───────────────────────────────────────────────────

def _ff_get(key):
    flags = get_setting("feature_flags", {}) or {}
    return bool(flags.get(key, _FEATURE_FLAG_DEFAULTS.get(key, True)))


def _ff_set(key, val):
    flags = get_setting("feature_flags", {}) or {}
    flags[key] = bool(val)
    set_setting("feature_flags", flags)


def _ff_toggle(key):
    new_val = not _ff_get(key)
    _ff_set(key, new_val)
    return new_val


def _ff_reset_all():
    set_setting("feature_flags", dict(_FEATURE_FLAG_DEFAULTS))


# ─── 2FA Engine ─────────────────────────────────────────────────────────────

_2FA_CODES = {}
_2FA_LOCK  = threading.Lock()


def _2fa_generate(uid):
    import random
    code = str(random.randint(100000, 999999))
    with _2FA_LOCK:
        _2FA_CODES[uid] = {"code": code, "ts": time.time(), "attempts": 0}
    return code


def _2fa_verify(uid, code):
    with _2FA_LOCK:
        entry = _2FA_CODES.get(uid)
        if not entry:
            return False, "No active session. Request a new code."
        if time.time() - entry["ts"] > 300:
            _2FA_CODES.pop(uid, None)
            return False, "Code expired."
        if entry["attempts"] >= 3:
            _2FA_CODES.pop(uid, None)
            return False, "Too many attempts."
        entry["attempts"] += 1
        if entry["code"] == code.strip():
            _2FA_CODES.pop(uid, None)
            return True, ""
        return False, f"Wrong code. {3 - entry['attempts']} attempt(s) left."


def _2fa_is_enabled():
    return bool(get_setting("admin_2fa_enabled", False))


def _2fa_send_code(uid):
    code = _2fa_generate(uid)
    try:
        bot.send_message(uid,
            f"<b>🔐 Admin 2FA Code</b>\n\n<code>{code}</code>\n\nExpires in 5 minutes.",
            parse_mode="HTML")
        return True
    except Exception:
        return False


def _2fa_session_check(uid):
    sessions = get_setting("admin_2fa_sessions", {}) or {}
    ts = sessions.get(str(uid), {}).get("ts", 0)
    return (time.time() - ts) < 86400


def _2fa_session_create(uid):
    sessions = get_setting("admin_2fa_sessions", {}) or {}
    sessions[str(uid)] = {"ts": time.time()}
    set_setting("admin_2fa_sessions", sessions)


def _2fa_revoke_all():
    set_setting("admin_2fa_sessions", {})


# ─── Import/Export Engine ───────────────────────────────────────────────────

def _export_full_db():
    import json as _json
    payload = {
        "version": "2.0", "exported_at": ts_iso(),
        "db": db_load(), "settings": _load_settings(),
    }
    return _json.dumps(payload, indent=2, default=str).encode("utf-8")


def _import_full_db(data):
    import json as _json
    try:
        payload = _json.loads(data.decode("utf-8"))
    except Exception as e:
        return False, f"JSON parse error: {e}"
    db_data = payload.get("db")
    if not isinstance(db_data, dict) or "users" not in db_data:
        return False, "Invalid DB structure."
    db_save(db_data)
    settings_data = payload.get("settings")
    if isinstance(settings_data, dict):
        _save_settings(settings_data)
    return True, f"Imported {len(db_data['users'])} users, {len(db_data['bots'])} bots."


def _export_users_csv():
    import csv, io
    d   = db_load()
    buf = io.StringIO()
    fn  = ["uid","name","username","plan","plan_expires","joined","banned","credits","referrals","bots"]
    w   = csv.DictWriter(buf, fieldnames=fn)
    w.writeheader()
    for uid, u in d["users"].items():
        bc = sum(1 for b in d["bots"].values() if str(b.get("owner")) == uid)
        w.writerow({"uid": uid, "name": u.get("name",""), "username": u.get("username",""),
                    "plan": u.get("plan","free"), "plan_expires": u.get("plan_expires",""),
                    "joined": u.get("joined",""), "banned": u.get("banned",False),
                    "credits": u.get("credits",0), "referrals": len(u.get("referrals",[])), "bots": bc})
    return buf.getvalue().encode("utf-8")


def _export_bots_csv():
    import csv, io
    d   = db_load()
    buf = io.StringIO()
    fn  = ["bot_id","name","owner","status","created","main_file","crash_count","total_run_hours"]
    w   = csv.DictWriter(buf, fieldnames=fn)
    w.writeheader()
    for bid, b in d["bots"].items():
        w.writerow({"bot_id": bid, "name": b.get("name",""), "owner": b.get("owner",""),
                    "status": b.get("status","stopped"), "created": b.get("created",""),
                    "main_file": b.get("main_file",""), "crash_count": b.get("crash_count",0),
                    "total_run_hours": b.get("total_run_hours",0)})
    return buf.getvalue().encode("utf-8")


def _export_transactions_csv():
    import csv, io
    d   = db_load()
    buf = io.StringIO()
    fn  = ["uid","user_name","type","amount","plan","ts","note"]
    w   = csv.DictWriter(buf, fieldnames=fn)
    w.writeheader()
    for uid, u in d["users"].items():
        for tx in u.get("transactions", []):
            w.writerow({"uid": uid, "user_name": u.get("name",""), "type": tx.get("type",""),
                        "amount": tx.get("amount",0), "plan": tx.get("plan",""),
                        "ts": tx.get("ts",""), "note": tx.get("note","")})
    return buf.getvalue().encode("utf-8")


def _export_audit_log_csv():
    import csv, io
    log = get_setting("security_audit_log", []) or []
    buf = io.StringIO()
    fn  = ["ts","uid","action","detail","risk"]
    w   = csv.DictWriter(buf, fieldnames=fn)
    w.writeheader()
    for e in log:
        w.writerow({"ts": e.get("ts",""), "uid": e.get("uid",""), "action": e.get("action",""),
                    "detail": e.get("detail",""), "risk": e.get("risk","low")})
    return buf.getvalue().encode("utf-8")


# ─── Janitor Engine ─────────────────────────────────────────────────────────

def _janitor_purge_stale_tmp(max_age_hours=24):
    count  = 0
    cutoff = time.time() - max_age_hours * 3600
    for p in DIRS["tmp"].iterdir():
        try:
            if p.is_file() and p.stat().st_mtime < cutoff:
                p.unlink(); count += 1
        except Exception:
            pass
    return count


def _janitor_purge_empty_sandboxes():
    import shutil
    d           = db_load()
    valid_ids   = set(d["bots"].keys())
    sandbox_root= DIRS.get("sandboxes", BASE_DIR / "sandboxes")
    count       = 0
    if not sandbox_root.exists():
        return 0
    for p in sandbox_root.iterdir():
        if p.is_dir() and p.name not in valid_ids:
            try:
                shutil.rmtree(p); count += 1
            except Exception:
                pass
    return count


def _janitor_compact_db():
    d = db_load()
    tx_trunc = 0
    for u in d["users"].values():
        txs = u.get("transactions", [])
        if len(txs) > 200:
            u["transactions"] = txs[-200:]
            tx_trunc += len(txs) - 200
    orphan = [bid for bid, b in d["bots"].items() if not b.get("owner")]
    for bid in orphan:
        del d["bots"][bid]
    sessions = get_setting("admin_2fa_sessions", {}) or {}
    stale    = [k for k, v in sessions.items() if time.time() - v.get("ts",0) > 86400]
    for k in stale:
        sessions.pop(k, None)
    set_setting("admin_2fa_sessions", sessions)
    db_save(d)
    return {"tx_truncated": tx_trunc, "orphan_bots": len(orphan), "stale_sessions": len(stale)}


def _janitor_full_run():
    tmp_del  = _janitor_purge_stale_tmp()
    sbox_del = _janitor_purge_empty_sandboxes()
    ok, ver  = _do_clean_orphans()
    compact  = _janitor_compact_db()
    return {
        "tmp_files_deleted":    tmp_del,
        "empty_sandboxes":      sbox_del,
        "orphan_procs_killed":  ok,
        "orphan_procs_verified":ver,
        "tx_truncated":         compact["tx_truncated"],
        "orphan_bots_removed":  compact["orphan_bots"],
        "stale_sessions_purged":compact["stale_sessions"],
    }


# ─── Scheduler Engine ───────────────────────────────────────────────────────

def _sched_add_task(task_type, task_time, msg, target="all"):
    tasks = get_setting("scheduled_tasks", []) or []
    task  = {
        "id": f"task_{int(time.time())}", "type": task_type, "time": task_time,
        "msg": msg, "target": target, "enabled": True, "created": ts_iso(),
        "last_run": None, "run_count": 0,
    }
    tasks.append(task)
    set_setting("scheduled_tasks", tasks)
    return task


def _sched_remove_task(task_id):
    tasks = get_setting("scheduled_tasks", []) or []
    orig  = len(tasks)
    tasks = [t for t in tasks if t.get("id") != task_id]
    if len(tasks) < orig:
        set_setting("scheduled_tasks", tasks)
        return True
    return False


def _sched_toggle_task(task_id):
    tasks = get_setting("scheduled_tasks", []) or []
    for t in tasks:
        if t.get("id") == task_id:
            t["enabled"] = not t.get("enabled", True)
            set_setting("scheduled_tasks", tasks)
            return t["enabled"]
    return None


def _sched_broadcast(msg, target="all"):
    d    = db_load()
    uids = []
    for uid_s, u in d["users"].items():
        if u.get("banned"):
            continue
        if target == "all":
            uids.append(int(uid_s))
        elif target == "paid" and u.get("plan","free") not in ("free", None):
            uids.append(int(uid_s))
        elif target == "free" and u.get("plan","free") in ("free", None):
            uids.append(int(uid_s))
    sent = 0
    for uid in uids:
        try:
            bot.send_message(uid, msg, parse_mode="HTML")
            sent += 1; time.sleep(0.04)
        except Exception:
            pass
    return sent


# ─── Referral Engine ────────────────────────────────────────────────────────

def _ref_process(new_uid, ref_uid):
    if not _ff_get("referral_enabled") or new_uid == ref_uid:
        return False
    d       = db_load()
    ref_u   = d["users"].get(str(ref_uid), {})
    if new_uid in ref_u.get("referrals", []):
        return False
    reward  = float(get_setting("referral_reward", 0) or 0)
    ref_u.setdefault("referrals", []).append(new_uid)
    if reward > 0:
        ref_u["credits"] = float(ref_u.get("credits", 0)) + reward
    db_save(d)
    try:
        new_name = d["users"].get(str(new_uid), {}).get("name", str(new_uid))
        bot.send_message(ref_uid,
            f"<b>{G['spark']} Referral Reward!</b>\n"
            f"{bullet('New user', esc(str(new_name)))}\n"
            f"{bullet('Credits', reward)}", parse_mode="HTML")
    except Exception:
        pass
    _wh_fire("referral", {"ref_uid": ref_uid, "new_uid": new_uid, "reward": reward})
    return True


def _ref_get_link(uid):
    me = bot.get_me()
    return f"https://t.me/{me.username if me else 'YourBot'}?start=ref_{uid}"


def _ref_stats(uid):
    d   = db_load()
    u   = d["users"].get(str(uid), {})
    refs= u.get("referrals", [])
    return {
        "total":   len(refs),
        "credits": u.get("credits", 0),
        "link":    _ref_get_link(uid),
        "users":   [{
            "uid":  rid,
            "name": d["users"].get(str(rid), {}).get("name", str(rid)),
            "plan": d["users"].get(str(rid), {}).get("plan", "free"),
        } for rid in refs],
    }


# ─── Monitor / Diagnostics ──────────────────────────────────────────────────

def _monitor_system_stats():
    import os
    stats = {}
    stats["uptime"] = fmt_dur(int(time.time() - START_TIME) * 1000)
    stats["uptime_secs"] = int(time.time() - START_TIME)
    try:
        with open("/proc/meminfo") as f:
            mem = {}
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    mem[parts[0].rstrip(":")] = int(parts[1])
        tm = mem.get("MemTotal",0)//1024
        av = mem.get("MemAvailable",0)//1024
        stats.update({"mem_total_mb": tm, "mem_used_mb": tm-av,
                       "mem_pct": round((tm-av)/tm*100,1) if tm else 0})
    except Exception:
        stats.update({"mem_total_mb": 0, "mem_used_mb": 0, "mem_pct": 0})
    try:
        with open("/proc/loadavg") as f:
            la = f.read().split()
        stats.update({"load_1": float(la[0]), "load_5": float(la[1]), "load_15": float(la[2])})
    except Exception:
        stats.update({"load_1": 0, "load_5": 0, "load_15": 0})
    try:
        st = os.statvfs(str(BASE_DIR))
        tg = st.f_blocks*st.f_frsize/1e9
        fg = st.f_bavail*st.f_frsize/1e9
        stats.update({"disk_total_gb": round(tg,2), "disk_used_gb": round(tg-fg,2),
                       "disk_free_gb": round(fg,2), "disk_pct": round((tg-fg)/tg*100,1) if tg else 0})
    except Exception:
        stats.update({"disk_total_gb": 0, "disk_used_gb": 0, "disk_pct": 0})
    stats["running_bots"]  = len(RUNNING)
    stats["total_threads"] = threading.active_count()
    stats["pid"]           = os.getpid()
    try:
        d = db_load()
        stats["total_users"]  = len(d["users"])
        stats["total_bots"]   = len(d["bots"])
        stats["paid_users"]   = sum(1 for u in d["users"].values()
                                    if u.get("plan","free") not in ("free",None))
    except Exception:
        stats.update({"total_users":0,"total_bots":0,"paid_users":0})
    stats["metrics"] = _metrics_snapshot()
    return stats


def _progress_bar(current, total=None, width=12):
    # Supports both _progress_bar(pct) and _progress_bar(sent, total).
    if total is None:
        try:
            pct = max(0, min(100, int(current)))
        except Exception:
            pct = 0
        filled = int(round(width * pct / 100))
        return "▓" * filled + "░" * (width - filled) + f" {pct:>3}%"
    if total <= 0:
        return "░" * width + " 0%"
    pct    = min(current / total, 1.0)
    filled = int(pct * width)
    return "█" * filled + "░" * (width - filled) + f" {pct*100:.1f}%"


def _run_diagnostics():
    import os, shutil
    report = {
        "bot_token":      bool(os.environ.get("BOT_TOKEN")),
        "db_writable":    DB_FILE.parent.exists() and os.access(str(DB_FILE.parent), os.W_OK),
        "sandbox_exists": DIRS.get("sandboxes", BASE_DIR/"sandboxes").exists(),
        "python_found":   bool(shutil.which("python3")),
        "owner_set":      OWNER_ID > 0,
        "threads_running":threading.active_count() > 3,
        "uptime_secs":    int(time.time() - START_TIME),
        "running_bots":   len(RUNNING),
    }
    return report


# ─── Utility Helpers ────────────────────────────────────────────────────────

def _truncate(s, max_len=200, suffix="…"):
    return s if len(s) <= max_len else s[:max_len-len(suffix)] + suffix

def _sanitize_filename(name):
    import re
    return re.sub(r"[^\w\-_\. ]","_",name).strip()[:100]

def _human_number(n):
    if n >= 1_000_000: return f"{n/1_000_000:.1f}M"
    if n >= 1_000:     return f"{n/1_000:.1f}K"
    return str(int(n))

def _safe_int(val, default=0):
    try:    return int(val)
    except: return default

def _safe_float(val, default=0.0):
    try:    return float(val)
    except: return default

def _clamp(val, lo, hi):
    return max(lo, min(hi, val))

def _chunk_list(lst, size):
    return [lst[i:i+size] for i in range(0, len(lst), size)]

def _hash_str(s):
    import hashlib
    return hashlib.sha256(s.encode()).hexdigest()

def _gen_random_id(length=12):
    import random, string
    return "".join(random.choices(string.ascii_lowercase+string.digits, k=length))

def _gen_coupon_code(prefix="", length=8):
    import random, string
    return (prefix + "".join(random.choices(string.ascii_uppercase+string.digits, k=length))).upper()

def _parse_duration(s):
    import re
    m = re.match(r"^(\d+)\s*([dhms]?)$", s.strip().lower())
    if not m: return 0
    return int(m.group(1)) * {"d":86400,"h":3600,"m":60,"s":1}.get(m.group(2) or "s", 1)

def _format_duration_human(secs):
    if secs < 0: return "0s"
    d,secs = divmod(int(secs),86400)
    h,secs = divmod(secs,3600)
    mi,s   = divmod(secs,60)
    parts  = []
    if d:  parts.append(f"{d}d")
    if h:  parts.append(f"{h}h")
    if mi: parts.append(f"{mi}m")
    if s or not parts: parts.append(f"{s}s")
    return " ".join(parts)

def _iso_add_days(iso_ts, days):
    try:
        from datetime import datetime, timezone, timedelta
        dt = datetime.fromisoformat(iso_ts)
        if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
        return (dt + timedelta(days=days)).isoformat()
    except Exception:
        return iso_ts

def _iso_now_plus_days(days):
    from datetime import timedelta
    return (now_utc() + timedelta(days=days)).isoformat()

def _validate_bot_token_format(token):
    import re
    return bool(re.match(r"^\d{8,10}:[A-Za-z0-9_-]{35}$", token.strip()))

def _validate_url(url):
    return url.startswith(("http://","https://")) and "." in url

def _time_since(iso_ts):
    if not iso_ts: return "never"
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(iso_ts)
        if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
        secs = int((now_utc()-dt).total_seconds())
        if secs < 60:   return f"{secs}s ago"
        if secs < 3600: return f"{secs//60}m ago"
        if secs < 86400:return f"{secs//3600}h ago"
        return f"{secs//86400}d ago"
    except: return iso_ts[:10]

def _until(iso_ts):
    if not iso_ts: return "never"
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(iso_ts)
        if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
        secs = int((dt-now_utc()).total_seconds())
        if secs <= 0:   return "expired"
        if secs < 3600: return f"{secs//60}m"
        if secs < 86400:return f"{secs//3600}h"
        return f"{secs//86400}d"
    except: return iso_ts[:10]

def _mask_token(token):
    if not token or len(token) < 10: return "****"
    return token[:6] + "..." + token[-4:]

def _mask_secret(s, show_chars=4):
    if not s: return "—"
    if len(s) <= show_chars: return "*"*len(s)
    return s[:show_chars] + "*"*(len(s)-show_chars)

def _size_of_dir(path):
    total = 0
    try:
        for p in Path(path).rglob("*"):
            if p.is_file():
                try: total += p.stat().st_size
                except: pass
    except: pass
    return total

def _env_dict_from_str(env_str):
    result = {}
    for line in env_str.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"): continue
        if "=" in line:
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip()
    return result

def _env_dict_to_str(env_dict):
    return "\n".join(f"{k}={v}" for k, v in sorted(env_dict.items()))

def _diff_dicts(old, new):
    changes = {}
    for k in set(old)|set(new):
        ov, nv = old.get(k,"__MISSING__"), new.get(k,"__MISSING__")
        if ov != nv: changes[k] = {"old": ov, "new": nv}
    return changes


# ─── API Key Manager ────────────────────────────────────────────────────────

def _apikey_generate(uid):
    import secrets
    key = "sbhb_" + secrets.token_urlsafe(32)
    d = db_load()
    if str(uid) in d["users"]:
        d["users"][str(uid)]["api_key_hash"] = _hash_str(key)
        d["users"][str(uid)]["api_key_created"] = ts_iso()
        db_save(d)
    return key


def _apikey_verify(key):
    key_hash = _hash_str(key)
    d = db_load()
    for uid_s, u in d["users"].items():
        if u.get("api_key_hash") == key_hash:
            return int(uid_s)
    return 0


def _apikey_revoke(uid):
    d = db_load()
    if str(uid) in d["users"]:
        d["users"][str(uid)].pop("api_key_hash", None)
        d["users"][str(uid)].pop("api_key_created", None)
        db_save(d)
        return True
    return False


# ─── Payment Processor ──────────────────────────────────────────────────────

def _payment_create_request(uid, plan, amount, method, coupon=""):
    import random, string
    req_id   = "pay_" + "".join(random.choices(string.ascii_lowercase+string.digits, k=12))
    discount = 0.0
    if coupon:
        ok, _, c = _coupon_validate(coupon, uid)
        if ok:
            discount = float(c.get("discount_pct", 0))
            flat     = float(c.get("discount_flat", 0))
            if discount: amount = round(amount*(1-discount/100), 2)
            if flat:     amount = max(0, round(amount-flat, 2))
    req = {"id": req_id, "uid": uid, "plan": plan, "amount": amount, "method": method,
           "coupon": coupon, "discount": discount, "status": "pending",
           "created": ts_iso(), "updated": ts_iso(), "note": ""}
    reqs = get_setting("payment_requests", []) or []
    reqs.append(req)
    if len(reqs) > 1000: reqs = reqs[-1000:]
    set_setting("payment_requests", reqs)
    _wh_fire("payment_request_created", {"req_id": req_id, "uid": uid, "plan": plan, "amount": amount})
    return req


def _payment_approve(req_id, admin_uid, note=""):
    reqs = get_setting("payment_requests", []) or []
    req  = next((r for r in reqs if r["id"] == req_id), None)
    if not req: return False, "Request not found."
    if req["status"] != "pending": return False, f"Already {req['status']}."
    req.update({"status": "approved", "updated": ts_iso(), "note": note, "approved_by": admin_uid})
    set_setting("payment_requests", reqs)
    uid, plan = req["uid"], req["plan"]
    d = db_load()
    u = d["users"].get(str(uid), {})
    old_plan = u.get("plan", "free")
    u["plan"] = plan
    expires  = u.get("plan_expires", "")
    base     = ts_iso() if not expires or expires < ts_iso() else expires
    u["plan_expires"] = _iso_add_days(base, 30)
    u.setdefault("transactions", []).append({
        "type": "upgrade", "ts": ts_iso(), "plan": plan,
        "amount": req["amount"], "req_id": req_id, "note": note})
    db_save(d)
    audit(admin_uid, "payment_approved", f"req={req_id} uid={uid} plan={plan}")
    _wh_fire("payment_approved", {"req_id": req_id, "uid": uid, "plan": plan})
    _metric("plan_upgrades"); _metric("payments_received")
    try:
        bot.send_message(uid,
            f"<b>{G['ok']} Payment Approved!</b>\n"
            f"{bullet('Plan', plan)}\n{bullet('Expires', u['plan_expires'][:10])}\n"
            f"Enjoy your upgraded features!", parse_mode="HTML")
    except Exception:
        pass
    return True, f"Approved. {old_plan} → {plan}."


def _payment_reject(req_id, admin_uid, reason=""):
    reqs = get_setting("payment_requests", []) or []
    req  = next((r for r in reqs if r["id"] == req_id), None)
    if not req: return False, "Not found."
    req.update({"status": "rejected", "updated": ts_iso(), "note": reason, "rejected_by": admin_uid})
    set_setting("payment_requests", reqs)
    uid = req["uid"]
    audit(admin_uid, "payment_rejected", f"req={req_id} uid={uid}")
    _wh_fire("payment_rejected", {"req_id": req_id, "uid": uid, "reason": reason})
    try:
        bot.send_message(uid,
            f"<b>{G['no']} Payment Rejected</b>\n"
            f"{bullet('Reason', esc(reason) if reason else 'Not specified')}",
            parse_mode="HTML")
    except Exception:
        pass
    return True, "Rejected."


def _payment_list_pending():
    reqs = get_setting("payment_requests", []) or []
    return sorted([r for r in reqs if r.get("status") == "pending"],
                  key=lambda r: r.get("created",""), reverse=True)


def _payment_stats():
    reqs     = get_setting("payment_requests", []) or []
    approved = [r for r in reqs if r.get("status") == "approved"]
    return {
        "total":    len(reqs),
        "pending":  sum(1 for r in reqs if r.get("status") == "pending"),
        "approved": len(approved),
        "rejected": sum(1 for r in reqs if r.get("status") == "rejected"),
        "revenue":  sum(float(r.get("amount",0)) for r in approved),
    }


# ─── Process Monitor ────────────────────────────────────────────────────────

def _proc_get_memory_mb(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024
    except Exception:
        pass
    return 0.0


def _all_running_bot_stats():
    result = []
    for bid, info in list(RUNNING.items()):
        proc = info.get("proc")
        pid  = proc.pid if proc else 0
        b    = find_bot(bid)
        result.append({
            "bot_id":    bid,
            "name":      b.get("name", bid) if b else bid,
            "owner":     b.get("owner", 0)  if b else 0,
            "pid":       pid,
            "memory_mb": _proc_get_memory_mb(pid),
            "started_at":info.get("started_at", ""),
        })
    result.sort(key=lambda x: x["memory_mb"], reverse=True)
    return result


# ─── Extra Admin Render Helpers ─────────────────────────────────────────────

def render_adm_diagnostics(call):
    report = _run_diagnostics()
    ok = lambda v: "✅" if v else "❌"
    cap = (
        f"<b>🔬 {sc('System Diagnostics')}</b>\n{G['div_eq']}\n"
        f"{ok(report['bot_token'])}  BOT_TOKEN set\n"
        f"{ok(report['db_writable'])}  DB writable\n"
        f"{ok(report['sandbox_exists'])}  Sandbox dir\n"
        f"{ok(report['python_found'])}  Python found\n"
        f"{ok(report['owner_set'])}  Owner configured\n"
        f"{ok(report['threads_running'])}  Background threads\n"
        f"{G['div']}\n"
        + bullet("Uptime", _format_duration_human(report["uptime_secs"])) + "\n"
        + bullet("Running bots", report["running_bots"]) + "\n"
        + G["div"] + FOOTER
    )
    show_menu(call.message.chat.id, PHOTOS.get("monitor", PHOTOS["admin"]),
              cap, _adm_back("menu_admin"), call=call)


def render_adm_payment_requests(call):
    pending = _payment_list_pending()
    pstats  = _payment_stats()
    lines   = [
        f"<b>💳 {sc('Payment Requests')}</b>", G["div_eq"],
        bullet("Total",    pstats["total"]),   bullet("Pending",  pstats["pending"]),
        bullet("Approved", pstats["approved"]),bullet("Revenue",  round(pstats["revenue"],2)),
        G["div"],
    ]
    if not pending:
        lines.append(f"  {sc('No pending requests')}")
    for req in pending[:10]:
        lines.append(f"  💳 <code>{req['id'][:12]}</code> {req['uid']} → {req['plan']} ({req['amount']})")
    lines.append(G["div"] + FOOTER)
    cap = "\n".join(lines)
    kb  = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("✅  Aᴘᴘʀᴏᴠᴇ", callback_data="adm_pay_approve_select", style="success"),
        Btn("❌  Rᴇᴊᴇᴄᴛ",   callback_data="adm_pay_reject_select",  style="danger"),
    )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("pay_config", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_process_monitor(call):
    stats = _all_running_bot_stats()
    lines = [f"<b>🔬 {sc('Process Monitor')}</b>", G["div_eq"],
             bullet("Running bots", len(stats)), G["div"]]
    if not stats:
        lines.append(f"  {sc('No bots running')}")
    for s in stats[:15]:
        lines.append(f"  🤖 <b>{esc(str(s['name'])[:20])}</b>  PID:{s['pid']}  Mem:{s['memory_mb']:.1f}MB")
    lines.append(G["div"] + FOOTER)
    show_menu(call.message.chat.id, PHOTOS.get("monitor", PHOTOS["admin"]),
              "\n".join(lines), _adm_back("adm_live_monitor"), call=call)


def render_adm_security_log(call):
    log    = get_setting("security_audit_log", []) or []
    recent = list(reversed(log[-20:]))
    lines  = [f"<b>🔐 {sc('Security Audit Log')}</b>", G["div_eq"],
              bullet("Total entries", len(log)), G["div"]]
    risk_icon = {"low":"🟢","medium":"🟡","high":"🔴","critical":"💀"}
    for e in recent[:15]:
        icon = risk_icon.get(e.get("risk","low"),"🟢")
        lines.append(f"  {icon} <code>{e.get('ts','')[:16]}</code> {e.get('uid','?')}: {esc(str(e.get('action',''))[:30])}")
    lines.append(G["div"] + FOOTER)
    show_menu(call.message.chat.id, PHOTOS["admin"], "\n".join(lines), _adm_back("menu_admin"), call=call)


def render_adm_broadcast_status(call):
    lines = [f"<b>📢 {sc('Broadcast Status')}</b>", G["div_eq"]]
    if not _BROADCAST_ACTIVE:
        lines.append(f"  {sc('No active broadcast jobs')}")
    for jid, st in _BROADCAST_ACTIVE.items():
        done  = st.get("done", False)
        total = st.get("total", 0)
        sent  = st.get("sent", 0)
        fail  = st.get("failed", 0)
        lines.append(f"  {'✅' if done else '🔄'} <code>{jid}</code>")
        lines.append(f"     {_progress_bar(sent+fail, total)}")
        lines.append(f"     Sent:{sent} Failed:{fail} Total:{total}")
    lines.append(G["div"] + FOOTER)
    show_menu(call.message.chat.id, PHOTOS["admin"], "\n".join(lines), _adm_back("menu_admin"), call=call)


def render_adm_api_keys(call):
    d    = db_load()
    keys = [(uid, u.get("name",uid), u.get("api_key_created","")[:10])
            for uid, u in d["users"].items() if u.get("api_key_hash")]
    lines = [f"<b>🔑 {sc('API Key Manager')}</b>", G["div_eq"],
             bullet("Users with keys", len(keys)), G["div"]]
    for uid, name, created in keys[:10]:
        lines.append(f"  🔑 <code>{uid}</code>  {esc(str(name)[:20])} (created {created})")
    lines.append(G["div"] + FOOTER)
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(Btn("🗑️  Rᴇᴠᴏᴋᴇ Aʟʟ", callback_data="adm_apikey_revoke_all", style="danger"))
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS["admin"], "\n".join(lines), kb, call=call)


def action_adm_sub_send_reminders(call):
    sent = _sub_renewal_reminders()
    ack(call, f"{G['ok']} Sent {sent} renewal reminder(s)")


def render_adm_webhook_log(call):
    log    = get_setting("webhook_log", []) or []
    recent = list(reversed(log[-20:]))
    lines  = [f"<b>🔗 {sc('Webhook Log')}</b>", G["div_eq"], bullet("Total", len(log)), G["div"]]
    for e in recent[:15]:
        st   = str(e.get("status","?"))
        icon = "✅" if st in ("200","201","204") else "❌"
        lines.append(f"  {icon} <code>{e.get('ts','')[:16]}</code> {esc(str(e.get('event',''))[:25])} → {st}")
    lines.append(G["div"] + FOOTER)
    show_menu(call.message.chat.id, PHOTOS.get("webhooks", PHOTOS["admin"]),
              "\n".join(lines), _adm_back("adm_webhooks"), call=call)


def render_adm_rate_stats(call):
    with _RATE_LOCK:
        bc    = len(_RATE_BUCKETS)
        top   = sorted(_RATE_BUCKETS.items(), key=lambda x: x[1]["count"], reverse=True)[:10]
    lines = [f"<b>⚡ {sc('Rate Limit Stats')}</b>", G["div_eq"], bullet("Active buckets", bc), G["div"]]
    for key, bucket in top:
        lines.append(f"  <code>{key[:30]}</code>: {bucket['count']} hits")
    lines.append(G["div"] + FOOTER)
    show_menu(call.message.chat.id, PHOTOS.get("rate_limits", PHOTOS["admin"]),
              "\n".join(lines), _adm_back("adm_rate_cfg"), call=call)


def action_adm_export_full_db(call):
    data  = _export_full_db()
    fname = f"simran_db_{now_utc().strftime('%Y%m%d_%H%M%S')}.json"
    import io
    bot.send_document(call.message.chat.id, (fname, io.BytesIO(data)),
                      caption=f"<b>📂 Full DB Export</b>\n{bullet('Size', fmt_bytes(len(data)))}",
                      parse_mode="HTML")
    ack(call, f"{G['ok']} Export sent")


def action_adm_export_users_csv(call):
    data  = _export_users_csv()
    fname = f"simran_users_{now_utc().strftime('%Y%m%d')}.csv"
    import io
    bot.send_document(call.message.chat.id, (fname, io.BytesIO(data)),
                      caption=f"<b>👥 Users CSV</b>\n{bullet('Size', fmt_bytes(len(data)))}",
                      parse_mode="HTML")
    ack(call, f"{G['ok']} Users CSV sent")


def action_adm_export_bots_csv(call):
    data  = _export_bots_csv()
    fname = f"simran_bots_{now_utc().strftime('%Y%m%d')}.csv"
    import io
    bot.send_document(call.message.chat.id, (fname, io.BytesIO(data)),
                      caption=f"<b>🤖 Bots CSV</b>\n{bullet('Size', fmt_bytes(len(data)))}",
                      parse_mode="HTML")
    ack(call, f"{G['ok']} Bots CSV sent")


def action_adm_export_trans_csv(call):
    data  = _export_transactions_csv()
    fname = f"simran_transactions_{now_utc().strftime('%Y%m%d')}.csv"
    import io
    bot.send_document(call.message.chat.id, (fname, io.BytesIO(data)),
                      caption=f"<b>💳 Transactions CSV</b>\n{bullet('Size', fmt_bytes(len(data)))}",
                      parse_mode="HTML")
    ack(call, f"{G['ok']} Transactions CSV sent")


def action_adm_export_audit_csv(call):
    data  = _export_audit_log_csv()
    fname = f"simran_audit_{now_utc().strftime('%Y%m%d')}.csv"
    import io
    bot.send_document(call.message.chat.id, (fname, io.BytesIO(data)),
                      caption=f"<b>🔐 Audit CSV</b>\n{bullet('Size', fmt_bytes(len(data)))}",
                      parse_mode="HTML")
    ack(call, f"{G['ok']} Audit CSV sent")


def render_adm_referral_detail(call):
    top       = _analytics_top_referrers(15)
    total_refs= sum(r[2] for r in top)
    lines     = [f"<b>👥 {sc('Referral Analytics')}</b>", G["div_eq"],
                 bullet("Total referrals", total_refs), bullet("Active referrers", len(top)),
                 bullet("Reward/referral", get_setting("referral_reward", 0)),
                 G["div"], f"<b>🏆 Top Referrers</b>"]
    medals = ["🥇","🥈","🥉"]
    for i, (uid, name, cnt) in enumerate(top[:10], 1):
        m = medals[i-1] if i <= 3 else f"{i}."
        lines.append(f"  {m} {esc(str(name)[:20])} — {cnt} refs")
    lines.append(G["div"] + FOOTER)
    show_menu(call.message.chat.id, PHOTOS.get("referral_adm", PHOTOS["admin"]),
              "\n".join(lines), _adm_back("adm_referral_sys"), call=call)


def render_adm_sub_expiry_report(call):
    d   = db_load()
    from datetime import timedelta
    thr = (now_utc() + timedelta(days=7)).isoformat()
    now = ts_iso()
    exp = [(uid, u.get("name",uid), u.get("plan","free"), u.get("plan_expires","")[:10])
           for uid, u in d["users"].items()
           if u.get("plan","free") not in ("free",None)
           and u.get("plan_expires","") and now < u["plan_expires"] <= thr]
    exp.sort(key=lambda x: x[3])
    lines = [f"<b>⏰ {sc('Expiring Soon (7d)')}</b>", G["div_eq"], bullet("Expiring", len(exp)), G["div"]]
    for uid, name, plan, date in exp[:15]:
        lines.append(f"  ⏳ {esc(str(name)[:18])} — {plan} — {date}")
    lines.append(G["div"] + FOOTER)
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(Btn("📨  Sᴇɴᴅ Rᴇᴍɪɴᴅᴇʀꜱ", callback_data="adm_sub_send_reminders", style="primary"))
    kb.add(Btn(f"{G['back']}  Sᴜʙꜱ", callback_data="adm_subscriptions", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("subscriptions", PHOTOS["admin"]),
              "\n".join(lines), kb, call=call)


def render_adm_lang_stats(call):
    d      = db_load()
    counts = {}
    for u in d["users"].values():
        lang = u.get("lang","en") or "en"
        counts[lang] = counts.get(lang,0) + 1
    total = len(d["users"]) or 1
    lines = [f"<b>🌐 {sc('Language Stats')}</b>", G["div_eq"],
             bullet("Total users", len(d["users"])),
             bullet("Default", get_setting("ui_language","en") or "en"), G["div"]]
    for lang, cnt in sorted(counts.items(), key=lambda x: x[1], reverse=True):
        name = _SUPPORTED_LANGUAGES.get(lang, lang)
        lines.append(f"  🌐 {name}: {cnt} ({round(cnt/total*100,1)}%)")
    lines.append(G["div"] + FOOTER)
    show_menu(call.message.chat.id, PHOTOS.get("lang_panel", PHOTOS["admin"]),
              "\n".join(lines), _adm_back("adm_lang_panel"), call=call)


def render_adm_scheduler_history(call):
    tasks = get_setting("scheduled_tasks", []) or []
    lines = [f"<b>⏰ {sc('Scheduler Tasks')}</b>", G["div_eq"], bullet("Total tasks", len(tasks)), G["div"]]
    for t in tasks[:15]:
        icon = "🟢" if t.get("enabled",True) else "🔴"
        ttime = t.get("time","?")[:16]
        runs  = t.get("run_count",0)
        msg_p = esc(str(t.get("msg",""))[:30]) + "…"
        lines.append(f"  {icon} [{t.get('type','daily')}] {ttime} runs:{runs}  {msg_p}")
    lines.append(G["div"] + FOOTER)
    show_menu(call.message.chat.id, PHOTOS.get("scheduler", PHOTOS["admin"]),
              "\n".join(lines), _adm_back("adm_scheduler"), call=call)


def render_adm_export_menu(call):
    cap = (
        f"<b>📦 {sc('Export & Import')}</b>\n{G['div_eq']}\n"
        f"{sc('Export data in multiple formats')}\n\n"
        f"• <b>Full DB JSON</b> — complete backup\n"
        f"• <b>Users CSV</b>\n• <b>Bots CSV</b>\n"
        f"• <b>Transactions CSV</b>\n• <b>Audit Log CSV</b>\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("📂  Fᴜʟʟ DB",     callback_data="adm_export_full_db",   style="primary"),
        Btn("👥  Uꜱᴇʀꜱ CSV",   callback_data="adm_export_users_csv", style="primary"),
    )
    kb.add(
        Btn("🤖  Bᴏᴛꜱ CSV",   callback_data="adm_export_bots_csv",  style="primary"),
        Btn("💳  Tʀᴀɴꜱ CSV",  callback_data="adm_export_trans_csv", style="primary"),
    )
    kb.add(
        Btn("🔐  Aᴜᴅɪᴛ CSV",  callback_data="adm_export_audit_csv", style="primary"),
        Btn("📥  Iᴍᴘᴏʀᴛ DB",  callback_data="adm_import_db",        style="danger"),
    )
    kb.add(Btn(f"{G['back']}  Aᴅᴍɪɴ", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("import_export", PHOTOS["admin"]), cap, kb, call=call)


# ─── Extra Callback Router ──────────────────────────────────────────────────

def _register_extra_routes(data, call):
    """Returns True if handled."""
    # Help
    if data == "help_main":                  render_help_page(call.message.chat.id,"main",call=call); return True
    if data.startswith("help_"):             render_help_page(call.message.chat.id,data[5:],call=call); return True
    # Extra admin panels
    if data == "adm_diagnostics":            render_adm_diagnostics(call); return True
    if data == "adm_payment_requests":       render_adm_payment_requests(call); return True
    if data == "adm_process_monitor":        render_adm_process_monitor(call); return True
    if data == "adm_security_log":           render_adm_security_log(call); return True
    if data == "adm_broadcast_status":       render_adm_broadcast_status(call); return True
    if data == "adm_api_keys":               render_adm_api_keys(call); return True
    if data == "adm_apikey_revoke_all":
        if not is_owner(call.from_user.id):  ack(call,"Owner only"); return True
        d = db_load()
        cnt = 0
        for u in d["users"].values():
            if u.pop("api_key_hash",None): u.pop("api_key_created",None); cnt+=1
        db_save(d); ack(call,f"{G['ok']} Revoked {cnt} API keys")
        render_adm_api_keys(call); return True
    if data == "adm_sub_send_reminders":     action_adm_sub_send_reminders(call); return True
    if data == "adm_webhook_log":            render_adm_webhook_log(call); return True
    if data == "adm_rate_stats":             render_adm_rate_stats(call); return True
    if data == "adm_export_full_db":         action_adm_export_full_db(call); return True
    if data == "adm_export_users_csv":       action_adm_export_users_csv(call); return True
    if data == "adm_export_bots_csv":        action_adm_export_bots_csv(call); return True
    if data == "adm_export_trans_csv":       action_adm_export_trans_csv(call); return True
    if data == "adm_export_audit_csv":       action_adm_export_audit_csv(call); return True
    if data == "adm_referral_detail":        render_adm_referral_detail(call); return True
    if data == "adm_sub_expiry_report":      render_adm_sub_expiry_report(call); return True
    if data == "adm_lang_stats":             render_adm_lang_stats(call); return True
    if data == "adm_sched_history":          render_adm_scheduler_history(call); return True
    if data == "adm_export_menu":            render_adm_export_menu(call); return True
    return False


# ─── Extra Background Threads ───────────────────────────────────────────────

def _start_extra_background_threads():
    threading.Thread(target=_notif_runner,        daemon=True, name="notif-flush").start()
    threading.Thread(target=_rate_cleanup_loop,   daemon=True, name="rate-cleanup").start()
    threading.Thread(target=_sub_reminder_loop,   daemon=True, name="sub-reminder").start()
    threading.Thread(target=_metrics_persist_loop,daemon=True, name="metrics-persist").start()


# ─── Constant Lookup Tables ─────────────────────────────────────────────────

_STATUS_EMOJIS = {
    "running":"🟢","stopped":"🔴","crashed":"💥",
    "starting":"🟡","stopping":"🟠","idle":"⚪",
}
_RISK_EMOJIS = {"low":"🟢","medium":"🟡","high":"🔴","critical":"💀"}
_PAYMENT_STATUS_EMOJIS = {"pending":"⏳","approved":"✅","rejected":"❌","refunded":"↩️"}
_PLAN_DISPLAY_NAMES  = {"free":"🆓 Free","basic":"🥈 Basic","pro":"🥇 Pro","ultra":"💎 Ultra"}
_PLAN_ORDER          = ["free","basic","pro","ultra"]
_CURRENCY_SYMBOLS = {
    "USD":"$","EUR":"€","GBP":"£","INR":"₹","JPY":"¥","CNY":"¥","RUB":"₽","TRY":"₺",
    "KRW":"₩","BRL":"R$","AUD":"A$","CAD":"C$","CHF":"CHF","SGD":"S$","HKD":"HK$",
    "MXN":"MX$","AED":"د.إ","SAR":"﷼","ZAR":"R","THB":"฿","IDR":"Rp","MYR":"RM",
    "PHP":"₱","VND":"₫","PKR":"₨","BDT":"৳","EGP":"£","NGN":"₦","KES":"Ksh",
}
_CRYPTO_SYMBOLS = {
    "BTC":"₿","ETH":"Ξ","USDT":"₮","BNB":"B","SOL":"◎","ADA":"₳",
    "XRP":"✕","DOT":"●","DOGE":"Ð","MATIC":"⬡","AVAX":"A","LTC":"Ł","TRX":"T",
}
_ERROR_MESSAGES = {
    "not_registered":   "Please /start first to register.",
    "banned":           "You have been banned.",
    "admin_only":       "Admins only.",
    "owner_only":       "Owner only.",
    "bot_not_found":    "Bot not found.",
    "plan_limit_bots":  "Bot limit reached. Upgrade your plan.",
    "plan_limit_upload":"File exceeds upload limit.",
    "invalid_token":    "Invalid bot token format.",
    "invalid_url":      "Invalid URL.",
    "invalid_coupon":   "Invalid or expired coupon.",
    "upload_failed":    "Upload failed. Try again.",
    "rate_limited":     "You're going too fast. Slow down!",
    "2fa_required":     "Admin 2FA required.",
    "session_expired":  "Session expired. Start again.",
    "db_error":         "Database error. Try again.",
    "network_error":    "Network error. Try again.",
    "timeout":          "Operation timed out.",
    "permission_denied":"Permission denied.",
    "not_implemented":  "Feature not yet available.",
}
_SUCCESS_MESSAGES = {
    "bot_started":    "Bot started successfully!",
    "bot_stopped":    "Bot stopped successfully!",
    "bot_restarted":  "Bot restarted successfully!",
    "bot_deleted":    "Bot deleted.",
    "upload_ok":      "File uploaded successfully!",
    "plan_upgraded":  "Plan upgraded!",
    "env_saved":      "Environment variables saved!",
    "coupon_ok":      "Coupon applied!",
    "settings_saved": "Settings saved!",
    "backup_done":    "Backup completed!",
    "restore_done":   "Restore completed!",
    "ban_applied":    "User banned.",
    "ban_lifted":     "User unbanned.",
    "broadcast_queued":"Broadcast queued!",
    "task_added":     "Scheduled task added!",
    "task_removed":   "Task removed.",
    "2fa_verified":   "2FA verified! Access granted.",
    "export_ready":   "Export ready.",
}



# COMPLETION BLOCK — HANDLERS, NEW FEATURES, MAIN


# ─── Telegram Channel Backup ──────────────────────────────────────────────────

def _tg_channel_backup_enabled() -> bool:
    ch = get_setting("tg_backup_channel", None)
    return bool(ch)

def _tg_backup_channel() -> Optional[str]:
    return get_setting("tg_backup_channel", None)

def tg_channel_backup_now() -> Dict[str, Any]:
    """Zip the entire DB + settings + bot_data and send to a Telegram channel."""
    ch = _tg_backup_channel()
    if not ch:
        return {"ok": False, "error": "tg_backup_channel not configured"}
    try:
        out_dir = BASE_DIR / "exports"
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        target = out_dir / f"tg_backup_{stamp}.zip"
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
            for name in ("user_data.json", "settings.json", "audit.log", "github_config.json"):
                p = BASE_DIR / "storage" / name
                if p.exists():
                    zf.write(p, arcname=name)
            bot_data = BASE_DIR / "storage" / "bot_data"
            if bot_data.exists():
                for f in bot_data.iterdir():
                    if f.is_file():
                        zf.write(f, arcname=f"bot_data/{f.name}")
            photos_dir = DIRS.get("photos")
            if photos_dir and photos_dir.exists():
                for f in photos_dir.iterdir():
                    if f.is_file() and f.name.startswith("custom_"):
                        zf.write(f, arcname=f"photos/{f.name}")
        sz = target.stat().st_size
        with target.open("rb") as fh:
            bot.send_document(
                ch, fh,
                caption=(
                    f"<b>\U0001f4be {sc('Telegram Channel Backup')}</b>\n"
                    f"{bullet('Time', stamp)}\n"
                    f"{bullet('Size', fmt_bytes(sz))}\n"
                    f"{bullet('Brand', BRAND_TAG)}"
                ),
                parse_mode="HTML",
                visible_file_name=f"simran_backup_{stamp}.zip",
            )
        target.unlink(missing_ok=True)
        audit(0, "tg_channel_backup", f"channel={ch} size={sz}")
        return {"ok": True, "size": sz, "channel": ch}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def tg_channel_restore_latest() -> Dict[str, Any]:
    """Fetch the most recent backup zip from the configured Telegram channel."""
    ch = _tg_backup_channel()
    if not ch:
        return {"ok": False, "error": "tg_backup_channel not configured"}
    return {"ok": False, "error": "Use /getUpdates or export from Telegram to restore manually."}


def render_adm_tg_channel_backup(call: types.CallbackQuery) -> None:
    if not is_owner(call.from_user.id):
        ack(call, "Owner only"); return
    ch = _tg_backup_channel() or "\u2014"
    auto_on = bool(get_setting("tg_backup_auto", False))
    auto_interval = int(get_setting("tg_backup_interval_h", 6))
    cap = (
        f"<b>\U0001f4e1 {sc('Telegram Channel Backup')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Backup Channel', ch)}\n"
        f"{bullet('Auto Backup', 'ON' if auto_on else 'OFF')}\n"
        f"{bullet('Interval', f'{auto_interval}h')}\n"
        f"{G['div']}\n"
        f"{sc('Set a channel, add bot as admin, then enable backup.')}.\n"
        f"{sc('Bot will zip all data and send to the channel')}.{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("\U0001f4e1  S\u1d07\u1d1b C\u029c\u0251\u0274\u0274\u1d07\u029f", callback_data="adm_tg_bkp_set_ch", style="primary"),
        Btn("\U0001f4be  B\u1d00\u1d04\u1d0b\u1d1c\u1d18 N\u1d0f\u1d21", callback_data="adm_tg_bkp_now", style="success"),
    )
    kb.add(
        Btn(f"{'OK' if auto_on else 'OFF'}  A\u1d1c\u1d1b\u1d0f", callback_data="adm_tg_bkp_toggle_auto",
            style="success" if auto_on else "danger"),
        Btn("\U0001f4e5  R\u1d07\u02e2\u1d1b\u1d0f\u0280\u1d07", callback_data="adm_tg_bkp_restore", style="danger"),
    )
    kb.add(Btn(f"{G['back']}  A\u1d05\u1d0d\u026a\u0274", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


# ─── GitHub Repo Hosting for Users ──────────────────────────────────────────

def _user_can_host_gh(u: Dict[str, Any]) -> bool:
    plan = u.get("plan", "free")
    return plan not in ("free",)


def render_gh_repo_host_menu(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    d = db_load()
    u = d["users"].get(str(uid), {})
    if not _user_can_host_gh(u):
        ack(call, "Pro/Ultra plan required for GitHub hosting")
        show_text(
            call.message.chat.id,
            f"<b>{G['no']} {sc('GitHub Repo Hosting — Pro+ Only')}</b>\n"
            f"{G['div']}\n"
            f"{sc('Upgrade to Pro or Ultra to host bots from GitHub repos')}.\n"
            f"{G['div']}{FOOTER}",
            back_main_kb(), call=call,
        )
        return
    cap = (
        f"<b>\U0001f419 {sc('Host from GitHub Repo')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Clone a GitHub repository and run it as a bot')}.\n"
        f"{sc('Supports public and private repos (with token)')}.\n"
        f"{G['div']}\n"
        f"<b>{sc('Steps')}:</b>\n"
        f"1. {sc('Set your GitHub token (for private repos)')}\n"
        f"2. {sc('Tap Clone Repo and paste the URL')}\n"
        f"3. {sc('Bot auto-detects entry file and runs')}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("\U0001f419  C\u029f\u1d0f\u0274\u1d07 R\u1d07\u1d18\u1d0f", callback_data="gh_host_clone", style="primary"),
        Btn("\U0001f511  P\u0280\u026a\u1d20\u1d00\u1d1b\u1d07 T\u1d0f\u1d0b\u1d07\u0274", callback_data="gh_host_set_token", style="primary"),
    )
    kb.add(
        Btn("\U0001f4c2  M\u028f G\u029c B\u1d0f\u1d1b\u02e2", callback_data="gh_host_list", style="primary"),
        Btn("\U0001f5d1\ufe0f  R\u1d07\u1d0d\u1d0f\u1d20\u1d07 R\u1d07\u1d18\u1d0f", callback_data="gh_host_remove_sel", style="danger"),
    )
    kb.add(Btn(f"{G['back']}  M\u1d00\u026a\u0274", callback_data="menu_main", style="primary"))
    show_menu(call.message.chat.id, PHOTOS.get("upload", PHOTOS["main"]), cap, kb, call=call)


def _clone_gh_repo(repo_url: str, token: Optional[str], dest_dir: Path) -> Dict[str, Any]:
    """Clone a GitHub repo. Uses token for private repos."""
    import subprocess as _sp
    dest_dir.mkdir(parents=True, exist_ok=True)
    if token:
        url = repo_url.replace("https://", f"https://{token}@")
    else:
        url = repo_url
    try:
        result = _sp.run(
            ["git", "clone", "--depth=1", url, str(dest_dir)],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            return {"ok": False, "error": (result.stderr or result.stdout)[:500]}
        return {"ok": True}
    except FileNotFoundError:
        return {"ok": False, "error": "git not installed on server."}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def action_gh_host_clone(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    u = db_load()["users"].get(str(uid), {})
    if not _user_can_host_gh(u):
        ack(call, "Pro+ only"); return
    USER_STATES[uid] = {"flow": "await_gh_repo_url"}
    bot.send_message(
        call.message.chat.id,
        f"<b>\U0001f419 {sc('Clone GitHub Repo')}</b>\n{G['div']}\n"
        f"{sc('Send the full repo URL')}:\n"
        f"<code>https://github.com/user/repo</code>\n\n"
        f"{sc('For private repos, set your token first via')} Private Token.\n"
        f"{sc('Use')} /cancel {sc('to abort')}.",
        parse_mode="HTML",
    )
    ack(call)


def action_gh_host_set_token(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    USER_STATES[uid] = {"flow": "await_gh_user_token"}
    bot.send_message(
        call.message.chat.id,
        f"<b>\U0001f511 {sc('Set GitHub Personal Access Token')}</b>\n{G['div']}\n"
        f"{sc('Token is encrypted and only used for cloning your repos')}.\n"
        f"{sc('Send token now or /cancel')}.",
        parse_mode="HTML",
    )
    ack(call)


def action_gh_host_list(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    bots = list_user_bots(uid)
    gh_bots = [b for b in bots if b.get("source") in ("github", "github_browser")]
    if not gh_bots:
        show_text(
            call.message.chat.id,
            f"<b>\U0001f4c2 {sc('GitHub-hosted Bots')}</b>\n{G['div']}\n"
            f"<i>{sc('No GitHub-hosted bots yet')}.</i>{FOOTER}",
            _adm_back("menu_gh_host"), call=call,
        )
        ack(call); return
    rows = "\n".join(
        f"{G['bullet']} <b>{esc(b['name'])}</b> \u2014 "
        f"<code>{esc((b.get('gh_repo','?'))[:40])}</code>"
        for b in gh_bots
    )
    cap = (
        f"<b>\U0001f419 {sc('Your GitHub-hosted Bots')}</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup()
    for b in gh_bots:
        kb.add(Btn(f"\U0001f419  {esc(b['name'])[:30]}", callback_data=f"bot_view_{b['_id']}"))
    kb.add(Btn(f"{G['back']}  Main", callback_data="menu_main"))
    show_text(call.message.chat.id, cap, kb, call=call)
    ack(call)


# ─── GitHub File Browser ─────────────────────────────────────────────────────

def render_adm_gh_browser(call: types.CallbackQuery) -> None:
    if not admin_only_call(call, "view_stats"):
        return
    if not gh_enabled():
        show_text(
            call.message.chat.id,
            f"<b>\U0001f419 {sc('GitHub File Browser')}</b>\n{G['div']}\n"
            f"<i>{sc('GitHub backup not configured')}.</i>{FOOTER}",
            _adm_back("menu_admin"), call=call,
        )
        return
    _render_gh_dir(call, path="")


def _render_gh_dir(call: types.CallbackQuery, path: str = "") -> None:
    ack(call, "Browsing\u2026")
    def _bg() -> None:
        try:
            url = _gh_repo_url(f"contents/{path}") if path else _gh_repo_url("contents")
            r = _gh("GET", url, params={"ref": GH["branch"]})
            items = r.json() if r.status_code == 200 else []
            if not isinstance(items, list):
                items = [items]
            dirs  = sorted([x for x in items if x.get("type") == "dir"],  key=lambda x: x.get("name","").lower())
            files = sorted([x for x in items if x.get("type") == "file"], key=lambda x: x.get("name","").lower())
            path_display = f"/{path}" if path else "/ (root)"
            cap = (
                f"<b>\U0001f419 {sc('GitHub Browser')}</b>\n"
                f"{G['div_eq']}\n"
                f"{bullet('Repo',   GH.get('repo','?'))}\n"
                f"{bullet('Branch', GH.get('branch','main'))}\n"
                f"{bullet('Path',   esc(path_display))}\n"
                f"{bullet('Dirs',   len(dirs))}\n"
                f"{bullet('Files',  len(files))}\n"
                f"{G['div']}{FOOTER}"
            )
            kb = types.InlineKeyboardMarkup(row_width=1)
            if path:
                parent = "/".join(path.rstrip("/").split("/")[:-1])
                kb.add(Btn("\u2b06\ufe0f  .. (up)", callback_data=f"ghbrow_dir_{parent}"))
            for d in dirs[:15]:
                kb.add(Btn(f"\U0001f4c1  {esc(d['name'])}", callback_data=f"ghbrow_dir_{d['path']}"))
            for f in files[:20]:
                sz = fmt_bytes(f.get("size", 0))
                kb.add(Btn(f"\U0001f4c4  {esc(f['name'])} ({sz})", callback_data=f"ghbrow_file_{f['path']}"))
            kb.add(Btn(f"{G['back']}  Admin", callback_data="menu_admin"))
            show_text(call.message.chat.id, cap, kb)
        except Exception as e:
            try:
                bot.send_message(call.from_user.id,
                    f"<b>{G['no']} Browser Error</b>\n<code>{esc(e)}</code>", parse_mode="HTML")
            except Exception:
                pass
    threading.Thread(target=_bg, daemon=True).start()


def _render_gh_file(call: types.CallbackQuery, path: str) -> None:
    ack(call, "Loading file\u2026")
    def _bg() -> None:
        try:
            r = _gh("GET", _gh_repo_url(f"contents/{path}"), params={"ref": GH["branch"]})
            if r.status_code != 200:
                bot.send_message(call.from_user.id, f"{G['no']} HTTP {r.status_code}"); return
            payload = r.json()
            content_b64 = payload.get("content", "")
            raw = base64.b64decode(content_b64.replace("\n", ""))
            try:
                text = raw.decode("utf-8")
                is_text = True
            except Exception:
                text = ""
                is_text = False
            fname = payload.get("name", path.split("/")[-1])
            sz = fmt_bytes(payload.get("size", len(raw)))
            cap = (
                f"<b>\U0001f4c4 {esc(fname)}</b>\n"
                f"{G['div_eq']}\n"
                f"{bullet('Path', esc(path))}\n"
                f"{bullet('Size', sz)}\n{G['div']}\n"
            )
            if is_text and len(text) <= 3000:
                cap += f"<pre>{esc(text[:2800])}</pre>"
            elif is_text:
                cap += f"<pre>{esc(text[:1500])}\u2026</pre>"
            else:
                cap += "<i>Binary file</i>"
            cap += FOOTER
            parent = "/".join(path.rstrip("/").split("/")[:-1])
            kb = types.InlineKeyboardMarkup(row_width=2)
            kb.add(
                Btn("\U0001f4e5  Download", callback_data=f"ghbrow_dl_{path}"),
                Btn("\u2b06\ufe0f  Back up",  callback_data=f"ghbrow_dir_{parent}"),
            )
            if fname.endswith((".py", ".js", ".mjs")):
                kb.add(Btn("\u25b6\ufe0f  Run this file", callback_data=f"ghbrow_run_{path}"))
            kb.add(Btn(f"{G['back']}  Admin", callback_data="menu_admin"))
            show_text(call.message.chat.id, cap, kb)
        except Exception as e:
            try:
                bot.send_message(call.from_user.id,
                    f"<b>{G['no']} File load error</b>\n<code>{esc(e)}</code>", parse_mode="HTML")
            except Exception:
                pass
    threading.Thread(target=_bg, daemon=True).start()


def _action_gh_file_download(call: types.CallbackQuery, path: str) -> None:
    ack(call, "Downloading\u2026")
    def _bg() -> None:
        try:
            r = _gh("GET", _gh_repo_url(f"contents/{path}"), params={"ref": GH["branch"]})
            if r.status_code != 200:
                bot.send_message(call.from_user.id, f"{G['no']} HTTP {r.status_code}"); return
            payload = r.json()
            raw = base64.b64decode(payload.get("content", "").replace("\n", ""))
            fname = payload.get("name", path.split("/")[-1])
            tmp = Path(tempfile.mktemp(suffix=f"_{fname}"))
            tmp.write_bytes(raw)
            with tmp.open("rb") as fh:
                bot.send_document(call.from_user.id, fh,
                    caption=f"<b>\U0001f4c4 {esc(fname)}</b> ({fmt_bytes(len(raw))})",
                    parse_mode="HTML", visible_file_name=fname)
            tmp.unlink(missing_ok=True)
            audit(call.from_user.id, "gh_browser_download", f"path={path}")
        except Exception as e:
            try:
                bot.send_message(call.from_user.id,
                    f"<b>{G['no']} Download error</b>\n<code>{esc(e)}</code>", parse_mode="HTML")
            except Exception:
                pass
    threading.Thread(target=_bg, daemon=True).start()


def _action_gh_file_run(call: types.CallbackQuery, path: str) -> None:
    """Download .py/.js from GitHub and run it as a new bot."""
    if not is_owner(call.from_user.id):
        ack(call, "Owner only"); return
    ack(call, "Running from GitHub\u2026")
    def _bg() -> None:
        try:
            r = _gh("GET", _gh_repo_url(f"contents/{path}"), params={"ref": GH["branch"]})
            if r.status_code != 200:
                bot.send_message(call.from_user.id, f"{G['no']} HTTP {r.status_code}"); return
            payload = r.json()
            raw = base64.b64decode(payload.get("content", "").replace("\n", ""))
            fname = payload.get("name", path.split("/")[-1])
            uid = call.from_user.id
            bot_id = secrets.token_hex(8)
            bot_dir = DIRS["sandbox"] / f"{uid}_{bot_id}"
            bot_dir.mkdir(parents=True, exist_ok=True)
            (bot_dir / fname).write_bytes(raw)
            name = safe_name(Path(fname).stem) + "_gh"
            doc = {
                "_id": bot_id, "owner": uid, "name": name,
                "dir": str(bot_dir), "created": ts_iso(),
                "enc_files": {}, "env": {}, "status": "stopped", "cron": {},
                "source": "github_browser", "gh_path": path, "entry": fname,
            }
            d = db_load()
            d["bots"][bot_id] = doc
            db_save(d)
            audit(uid, "gh_browser_run", f"path={path} bot_id={bot_id}")
            res = start_child(doc)
            bot.send_message(uid,
                f"<b>{'OK' if res.get('ok') else G['no']} \U0001f419 Run</b>\n"
                f"{bullet('File', fname)}\n"
                f"{bullet('Bot ID', bot_id)}\n"
                f"{bullet('Status', 'Started' if res.get('ok') else 'Error: ' + str(res.get('error', '')))}\n"
                f"{sc('Find it in My Bots')}.{FOOTER}", parse_mode="HTML")
        except Exception as e:
            try:
                bot.send_message(call.from_user.id,
                    f"<b>{G['no']} Run error</b>\n<code>{esc(e)}</code>", parse_mode="HTML")
            except Exception:
                pass
    threading.Thread(target=_bg, daemon=True).start()


# ─── Approval Group Settings ─────────────────────────────────────────────────

def render_adm_approval_group(call: types.CallbackQuery) -> None:
    if not is_owner(call.from_user.id):
        ack(call, "Owner only"); return
    grp_on = bool(get_setting("group_verify_enabled", False))
    groups = list(get_setting("required_groups", []) or [])
    rows = "\n".join(
        f"{G['bullet']} {esc(g.get('name','?'))} \u2014 "
        f"<code>{g.get('id','')}</code> "
        f"<a href='{g.get('link','#')}'>{sc('link')}</a>"
        for g in groups
    ) or f"<i>{sc('No groups configured')}</i>"
    cap = (
        f"<b>\U0001f510 {sc('Approval Group Verification')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Status', 'ENABLED' if grp_on else 'DISABLED')}\n"
        f"{bullet('Groups', len(groups))}\n"
        f"{G['div']}\n"
        f"<b>{sc('Configured Groups')}:</b>\n{rows}\n"
        f"{G['div']}\n"
        f"{sc('Users must join all configured groups before accessing the bot')}.{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn(f"{'OK' if grp_on else 'OFF'}  Verify", callback_data="adm_grpv_toggle",
            style="success" if grp_on else "danger"),
        Btn("+ Add Group", callback_data="adm_grpv_add", style="primary"),
    )
    kb.add(
        Btn("- Remove Group", callback_data="adm_grpv_remove", style="danger"),
        Btn("List Groups",    callback_data="adm_grpv_list",   style="primary"),
    )
    kb.add(
        Btn("Stats",          callback_data="adm_grpv_stats",  style="primary"),
        Btn(f"{G['back']}  Admin", callback_data="menu_admin", style="primary"),
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


def render_adm_grpv_stats(call: types.CallbackQuery) -> None:
    if not is_admin(call.from_user.id):
        ack(call, "Admin only"); return
    d = db_load()
    verified = sum(1 for u in d["users"].values() if u.get("verified"))
    total = len(d["users"])
    cap = (
        f"<b>\U0001f4ca {sc('Group Verification Stats')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Total Users', total)}\n"
        f"{bullet('Verified', verified)}\n"
        f"{bullet('Unverified', total - verified)}\n"
        f"{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, _adm_back("menu_admin"), call=call)


def render_adm_private_group_panel(call: types.CallbackQuery) -> None:
    if not is_owner(call.from_user.id):
        ack(call, "Owner only"); return
    pg = get_setting("private_approval_group", None)
    notify_admins_only = bool(get_setting("approval_notify_admins", True))
    cap = (
        f"<b>\U0001f512 {sc('Private Approval Group Settings')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Approval Group', pg or '— not set —')}\n"
        f"{bullet('Notify Admins Only', 'YES' if notify_admins_only else 'NO')}\n"
        f"{G['div']}\n"
        f"{sc('Bot uploads are forwarded to this group for admin approval')}.{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("Set Group",    callback_data="adm_apgrp_set",    style="primary"),
        Btn("Clear",        callback_data="adm_apgrp_clear",  style="danger"),
    )
    kb.add(
        Btn(f"Notify: {'Admins' if notify_admins_only else 'All'}", callback_data="adm_apgrp_toggle_notify", style="primary"),
        Btn("Test",         callback_data="adm_apgrp_test",   style="success"),
    )
    kb.add(Btn(f"{G['back']}  Admin", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


# ─── Verification State (deferred declarations) ───────────────────────────────

VERIFY_STATES: Dict[int, Dict[str, Any]] = {}
_verify_lock = threading.Lock()
_CAPTCHA_POOL = "ABCDEFGHJKLMNPRSTUVWXYZ23456789"
_CAPTCHA_FONT_PATHS = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
)
REQUIRED_GROUPS: List[Dict[str, Any]] = []


def _load_required_groups() -> None:
    global REQUIRED_GROUPS
    REQUIRED_GROUPS = list(get_setting("required_groups", []) or [])


def _captcha_font(size: int):
    if not _PIL_OK:
        return None
    for fp in _CAPTCHA_FONT_PATHS:
        try:
            if os.path.exists(fp):
                return ImageFont.truetype(fp, size)
        except Exception:
            continue
    try:
        return ImageFont.load_default()
    except Exception:
        return None


def _gen_captcha_image() -> Tuple[Optional[bytes], str, List[str]]:
    text = "".join(random.choice(_CAPTCHA_POOL) for _ in range(4))
    correct_idx = random.randrange(4)
    correct_ch = text[correct_idx]
    options = list(set(text))
    while len(options) < 6:
        c = random.choice(_CAPTCHA_POOL)
        if c not in options:
            options.append(c)
    random.shuffle(options)
    if not _PIL_OK:
        return None, correct_ch, options
    W, H = 720, 320
    bg = (15, 23, 42)
    img = Image.new("RGB", (W, H), bg)
    draw = ImageDraw.Draw(img)
    for _ in range(10):
        x1, y1 = random.randint(-50, W), random.randint(-50, H)
        x2, y2 = x1 + random.randint(150, 400), y1 + random.randint(-80, 80)
        draw.line([(x1, y1), (x2, y2)], fill=(40, 50, 70), width=random.randint(2, 4))
    for _ in range(450):
        x, y = random.randint(0, W - 1), random.randint(0, H - 1)
        v = random.randint(80, 200)
        draw.point((x, y), fill=(v, v, v))
    font = _captcha_font(140)
    char_centers: List[Tuple[int, int]] = []
    slot_w = W // 4
    palette = [(250, 204, 21), (96, 165, 250), (236, 72, 153), (52, 211, 153), (244, 114, 182), (251, 146, 60)]
    for i, ch in enumerate(text):
        tile = Image.new("RGBA", (200, 240), (0, 0, 0, 0))
        td = ImageDraw.Draw(tile)
        col = random.choice(palette)
        try:
            td.text((30, 30), ch, font=font, fill=col + (255,))
        except Exception:
            td.text((30, 30), ch, fill=col + (255,))
        tile = tile.rotate(random.randint(-22, 22), resample=Image.BILINEAR)
        cx = slot_w * i + slot_w // 2 - 100 + random.randint(-10, 10)
        cy = (H - 240) // 2 + random.randint(-15, 15)
        img.paste(tile, (cx, cy), tile)
        char_centers.append((cx + 100, cy + 120))
    cx, cy = char_centers[correct_idx]
    r = 90
    for dr in range(5):
        draw.ellipse([cx - r - dr, cy - r - dr, cx + r + dr, cy + r + dr], outline=(239, 68, 68))
    hint_font = _captcha_font(28)
    hint = "tap the circled character"
    try:
        bbox = draw.textbbox((0, 0), hint, font=hint_font)
        tw = bbox[2] - bbox[0]
    except Exception:
        tw = len(hint) * 10
    draw.rectangle([0, H - 44, W, H], fill=(30, 41, 59))
    try:
        draw.text(((W - tw) // 2, H - 38), hint, font=hint_font, fill=(226, 232, 240))
    except Exception:
        pass
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue(), correct_ch, options


def _progress_bar_text(pct: int) -> str:
    pct = max(0, min(100, pct))
    filled = pct // 10
    bar = "\u25b0" * filled + "\u25b1" * (10 - filled)
    return (
        f"<b>{G['shield']} {sc('Verifying you')}\u2026</b>\n"
        f"{G['div']}\n"
        f"<b><code>[{bar}] {pct:3d}%</code></b>"
    )


def _send_captcha(chat_id: int, uid: int) -> None:
    png, correct, opts = _gen_captcha_image()
    kb = types.InlineKeyboardMarkup()
    btns = [Btn(c, callback_data=f"verify_{c}") for c in opts]
    for i in range(0, len(btns), 3):
        kb.row(*btns[i:i + 3])
    kb.row(Btn(f"\u21bb {sc('New captcha')}", callback_data="verify_new"))
    cap = (
        f"<b>{G['shield']} {sc('Human verification')}</b>\n"
        f"{G['div']}\n"
        f"{sc('One character has a red circle around it')}.\n"
        f"<b>{sc('Tap that exact character below')}.</b>{FOOTER}"
    )
    sent_id: Optional[int] = None
    try:
        if png is not None:
            m2 = bot.send_photo(chat_id, png, caption=cap, parse_mode="HTML", reply_markup=kb)
            sent_id = m2.message_id
        else:
            m2 = bot.send_message(chat_id,
                f"<b>{G['shield']}</b> Tap: <b><code>{esc(correct)}</code></b>",
                parse_mode="HTML", reply_markup=kb)
            sent_id = m2.message_id
    except Exception as e:
        print(f"[verify] send failed: {e}", flush=True)
        return
    with _verify_lock:
        prev = VERIFY_STATES.get(uid) or {}
        VERIFY_STATES[uid] = {
            "answer": correct, "options": opts, "msg_id": sent_id,
            "chat_id": chat_id, "tries": 0, "regens": int(prev.get("regens", 0)), "ts": time.time(),
        }


def _send_progress_then_captcha(chat_id: int, uid: int) -> None:
    msg_id: Optional[int] = None
    try:
        m2 = bot.send_message(chat_id, _progress_bar_text(10), parse_mode="HTML")
        msg_id = m2.message_id
    except Exception:
        pass
    for pct in (25, 45, 65, 85, 100):
        time.sleep(0.45)
        if msg_id is None:
            break
        try:
            bot.edit_message_text(_progress_bar_text(pct), chat_id, msg_id, parse_mode="HTML")
        except Exception:
            pass
    if msg_id is not None:
        try:
            bot.edit_message_text(
                f"<b>{G['shield']} {sc('Loading complete')}\u2026 {sc('solve captcha below')} \u2193</b>",
                chat_id, msg_id, parse_mode="HTML")
        except Exception:
            pass
    _send_captcha(chat_id, uid)


def _verify_state_janitor() -> None:
    while True:
        try:
            time.sleep(120)
            cutoff = time.time() - 600
            with _verify_lock:
                stale = [u for u, s in VERIFY_STATES.items() if s.get("ts", 0) < cutoff]
                for u in stale:
                    VERIFY_STATES.pop(u, None)
        except Exception as e:
            print(f"[verify] janitor error: {e}", flush=True)


def _check_group_membership(uid: int) -> List[Dict[str, Any]]:
    if not REQUIRED_GROUPS:
        return []
    not_joined = []
    for grp in REQUIRED_GROUPS:
        try:
            member = bot.get_chat_member(grp["id"], uid)
            if member.status in ("left", "kicked", "banned"):
                not_joined.append(grp)
        except Exception:
            not_joined.append(grp)
    return not_joined


def _send_join_verification(chat_id: int, uid: int, not_joined: List[Dict[str, Any]]) -> None:
    kb = types.InlineKeyboardMarkup(row_width=2)
    for grp in not_joined:
        kb.add(Btn(f"Join {grp['name']}", url=grp["link"]))
    kb.add(Btn("Verify Membership", callback_data="group_verify_check"))
    cap = (
        f"<b>{G['shield']} {sc('Group Join Required')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Join all groups below to use this bot')}:\n{G['div']}\n"
        + "\n".join(f"- <a href='{g['link']}'>{esc(g['name'])}</a>" for g in not_joined)
        + f"\n{G['div']}\n{sc('After joining, tap Verify Membership')}.{FOOTER}"
    )
    try:
        bot.send_message(chat_id, cap, parse_mode="HTML", reply_markup=kb,
                         disable_web_page_preview=True)
    except Exception as e:
        print(f"[group_verify] send failed: {e}", flush=True)


def _is_private(m) -> bool:
    try:
        return m.chat.type == "private"
    except Exception:
        return True


def _is_verified(uid: int) -> bool:
    if uid == OWNER_ID and OWNER_ID > 0:
        return True
    u = db_load_ro()["users"].get(str(uid)) or {}
    return bool(u.get("verified"))


def _mark_verified(uid: int) -> None:
    db = db_load()
    if str(uid) in db["users"]:
        db["users"][str(uid)]["verified"] = True
        db["users"][str(uid)]["verified_at"] = ts_iso()
        db_save(db)


def require_verified(chat_id: int, uid: int) -> bool:
    if _is_verified(uid):
        return True
    with _verify_lock:
        st = VERIFY_STATES.get(uid)
        now = time.time()
        if st and (st.get("msg_id") or now - st.get("ts", 0) < 6):
            return False
        VERIFY_STATES[uid] = {
            "answer": "", "options": [], "msg_id": None,
            "chat_id": chat_id, "tries": 0, "regens": 0, "ts": now, "starting": True,
        }
    threading.Thread(target=_send_progress_then_captcha, args=(chat_id, uid), daemon=True).start()
    return False


def require_group_membership(chat_id: int, uid: int) -> bool:
    if uid == OWNER_ID and OWNER_ID > 0:
        return True
    if is_admin(uid):
        return True
    if not bool(get_setting("group_verify_enabled", False)):
        return True
    not_joined = _check_group_membership(uid)
    if not not_joined:
        return True
    _send_join_verification(chat_id, uid, not_joined)
    return False


# ─── Main Menu ────────────────────────────────────────────────────────────────

def render_main_menu(chat_id: int, uid: int,
                     call: Optional[types.CallbackQuery] = None,
                     intro: Optional[str] = None) -> None:
    u = db_load()["users"].get(str(uid)) or {}
    plan = PLAN_LIMITS.get(u.get("plan", "free"), PLAN_LIMITS["free"])
    bots = list_user_bots(uid)
    running = sum(1 for b in bots if b.get("status") == "running")
    intro_block = f"{intro}\n{G['div']}\n" if intro else ""
    custom_welcome = get_setting("custom_welcome", None)
    welcome_line = esc(custom_welcome) if custom_welcome else f"{sc('Welcome')}, <b>{esc(u.get('name') or 'friend')}</b>"
    cap = (
        f"<b>{esc(BRAND_TAG)}</b>\n"
        f"{G['div_eq']}\n"
        f"{intro_block}"
        f"{welcome_line}\n"
        f"{bullet('Plan', plan['name'])}\n"
        f"{bullet('Until', fmt_ts(u.get('plan_expires')) if u.get('plan_expires') else 'Forever' if plan['price'] == 0 else '—')}\n"
        f"{bullet('Bots', str(len(bots)) + ' / ' + str(user_max_bots(u)) + '  (running ' + str(running) + ')')}\n"
        f"{bullet('Wallet', '{}$'.format(u.get('wallet', 0)))}\n"
        f"{G['div']}\nChoose an option below.{FOOTER}"
    )
    show_start_menu(chat_id, cap, main_menu_kb(is_admin(uid)), call=call,
                    photo_fallback=PHOTOS.get("main", ""))


# ─── Render functions used by router ─────────────────────────────────────────

def render_bots_menu(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    bots = list_user_bots(uid)
    u = db_load()["users"][str(uid)]
    cap = (
        f"<b>{G['diamond']} {sc('Your Bots')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Slots', str(len(bots)) + ' / ' + str(user_max_bots(u)))}\n"
    )
    kb = types.InlineKeyboardMarkup()
    if not bots:
        cap += f"\n{sc('No bots yet. Tap Upload to begin')}."
    else:
        for b in sorted(bots, key=lambda x: x.get("name", "")):
            running = b.get("status") == "running"
            mark = G["play"] if running else G["stop"]
            src_mark = " \U0001f419" if b.get("source") in ("github", "github_browser") else ""
            kb.add(Btn(f"{mark}  {sc(b['name'])[:30]}{src_mark}",
                       callback_data=f"bot_view_{b['_id']}"))
    kb.add(
        Btn(f"{G['plus']}  {sc('Upload')}", callback_data="menu_upload", style="success"),
        Btn("\U0001f419  From GitHub",      callback_data="menu_gh_host", style="primary"),
    )
    kb.add(Btn(f"{G['back']}  {sc('Main Menu')}", callback_data="menu_main", style="primary"))
    show_menu(call.message.chat.id, PHOTOS["bots"], cap + FOOTER, kb, call=call)


def render_upload_menu(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    u = db_load()["users"][str(uid)]
    used = len(list_user_bots(uid))
    rules = get_setting("hosting_rules", None)
    rules_block = f"\n{G['div']}\n<b>{sc('Hosting Rules')}:</b>\n{esc(rules)}" if rules else ""
    cap = (
        f"<b>{G['plus']} {sc('Upload Bot')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Plan', PLAN_LIMITS.get(u.get('plan','free'),PLAN_LIMITS['free'])['name'])}\n"
        f"{bullet('Slots', str(used) + ' / ' + str(user_max_bots(u)))}\n"
        f"{G['div']}\n"
        f"<b>{sc('Send your bot file as a document')}.</b>\n"
        f"Accepted: <code>.zip  .py  .js</code>\n"
        f"Entry detection: <code>bot.py main.py app.py index.js</code>\n"
        f"All files are <b>encrypted at rest</b>.{rules_block}"
    )
    USER_STATES[uid] = {"flow": "await_upload"}
    show_menu(call.message.chat.id, PHOTOS["upload"], cap + FOOTER, back_main_kb(), call=call)


def render_plans_menu(call: types.CallbackQuery) -> None:
    lines = []
    for key, v in PLAN_LIMITS.items():
        price_txt = "Free" if v["price"] == 0 else f"{v['price']}$"
        live_bots = int(get_setting(f"plan_max_bots_{key}", v["max_bots"]))
        detail = f"{live_bots} bots {G['bullet']} {v['ram']} MB RAM {G['bullet']} {price_txt}"
        lines.append(bullet(v["name"], detail))
    cap = (
        f"<b>{G['star']} {sc('Plans')}</b>\n"
        f"{G['div_eq']}\n"
        + "\n".join(lines)
        + f"\n{G['div']}\nTap a plan for full details.{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["plans"], cap, plans_kb(), call=call)


def render_plan_detail(call: types.CallbackQuery, plan: str) -> None:
    p = PLAN_LIMITS.get(plan)
    if not p:
        ack(call, "Unknown plan"); return
    live_bots = int(get_setting(f"plan_max_bots_{plan}", p["max_bots"]))
    cap = (
        f"<b>{G['star']} {esc(p['name'])} {sc('Plan')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Max bots', live_bots)}\n"
        f"{bullet('RAM per bot', '{} MB'.format(p['ram']))}\n"
        f"{bullet('Auto-restart', 'Yes' if p['auto_restart'] else 'No')}\n"
        f"{bullet('Duration', 'Lifetime' if plan == 'lifetime' else '{} days'.format(p['days']))}\n"
        f"{bullet('Price', 'Free' if p['price'] == 0 else '{}$'.format(p['price']))}\n"
        f"{bullet('GitHub hosting', 'Yes' if plan not in ('free',) else 'No')}\n"
        f"{G['div']}\n{sc('Tap buy to choose a payment method')}.{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup()
    if plan != "free":
        kb.add(Btn(f"{G['spark']}  {sc('Buy')} {p['name']}", callback_data=f"plan_buy_{plan}"))
    kb.add(Btn(f"{G['back']}  {sc('Plans')}", callback_data="menu_plans"))
    show_menu(call.message.chat.id, PHOTOS["buy"], cap, kb, call=call)


def render_buy_menu(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>{G['spark']} {sc('Buy a Plan')}</b>\n"
        f"{G['div_eq']}\n{sc('Pick a plan first')}.{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["buy"], cap, plans_kb(), call=call)


def render_payment_methods_for(call: types.CallbackQuery, plan: str) -> None:
    p = PLAN_LIMITS.get(plan)
    if not p:
        ack(call, "Unknown plan"); return
    cap = (
        f"<b>{G['wallet']} {sc('Choose Payment Method')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Plan', p['name'])}\n"
        f"{bullet('Price', '{}$'.format(p['price']))}\n"
        f"{G['div']}\n{sc('Pick the method you will pay with')}.{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS.get("pay", PHOTOS["wallet"]), cap, payments_kb(plan), call=call)


def render_payment_screen(call: types.CallbackQuery, data: str) -> None:
    parts = data.split("_")
    method = parts[1] if len(parts) > 1 else ""
    plan   = parts[2] if len(parts) > 2 else None
    pm = PAYMENT_METHODS.get(method)
    if not pm:
        ack(call, "Unknown method"); return
    p = PLAN_LIMITS.get(plan or "")
    cap = (
        f"<b>{pm['tag']} {esc(pm['name'])} \u2014 {sc('Payment')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Number', pm['number'])}\n"
        f"{bullet('Type', pm['type'])}\n"
    )
    if p:
        cap += f"{bullet('Plan', p['name'])}\n{bullet('Amount', '{}$'.format(p['price']))}\n"
    cap += (
        f"{G['div']}\n"
        f"<b>{sc('How to pay')}:</b>\n"
        f"1. {sc('Send the exact amount to the number above')}.\n"
        f"2. {sc('Tap Send Proof and forward your receipt screenshot')}.\n"
        f"3. {sc('Wait for admin approval (usually within 1 hour)')}.\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup()
    USER_STATES[call.from_user.id] = {"flow": "await_payment_proof", "method": method, "plan": plan}
    kb.add(Btn(f"{G['plus']}  {sc('Send Proof')}", callback_data="pay_proof"))
    kb.add(Btn(f"{G['back']}  {sc('Methods')}", callback_data=f"plan_buy_{plan}" if plan else "menu_buy"))
    show_menu(call.message.chat.id, PHOTOS.get("pay", PHOTOS["wallet"]), cap, kb, call=call)


def start_proof_flow(call: types.CallbackQuery) -> None:
    USER_STATES[call.from_user.id] = {"flow": "await_payment_proof"}
    bot.send_message(
        call.message.chat.id,
        f"{G['plus']} {sc('Send your payment screenshot or transaction id now')}. /cancel {sc('to abort')}.",
    )


def render_profile(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    u = db_load()["users"][str(uid)]
    p = PLAN_LIMITS.get(u.get("plan", "free"), PLAN_LIMITS["free"])
    bots = list_user_bots(uid)
    cap = (
        f"<b>{G['user']} {sc('Profile')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Name', u.get('name'))}\n"
        f"{bullet('Username', '@' + (u.get('username') or '—'))}\n"
        f"{bullet('User ID', uid)}\n"
        f"{bullet('Plan', p['name'])}\n"
        f"{bullet('Until', fmt_ts(u.get('plan_expires')) if u.get('plan_expires') else 'Forever' if p['price'] == 0 else '—')}\n"
        f"{bullet('Wallet', '{}$'.format(u.get('wallet', 0)))}\n"
        f"{bullet('Bots', str(len(bots)) + ' / ' + str(user_max_bots(u)))}\n"
        f"{bullet('Joined', fmt_ts(u.get('joined')))}\n"
        f"{bullet('Referrals', u.get('ref_count', 0))}\n"
        f"{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS.get("profile", PHOTOS["main"]), cap, back_main_kb(), call=call)


def render_referral(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    u = db_load()["users"][str(uid)]
    try:
        me = bot.get_me()
        link = f"https://t.me/{me.username}?start={uid}"
    except Exception:
        link = f"https://t.me/SimranRBOT?start={uid}"
    cap = (
        f"<b>{G['users']} {sc('Referral')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Your link', link)}\n"
        f"{bullet('Referrals', u.get('ref_count', 0))}\n"
        f"{bullet('Bonus slots', u.get('bot_slots_bonus', 0))}\n"
        f"{G['div']}\n"
        f"{sc('Each friend who joins via your link gives you +1 bot slot')}.\n{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS.get("referral", PHOTOS["main"]), cap, back_main_kb(), call=call)


def render_wallet(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    u = db_load()["users"][str(uid)]
    cap = (
        f"<b>{G['wallet']} {sc('Wallet')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Balance', '{}$'.format(u.get('wallet', 0)))}\n"
        f"{G['div']}\n"
        f"{sc('Top up by sending payment proof. Admin will credit your wallet')}.{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup()
    kb.add(Btn(f"{G['plus']}  {sc('Top Up')}", callback_data="wallet_topup"))
    if u.get("plan") not in ("free", None):
        kb.add(Btn(f"{G['spark']}  {sc('Gift Plan')}", callback_data="wallet_gift"))
    kb.add(Btn(f"{G['back']}  {sc('Main Menu')}", callback_data="menu_main"))
    show_menu(call.message.chat.id, PHOTOS["wallet"], cap, kb, call=call)


def render_help(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>{G['rec']} {sc('Help')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Upload', 'Send .py / .js / .zip')}\n"
        f"{bullet('GitHub', 'Host from GitHub repo (Pro+)')}\n"
        f"{bullet('Run', 'My Bots → pick → Start')}\n"
        f"{bullet('Logs', 'My Bots → pick → Live Logs')}\n"
        f"{bullet('Env', 'My Bots → pick → Env Vars')}\n"
        f"{bullet('Plans', 'Plans → Buy Plan → method')}\n"
        f"{bullet('Coupon', 'Coupon menu → Redeem')}\n"
        f"{bullet('Trial', 'One-time 48h Pro trial')}\n"
        f"{bullet('Tickets', 'Private support tickets')}\n"
        f"{G['div']}\nUpdates: {UPDATE_CH}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS.get("help", PHOTOS["main"]), cap, back_main_kb(), call=call)


def render_support(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>{G['broadcast']} {sc('Support')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('DM', SUPPORT_USR)}\n"
        f"{bullet('Channel', UPDATE_CH)}\n"
        f"{G['div']}\n"
        f"{sc('Or open a ticket from Tickets menu')}.{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS.get("support", PHOTOS["main"]), cap, back_main_kb(), call=call)


def render_trial(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    u = db_load()["users"][str(uid)]
    cap = (
        f"<b>{G['eye']} {sc('Free Trial')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Get a free 48-hour Pro trial — one time per account')}.\n"
        f"{bullet('Status', 'Already used' if u.get('trial_used') else 'Available')}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup()
    if not u.get("trial_used"):
        kb.add(Btn(f"{G['ok']}  {sc('Claim 48h Pro Trial')}", callback_data="trial_claim"))
    kb.add(Btn(f"{G['back']}  {sc('Main Menu')}", callback_data="menu_main"))
    show_menu(call.message.chat.id, PHOTOS.get("trial", PHOTOS["main"]), cap, kb, call=call)


def action_trial_claim(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    d = db_load()
    u = d["users"][str(uid)]
    if u.get("trial_used"):
        ack(call, "Already used"); return
    u["trial_used"] = True
    db_save(d)
    grant_plan(uid, "pro", days=2)
    audit(0, "trial_grant", f"uid={uid}")
    ack(call, "Trial activated!")
    render_main_menu(call.message.chat.id, uid, call)


def render_coupon(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>{G['key']} {sc('Coupon')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Have a discount code? Tap redeem and send the code')}.{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup()
    kb.add(Btn(f"{G['plus']}  {sc('Redeem Code')}", callback_data="coupon_redeem"))
    kb.add(Btn(f"{G['back']}  {sc('Main Menu')}", callback_data="menu_main"))
    show_menu(call.message.chat.id, PHOTOS.get("coupon", PHOTOS["main"]), cap, kb, call=call)


def render_user_stats(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    d = db_load()
    u = d["users"][str(uid)]
    p = PLAN_LIMITS.get(u.get("plan", "free"), PLAN_LIMITS["free"])
    bots = list_user_bots(uid)
    running = sum(1 for b in bots if b.get("status") == "running")
    pays = [x for x in d.get("payments", []) if x.get("uid") == uid and x.get("status") == "approved"]
    tickets = d.get("tickets", {})
    my_tickets = [t for t in tickets.values() if t.get("uid") == uid]
    plan_expires = u.get("plan_expires")
    expires_txt = fmt_ts(plan_expires) if plan_expires else ("Forever" if p["price"] == 0 else "\u2014")
    cap = (
        f"<b>{G['graph']} {sc('My Stats')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Name', u.get('name', '—'))}\n"
        f"{bullet('User ID', uid)}\n"
        f"{bullet('Plan', p['name'])}\n"
        f"{bullet('Expires', expires_txt)}\n"
        f"{bullet('RAM', str(p['ram']) + ' MB')}\n"
        f"{G['div']}\n"
        f"{bullet('Total Bots', len(bots))}\n"
        f"{bullet('Running', running)}\n"
        f"{bullet('Slots', str(len(bots)) + ' / ' + str(user_max_bots(u)))}\n"
        f"{G['div']}\n"
        f"{bullet('Payments', len(pays))}\n"
        f"{bullet('Wallet', '{}$'.format(u.get('wallet', 0)))}\n"
        f"{G['div']}\n"
        f"{bullet('Referrals', u.get('ref_count', 0))}\n"
        f"{bullet('Bonus Slots', u.get('bot_slots_bonus', 0))}\n"
        f"{bullet('Free Trial', 'Used' if u.get('trial_used') else 'Available')}\n"
        f"{bullet('Tickets', len(my_tickets))}\n"
        f"{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["stats"], cap, back_main_kb(), call=call)


def render_user_tickets(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    d = db_load()["tickets"]
    mine = [t for t in d.values() if t.get("uid") == uid][-10:]
    rows = "\n".join(
        f"{G['bullet']} <code>{t['id']}</code> {G['bullet']} {esc(t.get('status'))} {G['bullet']} {esc(t.get('subject', ''))[:40]}"
        for t in mine
    ) or f"<i>{sc('no tickets yet')}</i>"
    cap = (
        f"<b>{G['ticket']} {sc('Your Tickets')}</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup()
    for t in mine:
        kb.add(Btn(f"#{t['id']} {esc(t.get('subject', ''))[:25]}", callback_data=f"ticket_view_{t['id']}"))
    kb.add(
        Btn(f"{G['plus']}  {sc('Open Ticket')}", callback_data="ticket_open"),
        Btn(f"{G['back']}  {sc('Main Menu')}", callback_data="menu_main"),
    )
    show_menu(call.message.chat.id, PHOTOS.get("ticket", PHOTOS["main"]), cap, kb, call=call)


def start_ticket_flow(call: types.CallbackQuery) -> None:
    USER_STATES[call.from_user.id] = {"flow": "await_ticket_subject"}
    bot.send_message(
        call.message.chat.id,
        f"{G['ticket']} {sc('Send the ticket subject (one line)')}.\n/cancel {sc('to abort')}.",
    )


def render_ticket_view(call: types.CallbackQuery, tid: str) -> None:
    d = db_load()["tickets"]
    t = d.get(tid)
    if not t:
        ack(call, "Not found"); return
    uid = call.from_user.id
    if t["uid"] != uid and not is_admin(uid):
        ack(call, "Not yours"); return
    msgs = t.get("messages", [])[-5:]
    rows = "\n".join(
        f"<b>{esc(x.get('from', '?'))}</b>: {esc(x.get('text', ''))[:200]}"
        for x in msgs
    ) or "(empty)"
    cap = (
        f"<b>{G['ticket']} {sc('Ticket')} #{tid}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Subject', t.get('subject', '—'))}\n"
        f"{bullet('Status', t.get('status', '—'))}\n"
        f"{G['div']}\n{rows}\n{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn(f"{G['fwd']}  {sc('Reply')}", callback_data=f"ticket_reply_{tid}"),
        Btn(f"{G['no']}  {sc('Close')}", callback_data=f"ticket_close_{tid}"),
    )
    kb.add(Btn(f"{G['back']}  {sc('Tickets')}", callback_data="menu_tickets"))
    show_text(call.message.chat.id, cap, kb, call=call)


def action_ticket_close(call: types.CallbackQuery, tid: str) -> None:
    d = db_load()
    t = d["tickets"].get(tid)
    if not t:
        ack(call, "Not found"); return
    if t["uid"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    t["status"] = "closed"
    db_save(d)
    audit(call.from_user.id, "ticket_close", f"tid={tid}")
    ack(call, "Ticket closed")
    render_user_tickets(call)


def start_ticket_reply(call: types.CallbackQuery, tid: str) -> None:
    USER_STATES[call.from_user.id] = {"flow": "await_ticket_reply", "tid": tid}
    bot.send_message(
        call.message.chat.id,
        f"{G['ticket']} #{tid} \u2014 {sc('send your reply text')}.\n/cancel {sc('to abort')}.",
    )
    ack(call)


def start_coupon_flow(call: types.CallbackQuery) -> None:
    USER_STATES[call.from_user.id] = {"flow": "await_coupon"}
    bot.send_message(call.message.chat.id,
        f"{G['key']} {sc('Send your coupon code')}. /cancel {sc('to abort')}.")


def start_wallet_topup(call: types.CallbackQuery) -> None:
    USER_STATES[call.from_user.id] = {"flow": "await_topup_proof"}
    bot.send_message(call.message.chat.id,
        f"{G['plus']} {sc('Send a screenshot of your top-up payment')}.\n"
        f"{sc('Include the amount in the caption e.g.')} <code>200</code>.", parse_mode="HTML")


def start_wallet_gift(call: types.CallbackQuery) -> None:
    USER_STATES[call.from_user.id] = {"flow": "await_gift_target"}
    bot.send_message(call.message.chat.id,
        f"{G['spark']} {sc('Send the user id of the person to gift your plan to')}.")


# ─── Bot view and actions ─────────────────────────────────────────────────────

def render_bot_view(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b:
        ack(call, "Not found"); return
    if b["owner"] != call.from_user.id and not is_admin(call.from_user.id):
        ack(call, "Not yours"); return
    st = child_status(bot_id, b)
    err_block = ""
    if not st["running"]:
        rc = b.get("last_exit_code")
        last_err = (b.get("last_error") or "").strip()
        if last_err or (rc not in (None, 0)):
            err_block = (
                f"\n{G['div']}\n<b>{G['no']} Last error"
                + (f" (exit {rc})" if rc not in (None, 0) else "") + "</b>\n"
                f"<pre>{esc(last_err or '(no log captured)')[:900]}</pre>"
            )
    appr = (b.get("approval_status") or "").lower()
    if appr == "pending":
        status_lbl = "\u23f3 Pending Approval"
    elif appr == "rejected":
        status_lbl = "\u274c Rejected"
    elif st["running"]:
        status_lbl = "\u25b6 Running"
    elif b.get("status") == "crashed":
        status_lbl = "\U0001f4a5 Crashed"
    else:
        status_lbl = "\u23f9 Stopped"
    src_info = ""
    if b.get("source") in ("github", "github_browser"):
        src_info = f"\n{bullet('Source', '🐙 GitHub')}\n{bullet('Repo', esc((b.get('gh_repo','?'))[:40]))}"
    cap = (
        f"<b>{G['diamond']} {esc(b['name'])}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Status', status_lbl)}\n"
        f"{bullet('Kind', st['kind'] or '—')}\n"
        f"{bullet('Uptime', fmt_dur(st['uptimeMs']))}\n"
        f"{bullet('CPU', '{:.1f}%'.format(st['cpuPct']))}\n"
        f"{bullet('Memory', fmt_bytes(st['memBytes']))}\n"
        f"{bullet('Size', fmt_bytes(st['sizeBytes']))}\n"
        f"{bullet('Created', fmt_ts(b.get('created')))}"
        f"{src_info}"
        f"{err_block}\n"
        f"{G['div']}{FOOTER}"
    )
    owner_doc = db_load()["users"].get(str(b["owner"])) or {}
    is_premium = owner_doc.get("plan", "free") != "free" and user_plan_active(owner_doc)
    tun = TUNNELS.get(bot_id) if "TUNNELS" in globals() else None
    if tun and tun.get("proc") and tun["proc"].poll() is None and tun.get("url"):
        cap = cap[:-len(FOOTER)] + f"\n{bullet('Public URL', tun['url'])}" + FOOTER
    show_menu(call.message.chat.id, PHOTOS["bot"], cap,
              bot_actions_kb(bot_id, st["running"], premium=is_premium), call=call)


def action_bot_start(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b or (b["owner"] != call.from_user.id and not is_admin(call.from_user.id)):
        ack(call, "Not found / not yours"); return
    loading(call, "Starting bot")
    res = start_child(b)
    ack(call, "Started" if res["ok"] else f"Err: {res.get('error')}")
    render_bot_view(call, bot_id)


def action_bot_stop(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b or (b["owner"] != call.from_user.id and not is_admin(call.from_user.id)):
        ack(call, "Not found / not yours"); return
    loading(call, "Stopping bot")
    stop_child(bot_id, manual=True)
    ack(call, "Stopped")
    render_bot_view(call, bot_id)


def action_bot_restart(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b or (b["owner"] != call.from_user.id and not is_admin(call.from_user.id)):
        ack(call, "Not found / not yours"); return
    loading(call, "Restarting bot")
    res = restart_child(b)
    ack(call, "Restarted" if res.get("ok") else f"Err: {res.get('error')}")
    render_bot_view(call, bot_id)


def action_bot_logs(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b or (b["owner"] != call.from_user.id and not is_admin(call.from_user.id)):
        ack(call, "Not found"); return
    ack(call, "Fetching logs\u2026")
    logs = tail_log(bot_id, lines=60)
    if not logs:
        logs = "(no output yet)"
    cap = (
        f"<b>{G['eye']} {sc('Logs')}: {esc(b['name'])}</b>\n"
        f"{G['div_eq']}\n"
        f"<pre>{esc(logs[-3000:])}</pre>\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup()
    kb.add(Btn(f"\u21bb  {sc('Refresh')}", callback_data=f"bot_logs_{bot_id}"))
    kb.add(Btn(f"{G['back']}  {sc('Bot')}", callback_data=f"bot_view_{bot_id}"))
    show_text(call.message.chat.id, cap, kb, call=call)


def action_bot_info(call: types.CallbackQuery, bot_id: str) -> None:
    render_bot_view(call, bot_id)


def render_env_menu(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b or (b["owner"] != call.from_user.id and not is_admin(call.from_user.id)):
        ack(call, "Not found"); return
    env = b.get("env", {})
    rows = "\n".join(
        f"{G['bullet']} <code>{esc(k)}</code> = <code>{'*' * min(len(str(v)), 6)}\u2026</code>"
        for k, v in list(env.items())[:20]
    ) or f"<i>{sc('No env vars set')}</i>"
    cap = (
        f"<b>{G['key']} {sc('Env Vars')}: {esc(b['name'])}</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup()
    kb.add(Btn(f"{G['plus']}  {sc('Add / Edit Var')}", callback_data=f"env_add_{bot_id}"))
    for k in list(env.keys())[:10]:
        kb.add(Btn(f"\U0001f5d1\ufe0f {k}", callback_data=f"env_del_{bot_id}_{k}"))
    kb.add(Btn(f"{G['back']}  {sc('Bot')}", callback_data=f"bot_view_{bot_id}"))
    show_text(call.message.chat.id, cap, kb, call=call)


def start_env_add(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b or (b["owner"] != call.from_user.id and not is_admin(call.from_user.id)):
        ack(call, "Not yours"); return
    USER_STATES[call.from_user.id] = {"flow": "await_env_kv", "bot_id": bot_id}
    bot.send_message(call.message.chat.id,
        f"{G['key']} {sc('Send env var in format')}: <code>KEY=VALUE</code>\n"
        f"{sc('Example')}: <code>BOT_TOKEN=123456:AAA...</code>\n/cancel {sc('to abort')}.",
        parse_mode="HTML")
    ack(call)


def action_env_delete(call: types.CallbackQuery, bot_id: str, key: str) -> None:
    b = find_bot(bot_id)
    if not b or (b["owner"] != call.from_user.id and not is_admin(call.from_user.id)):
        ack(call, "Not yours"); return
    b.setdefault("env", {}).pop(key, None)
    save_bot(b)
    audit(call.from_user.id, "env_del", f"bot={bot_id} key={key}")
    ack(call, f"Deleted {key}")
    render_env_menu(call, bot_id)


def render_cron(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b or (b["owner"] != call.from_user.id and not is_admin(call.from_user.id)):
        ack(call, "Not yours"); return
    cron = b.get("cron", {})
    cap = (
        f"<b>{G['settings']} {sc('Cron / Auto Tasks')}: {esc(b['name'])}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Auto-restart hours', cron.get('restart_hours', '—'))}\n"
        f"{bullet('Auto-backup hours',  cron.get('backup_hours',  '—'))}\n"
        f"{G['div']}\n"
        f"Send: <code>restart_hours N</code> {sc('or')} <code>backup_hours N</code>\n"
        f"{sc('Set 0 to disable')}.\n/cancel {sc('to abort')}.{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_cron", "bot_id": bot_id}
    show_text(call.message.chat.id, cap, _adm_back(f"bot_view_{bot_id}"), call=call)


def start_pip_install_flow(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b or (b["owner"] != call.from_user.id and not is_admin(call.from_user.id)):
        ack(call, "Not yours"); return
    USER_STATES[call.from_user.id] = {"flow": "await_pip_install", "bot_id": bot_id}
    bot.send_message(call.message.chat.id,
        f"{G['plus']} {sc('Send package names space-separated')}:\n"
        f"<code>requests aiohttp python-dotenv</code>\n/cancel {sc('to abort')}.",
        parse_mode="HTML")
    ack(call)


def start_tunnel_flow(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b or (b["owner"] != call.from_user.id and not is_admin(call.from_user.id)):
        ack(call, "Not yours"); return
    USER_STATES[call.from_user.id] = {"flow": "await_tunnel_port", "bot_id": bot_id}
    bot.send_message(call.message.chat.id,
        f"\U0001f310 {sc('Send the port your bot listens on (e.g. 8080) to start a tunnel')}.\n/cancel {sc('to abort')}.")
    ack(call)


def render_bot_delete_confirm(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b or (b["owner"] != call.from_user.id and not is_admin(call.from_user.id)):
        ack(call, "Not yours"); return
    cap = (
        f"<b>{G['warn']} {sc('Confirm Delete')}</b>\n{G['div']}\n"
        f"{sc('Delete')} <b>{esc(b['name'])}</b>?\n"
        f"{sc('Keeps files but removes the bot record')}.{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn(f"{G['ok']}  Delete Record", callback_data=f"bot_delyes_{bot_id}", style="danger"),
        Btn(f"{G['no']}  Cancel",         callback_data=f"bot_view_{bot_id}",  style="primary"),
    )
    show_text(call.message.chat.id, cap, kb, call=call)


def action_bot_delete(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b or (b["owner"] != call.from_user.id and not is_admin(call.from_user.id)):
        ack(call, "Not yours"); return
    stop_child(bot_id, manual=True)
    delete_bot_doc(bot_id)
    audit(call.from_user.id, "bot_delete", f"bot={bot_id}")
    ack(call, "Deleted")
    render_bots_menu(call)


def render_bot_delfiles_confirm(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b or (b["owner"] != call.from_user.id and not is_admin(call.from_user.id)):
        ack(call, "Not yours"); return
    cap = (
        f"<b>{G['warn']} {sc('Delete Files')}</b>\n{G['div']}\n"
        f"{sc('Delete files of')} <b>{esc(b['name'])}</b>?\n"
        f"{sc('Record stays but all uploaded files will be removed')}.{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn(f"{G['ok']}  Delete Files", callback_data=f"bot_delfilesyes_{bot_id}", style="danger"),
        Btn(f"{G['no']}  Cancel",        callback_data=f"bot_view_{bot_id}",       style="primary"),
    )
    show_text(call.message.chat.id, cap, kb, call=call)


def action_bot_delfiles(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b or (b["owner"] != call.from_user.id and not is_admin(call.from_user.id)):
        ack(call, "Not yours"); return
    try:
        rmrf(b.get("dir", ""))
    except Exception:
        pass
    b["enc_files"] = {}
    b["status"] = "stopped"
    save_bot(b)
    stop_child(bot_id, manual=True)
    audit(call.from_user.id, "bot_delfiles", f"bot={bot_id}")
    ack(call, "Files deleted")
    render_bot_view(call, bot_id)


def render_bot_delall_confirm(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b or (b["owner"] != call.from_user.id and not is_admin(call.from_user.id)):
        ack(call, "Not yours"); return
    cap = (
        f"<b>{G['no']} {sc('Delete Everything')}</b>\n{G['div']}\n"
        f"{sc('Delete')} <b>{esc(b['name'])}</b> including all files and record?{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn(f"{G['no']}  Delete All", callback_data=f"bot_delalyes_{bot_id}", style="danger"),
        Btn(f"{G['ok']}  Cancel",     callback_data=f"bot_view_{bot_id}",     style="primary"),
    )
    show_text(call.message.chat.id, cap, kb, call=call)


def action_bot_delall(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b or (b["owner"] != call.from_user.id and not is_admin(call.from_user.id)):
        ack(call, "Not yours"); return
    stop_child(bot_id, manual=True)
    try:
        rmrf(b.get("dir", ""))
    except Exception:
        pass
    delete_bot_doc(bot_id)
    audit(call.from_user.id, "bot_delall", f"bot={bot_id}")
    ack(call, "Deleted everything")
    render_bots_menu(call)


def action_bot_clone(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b or (b["owner"] != call.from_user.id and not is_admin(call.from_user.id)):
        ack(call, "Not yours"); return
    uid = call.from_user.id
    u = db_load()["users"].get(str(uid), {})
    if len(list_user_bots(uid)) >= user_max_bots(u):
        ack(call, "Bot slot limit reached"); return
    ack(call, "Cloning\u2026")
    new_id = secrets.token_hex(8)
    new_dir = DIRS["sandbox"] / f"{uid}_{new_id}"
    src_dir = Path(b.get("dir", ""))
    try:
        if src_dir.exists():
            shutil.copytree(str(src_dir), str(new_dir), dirs_exist_ok=True)
        else:
            new_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        new_dir.mkdir(parents=True, exist_ok=True)
    new_doc = dict(b)
    new_doc.update({
        "_id": new_id, "name": b["name"] + "_copy", "dir": str(new_dir),
        "created": ts_iso(), "status": "stopped",
    })
    new_doc.pop("last_started", None)
    d = db_load()
    d["bots"][new_id] = new_doc
    db_save(d)
    audit(uid, "bot_clone", f"src={bot_id} new={new_id}")
    bot.send_message(uid,
        f"<b>{G['ok']} {sc('Bot cloned')}</b>\n{bullet('New Bot ID', new_id)}\n{bullet('Name', new_doc['name'])}",
        parse_mode="HTML")
    render_bots_menu(call)


def action_bot_download(call: types.CallbackQuery, bot_id: str) -> None:
    b = find_bot(bot_id)
    if not b or (b["owner"] != call.from_user.id and not is_admin(call.from_user.id)):
        ack(call, "Not found"); return
    ack(call, "Packaging\u2026")
    def _bg() -> None:
        try:
            bot_dir = Path(b.get("dir", ""))
            if not bot_dir.exists():
                bot.send_message(call.from_user.id, f"{G['no']} No files to download."); return
            tmp = Path(tempfile.mktemp(suffix=f"_{b['name']}.zip"))
            with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
                for root, _, files in os.walk(bot_dir):
                    for fname in files:
                        fp = Path(root) / fname
                        zf.write(fp, arcname=fp.relative_to(bot_dir))
            sz = tmp.stat().st_size
            with tmp.open("rb") as fh:
                bot.send_document(call.from_user.id, fh,
                    caption=f"<b>\U0001f4e6 {esc(b['name'])}</b> ({fmt_bytes(sz)})",
                    parse_mode="HTML", visible_file_name=f"{b['name']}.zip")
            tmp.unlink(missing_ok=True)
            audit(call.from_user.id, "bot_download", f"bot={bot_id}")
        except Exception as e:
            try:
                bot.send_message(call.from_user.id,
                    f"{G['no']} Download error: <code>{esc(e)}</code>", parse_mode="HTML")
            except Exception:
                pass
    threading.Thread(target=_bg, daemon=True).start()


# ─── Admin panel ──────────────────────────────────────────────────────────────

def render_admin(call: types.CallbackQuery) -> None:
    if not admin_only_call(call, "view_stats"):
        return
    d = db_load()
    revenue = sum(p.get("amount", 0) for p in d["payments"] if p.get("status") == "approved")
    running_n = sum(1 for x in RUNNING.values() if x["proc"].poll() is None)
    pending_n = len(_pending_load())
    cap = (
        f"<b>{G['shield']} {sc('Admin Panel')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Users',   len(d['users']))}\n"
        f"{bullet('Bots',    len(d['bots']))}\n"
        f"{bullet('Running', running_n)}\n"
        f"{bullet('Revenue', '{}$'.format(revenue))}\n"
        f"{bullet('Pending', pending_n)}\n"
        f"{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, admin_kb(), call=call)


# ─── Admin sub-panel renders ──────────────────────────────────────────────────

def render_adm_stats(call: types.CallbackQuery) -> None:
    d = db_load()
    revenue = sum(p.get("amount", 0) for p in d["payments"] if p.get("status") == "approved")
    today_str = now_utc().strftime("%Y-%m-%d")
    new_today = sum(1 for u in d["users"].values() if str(u.get("joined", "")).startswith(today_str))
    rss = 0
    if psutil is not None:
        try:
            rss = psutil.Process(os.getpid()).memory_info().rss
        except Exception:
            pass
    cap = (
        f"<b>{G['graph']} {sc('System Stats')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Total users', len(d['users']))}\n"
        f"{bullet('New today', new_today)}\n"
        f"{bullet('Total bots', len(d['bots']))}\n"
        f"{bullet('Running', sum(1 for x in RUNNING.values() if x['proc'].poll() is None))}\n"
        f"{bullet('Revenue', '{}$'.format(revenue))}\n"
        f"{bullet('Panel RAM', fmt_bytes(int(rss)))}\n"
        f"{bullet('Uptime', fmt_dur(int(time.time() * 1000) - START_TS))}\n"
        f"{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["stats"], cap, back_admin_kb(), call=call)


def render_adm_users(call: types.CallbackQuery) -> None:
    d = db_load()["users"]
    items = sorted(d.values(), key=lambda u: u.get("joined", ""), reverse=True)[:20]
    rows = "\n".join(
        f"{G['bullet']} <code>{u['_id']}</code> \u2014 {esc(u.get('name', ''))} "
        f"@{esc(u.get('username') or '—')} {G['bullet']} <i>{esc(PLAN_LIMITS.get(u.get('plan','free'),{}).get('name','?'))}</i>"
        for u in items
    ) or f"<i>{sc('no users yet')}</i>"
    cap = (
        f"<b>{G['users']} {sc('Recent Users')} ({len(d)} {sc('total')})</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}\n"
        f"{sc('Send a numeric user id to look one up')}.{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_admin_finduser"}
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, back_admin_kb(), call=call)


def render_adm_allbots(call: types.CallbackQuery) -> None:
    # All bots from ALL PIDs (live) + DB. No local RUNNING — PIDs are truth.
    agg = _pid_fetch_all_bots()
    try:
        d = db_load_ro().get("bots", {}) or {}
    except Exception:
        d = {}
    for bid, b in (d.items() if isinstance(d, dict) else []):
        if bid not in agg:
            try:
                agg[bid] = {"vm_id": b.get("vm_id"), "live": None, "record": b}
            except Exception:
                pass
    items = list(agg.values())[:25]
    def _row(e: Dict[str, Any]) -> str:
        rec = e.get("record") or {}
        live = e.get("live") or {}
        bid = rec.get("_id") or live.get("bot_id") or "?"
        name = rec.get("name") or live.get("bot_id") or "?"
        owner = rec.get("owner") or "?"
        vm_id = e.get("vm_id") or rec.get("vm_id") or "?"
        status = (live.get("status") if isinstance(live, dict) else None) or rec.get("status") or "idle"
        icon = "&#x25B6;" if status == "running" else "&#x23F9;"
        src = " 🐙" if rec.get("source") in ("github", "github_browser") else ""
        return (f"{G['bullet']} <code>{esc(bid)}</code> — {esc(name)} "
                f"{G['bullet']} uid {esc(owner)} {icon}{src} {G['bullet']} {esc(vm_id)}")
    rows = "\n".join(_row(e) for e in items) or f"<i>{sc('no bots')}</i>"
    cap = (
        f"<b>{G['diamond']} {sc('All Bots')} ({len(agg)})</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, back_admin_kb(), call=call)


def render_adm_payments(call: types.CallbackQuery) -> None:
    d = db_load()
    pays = [p for p in d["payments"] if p.get("status") == "pending"][-15:]
    rows = "\n".join(
        f"{G['bullet']} <code>{p['id']}</code> {G['bullet']} uid {p['uid']} "
        f"{G['bullet']} {esc(p.get('plan', '—'))} {G['bullet']} {esc(p.get('method', ''))}"
        for p in pays
    ) or f"<i>{sc('no pending payments')}</i>"
    cap = (
        f"<b>{G['wallet']} {sc('Pending Payments')}</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, back_admin_kb(), call=call)


def render_adm_broadcast(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>{G['broadcast']} {sc('Broadcast')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Send message text now')}.\n"
        f"Prefix <code>plan:pro</code> \u2014 only pro users.\n"
        f"Prefix <code>at:YYYY-MM-DD HH:MM</code> \u2014 schedule.{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_broadcast"}
    show_menu(call.message.chat.id, PHOTOS.get("broadcast", PHOTOS["admin"]), cap, back_admin_kb(), call=call)


def render_adm_ban(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>{G['no']} {sc('Ban / Unban')}</b>\n"
        f"{G['div_eq']}\n"
        f"Send: <code>ban user_id reason</code>\n"
        f"Send: <code>unban user_id</code>{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_ban_cmd"}
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, back_admin_kb(), call=call)


def render_adm_giveplan(call: types.CallbackQuery) -> None:
    cap = (
        f"<b>{G['plus']} {sc('Give Plan')}</b>\n"
        f"{G['div_eq']}\n"
        f"Send: <code>user_id plan [days]</code>\n"
        f"Plans: {', '.join(PLAN_LIMITS.keys())}{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_giveplan"}
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, back_admin_kb(), call=call)


def render_adm_approve(call: types.CallbackQuery) -> None:
    render_adm_payments(call)


def render_adm_coupons(call: types.CallbackQuery) -> None:
    d = db_load()["coupons"]
    rows = "\n".join(
        f"{G['bullet']} <code>{esc(code)}</code> \u2014 {esc(c.get('percent'))}% {G['bullet']} {esc(c.get('uses_left'))} uses"
        for code, c in d.items()
    ) or f"<i>{sc('no coupons yet')}</i>"
    cap = (
        f"<b>{G['key']} {sc('Coupons')}</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}\n"
        f"Send: <code>add CODE PERCENT USES</code>\n"
        f"Send: <code>del CODE</code>{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_coupon_admin"}
    show_menu(call.message.chat.id, PHOTOS.get("coupon", PHOTOS["admin"]), cap, back_admin_kb(), call=call)


def render_adm_tickets(call: types.CallbackQuery) -> None:
    d = db_load()["tickets"]
    open_t = [t for t in d.values() if t.get("status") == "open"][-15:]
    rows = "\n".join(
        f"{G['bullet']} <code>{t['id']}</code> uid {t['uid']} \u2014 {esc(t.get('subject', ''))[:40]}"
        for t in open_t
    ) or f"<i>{sc('no open tickets')}</i>"
    cap = (
        f"<b>{G['ticket']} {sc('Open Tickets')}</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup()
    for t in open_t:
        kb.add(Btn(f"{G['eye']}  #{t['id']}", callback_data=f"ticket_view_{t['id']}"))
    kb.add(Btn(f"{G['back']}  {sc('Admin')}", callback_data="menu_admin"))
    show_menu(call.message.chat.id, PHOTOS.get("ticket", PHOTOS["admin"]), cap, kb, call=call)


def render_adm_admins(call: types.CallbackQuery) -> None:
    if not is_owner(call.from_user.id):
        ack(call, "Owner only"); return
    d = db_load()["admins"]
    rows = "\n".join(
        f"{G['bullet']} <code>{uid}</code> \u2014 {esc(a.get('role'))}"
        for uid, a in d.items()
    ) or f"<i>{sc('no extra admins yet')}</i>"
    cap = (
        f"<b>{G['shield']} {sc('Admins')}</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}\n"
        f"Send: <code>add uid role</code>\n"
        f"Roles: <code>view-only</code>, <code>manage-users</code>, <code>full-access</code>\n"
        f"Send: <code>del uid</code>{FOOTER}"
    )
    USER_STATES[call.from_user.id] = {"flow": "await_admin_admins"}
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, back_admin_kb(), call=call)


def render_adm_audit(call: types.CallbackQuery) -> None:
    d = db_load()["audit"][-25:]
    rows = "\n".join(
        f"{G['bullet']} {esc(a.get('ts', ''))[11:19]} uid {a['uid']} \u2192 {esc(a['action'])} {esc(a.get('detail', ''))[:60]}"
        for a in reversed(d)
    ) or f"<i>{sc('no audit entries yet')}</i>"
    cap = (
        f"<b>{G['eye']} {sc('Recent Audit')}</b>\n"
        f"{G['div_eq']}\n{rows}\n{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["security"], cap, back_admin_kb(), call=call)


def render_adm_pending(call: types.CallbackQuery) -> None:
    if not admin_only_call(call, "approve_payment"):
        return
    items = pending_list()
    if not items:
        cap = (
            f"<b>{G['eye']} {sc('Pending Uploads')}</b>\n"
            f"{G['div_eq']}\n<i>{sc('Inbox is empty')}.</i>\n{G['div']}{FOOTER}"
        )
        show_menu(call.message.chat.id, PHOTOS["admin"], cap, back_admin_kb(), call=call)
        return
    rows = []
    kb = types.InlineKeyboardMarkup(row_width=2)
    for bid, info in items[:15]:
        b = find_bot(bid)
        nm = (b or {}).get("name") or info.get("file_name") or bid
        rows.append(
            f"{G['bullet']} <code>{esc(bid)}</code> \u2014 {esc(nm)} "
            f"{G['bullet']} uid {info.get('user_id')} "
            f"{G['bullet']} {fmt_bytes(info.get('size', 0))}"
        )
        kb.add(
            Btn(f"{G['ok']}  OK {esc(nm)[:18]}", callback_data=f"appr_ok_{bid}"),
            Btn(f"{G['no']}  No {esc(nm)[:18]}", callback_data=f"appr_no_{bid}"),
        )
    kb.add(Btn(f"{G['back']}  {sc('Admin')}", callback_data="menu_admin"))
    cap = (
        f"<b>{G['eye']} {sc('Pending Uploads')} ({len(items)})</b>\n"
        f"{G['div_eq']}\n" + "\n".join(rows) + f"\n{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


def render_adm_photos(call: types.CallbackQuery) -> None:
    if not is_owner(call.from_user.id) and not admin_can(call.from_user.id, "manage_admins"):
        ack(call, "Owner / full-access only."); return
    cap = (
        f"<b>{G['upload']} {sc('Menu Photos')}</b>\n"
        f"{G['div_eq']}\n"
        f"{sc('Tap any menu below, then send a photo to replace its banner')}.{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    for key, label in sorted(PHOTO_KEYS_FRIENDLY.items()):
        if key in _PHOTO_SPECS:
            kb.add(Btn(f"{G['cog']}  {sc(label)}", callback_data=f"adm_photo_{key}"))
    kb.add(Btn(f"{G['back']}  {sc('Admin')}", callback_data="menu_admin"))
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


def render_adm_security(call: types.CallbackQuery) -> None:
    d = db_load()
    scan_log = d.get("scan_log", [])
    blocked = sum(1 for s in scan_log if s.get("verdict") == "DANGEROUS")
    cap = (
        f"<b>{G['lock']} {sc('Security')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Scan log entries', len(scan_log))}\n"
        f"{bullet('Blocked uploads', blocked)}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("\U0001f6e1\ufe0f  Sec Center",       callback_data="adm_sec_center",    style="danger"),
        Btn(f"{G['eye']}  Scan Log",    callback_data="adm_security_log",  style="primary"),
    )
    kb.add(Btn(f"{G['back']}  Admin", callback_data="menu_admin"))
    show_menu(call.message.chat.id, PHOTOS["security"], cap, kb, call=call)


def render_adm_maintenance(call: types.CallbackQuery) -> None:
    if not is_owner(call.from_user.id):
        ack(call, "Owner only"); return
    on = bool(get_setting("maintenance", False))
    cap = (
        f"<b>{G['warn']} {sc('Maintenance Mode')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Status', 'ON' if on else 'OFF')}\n"
        f"{G['div']}\n"
        f"{sc('When enabled, only admins can use the bot')}.{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup()
    kb.add(Btn(f"{'Disable' if on else 'Enable'} Maintenance",
               callback_data="adm_maint_toggle",
               style="danger" if on else "success"))
    kb.add(Btn(f"{G['back']}  Admin", callback_data="menu_admin"))
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


def render_adm_settings(call: types.CallbackQuery) -> None:
    if not admin_only_call(call, "view_stats"):
        return
    on = bool(get_setting("maintenance", False))
    cap = (
        f"<b>{G['settings']} {sc('Settings')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Brand', BRAND_TAG)}\n"
        f"{bullet('Announce Ch', ANNOUNCE_CHANNEL or '—')}\n"
        f"{bullet('Maintenance', 'ON' if on else 'OFF')}\n"
        f"{bullet('TG Backup Ch', _tg_backup_channel() or '—')}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("\u270f\ufe0f  Brand Name",      callback_data="adm_set_brand",       style="primary"),
        Btn("\U0001f4e3  Announce Ch",       callback_data="adm_set_announce",    style="primary"),
    )
    kb.add(
        Btn("\U0001f451  Transfer Owner",    callback_data="adm_set_owner",       style="danger"),
        Btn("\U0001f527  Maint Mode",        callback_data="adm_maint",           style="danger"),
    )
    kb.add(
        Btn("\U0001f504  Restart All Bots",  callback_data="adm_set_restart_all", style="success"),
        Btn("\U0001f534  Stop All Bots",     callback_data="adm_set_stop_all",    style="danger"),
    )
    kb.add(
        Btn("\U0001f9f9  Clean Orphans",     callback_data="adm_set_clean_orphans",style="primary"),
        Btn("\U0001f4e4  Export Data",       callback_data="adm_set_export",      style="primary"),
    )
    kb.add(
        Btn("\U0001f4e1  TG Ch Backup",      callback_data="adm_tg_backup",       style="primary"),
        Btn("\U0001f510  Approval Groups",   callback_data="adm_approval_group",  style="primary"),
    )
    kb.add(
        Btn("\U0001f512  Private Appr Grp",  callback_data="adm_private_group",   style="primary"),
        Btn("\U0001f4ca  Plan Editor",       callback_data="adm_set_plans",       style="primary"),
    )
    kb.add(
        Btn("\U0001f5a5\ufe0f  Sys Info",    callback_data="adm_set_sysinfo",     style="primary"),
        Btn("\U0001f504  Reload Caches",     callback_data="adm_set_reload",      style="success"),
    )
    kb.add(
        Btn("\u270f\ufe0f  Footer Text",     callback_data="adm_set_footer_text", style="primary"),
        Btn("\U0001f44b  Welcome Msg",       callback_data="adm_set_welcome_text",style="primary"),
    )
    kb.add(
        Btn("\U0001f4dc  Hosting Rules",     callback_data="adm_set_rules_text",  style="primary"),
        Btn("\U0001f5c4\ufe0f  DB Info",     callback_data="adm_db_info",         style="primary"),
    )
    kb.add(Btn(f"{G['back']}  Admin", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


def render_adm_github(call: types.CallbackQuery) -> None:
    if not admin_only_call(call, "view_stats"):
        return
    enabled = gh_enabled()
    auto = bool(get_setting("github_auto_enabled", True))
    repo = GH.get("repo", "\u2014")
    branch = GH.get("branch", "main")
    interval = GH.get("intervalMin", 360)
    cap = (
        f"<b>{G['cog']} {sc('GitHub Backup')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Status', 'Active' if enabled else 'Not Configured')}\n"
        f"{bullet('Repo', repo)}\n"
        f"{bullet('Branch', branch)}\n"
        f"{bullet('Interval', f'{interval}min')}\n"
        f"{bullet('Auto', 'ON' if auto else 'OFF')}\n"
        f"{G['div']}{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn("\U0001f511  Token",    callback_data="gh_set_token",   style="primary"),
        Btn("\U0001f4e6  Repo",     callback_data="gh_set_repo",    style="primary"),
    )
    kb.add(
        Btn("\U0001f33f  Branch",   callback_data="gh_set_branch",  style="primary"),
        Btn("\u23f1\ufe0f  Interval",callback_data="gh_set_interval",style="primary"),
    )
    kb.add(
        Btn(f"{'OK' if auto else 'OFF'}  Auto", callback_data="gh_toggle_auto",
            style="success" if auto else "danger"),
        Btn("\U0001f4be  Backup Now", callback_data="gh_backup_now", style="success"),
    )
    kb.add(
        Btn("\U0001f4e5  Restore",    callback_data="gh_restore_now", style="danger"),
        Btn("\U0001f419  Browse",     callback_data="adm_gh_browser", style="primary"),
    )
    kb.add(Btn(f"{G['back']}  Admin", callback_data="menu_admin", style="primary"))
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


def render_adm_sysinfo(call: types.CallbackQuery) -> None:
    import platform
    rss = vms = cpu_p = 0.0
    if psutil is not None:
        try:
            p = psutil.Process(os.getpid())
            mi = p.memory_info()
            rss, vms = mi.rss, mi.vms
            cpu_p = p.cpu_percent(interval=0.3)
        except Exception:
            pass
    up_secs = int(time.time() - START_TS / 1000)
    cap = (
        f"<b>\U0001f441\ufe0f {sc('System Info')}</b>\n"
        f"{G['div_eq']}\n"
        f"{bullet('Python', platform.python_version())}\n"
        f"{bullet('OS', platform.system() + ' ' + platform.release())}\n"
        f"{bullet('PID', os.getpid())}\n"
        f"{bullet('Uptime', fmt_dur(up_secs * 1000))}\n"
        f"{bullet('RAM RSS', fmt_bytes(int(rss)))}\n"
        f"{bullet('CPU', f'{cpu_p:.1f}%')}\n"
        f"{bullet('Brand', BRAND_TAG)}\n"
        f"{bullet('Owner ID', OWNER_ID)}\n"
        f"{G['div']}{FOOTER}"
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, _adm_back("adm_settings"), call=call)


def render_adm_plans(call: types.CallbackQuery) -> None:
    rows = []
    for k, v in PLAN_LIMITS.items():
        live = int(get_setting(f"plan_max_bots_{k}", v["max_bots"]))
        rows.append(f"{bullet(v['name'], f'max_bots = {live}')}")
    cap = (
        f"<b>{G['diamond']} {sc('Plans Editor')}</b>\n"
        f"{G['div_eq']}\n"
        + "\n".join(rows) + "\n"
        f"{G['div']}\n"
        f"<i>{sc('Adjust bot quotas per plan')}.</i>{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=3)
    for k, v in PLAN_LIMITS.items():
        live = int(get_setting(f"plan_max_bots_{k}", v["max_bots"]))
        kb.add(
            Btn(f"\u2796 {sc(v['name'])}", callback_data=f"adm_set_plan_dec_{k}"),
            Btn(str(live),                  callback_data=f"adm_set_plan_show_{k}"),
            Btn(f"\u2795 {sc(v['name'])}", callback_data=f"adm_set_plan_inc_{k}"),
        )
    kb.add(Btn("\u21ba  Reset Defaults", callback_data="adm_set_plans_reset"))
    kb.add(Btn(f"{G['back']}  Settings", callback_data="adm_settings"))
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


def render_adm_confirm(call: types.CallbackQuery, action: str, label: str) -> None:
    cap = (
        f"<b>{G['warn']} {sc('Confirm')}</b>\n{G['div_eq']}\n"
        f"{sc('About to')}: <b>{esc(label)}</b>.\n{sc('Continue')}?{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn(f"{G['ok']}  Yes, do it",   callback_data=f"{action}_yes", style="danger"),
        Btn(f"{G['no']}  Cancel",        callback_data="adm_settings",  style="primary"),
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


def render_adm_confirm_custom(call: types.CallbackQuery, action: str,
                               label: str, back_cb: str = "menu_admin") -> None:
    cap = (
        f"<b>{G['warn']} {sc('Confirm')}</b>\n{G['div_eq']}\n"
        f"{sc('About to')}: <b>{esc(label)}</b>. {sc('Are you sure')}?{FOOTER}"
    )
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        Btn(f"{G['ok']}  Yes", callback_data=action,  style="danger"),
        Btn(f"{G['no']}  No",  callback_data=back_cb, style="primary"),
    )
    show_menu(call.message.chat.id, PHOTOS["admin"], cap, kb, call=call)


# ─── Payment handlers ─────────────────────────────────────────────────────────

def action_payment_approve(call: types.CallbackQuery, pid: str) -> None:
    if not admin_only_call(call, "approve_payment"):
        return
    d = db_load()
    pay = next((x for x in d["payments"] if x.get("id") == pid), None)
    if not pay:
        ack(call, "Not found"); return
    if pay.get("status") in ("approved", "rejected"):
        ack(call, f"Already {pay['status']}."); return
    loading(call, "Approving payment")
    pay["status"] = "approved"
    pay["approved_by"] = call.from_user.id
    pay["approved_at"] = ts_iso()
    db_save(d)
    if pay.get("kind") == "wallet_topup":
        u = d["users"].get(str(pay["uid"]))
        if u:
            u["wallet"] = int(u.get("wallet", 0)) + int(pay.get("amount", 0))
            db_save(d)
            try:
                bot.send_message(pay["uid"],
                    f"<b>{G['ok']} {sc('Wallet credited')}</b>\n"
                    f"{bullet('Amount', '{}$'.format(pay['amount']))}", parse_mode="HTML")
            except Exception:
                pass
    elif pay.get("plan"):
        grant_plan(pay["uid"], pay["plan"])
    audit(call.from_user.id, "pay_approve", f"pid={pid}")
    ack(call, "Approved")
    try:
        bot.edit_message_text(f"<b>{G['ok']} {sc('Approved')} #{pid}</b>",
                              chat_id=call.message.chat.id,
                              message_id=call.message.message_id, parse_mode="HTML")
    except Exception:
        pass


def action_payment_reject(call: types.CallbackQuery, pid: str) -> None:
    if not admin_only_call(call, "approve_payment"):
        return
    d = db_load()
    pay = next((x for x in d["payments"] if x.get("id") == pid), None)
    if not pay:
        ack(call, "Not found"); return
    if pay.get("status") in ("approved", "rejected"):
        ack(call, f"Already {pay['status']}."); return
    loading(call, "Rejecting payment")
    pay["status"] = "rejected"
    pay["rejected_by"] = call.from_user.id
    pay["rejected_at"] = ts_iso()
    db_save(d)
    audit(call.from_user.id, "pay_reject", f"pid={pid}")
    try:
        bot.send_message(pay["uid"],
            f"<b>{G['no']} {sc('Payment rejected')}</b> #{pid}\n{sc('Contact')} {SUPPORT_USR}",
            parse_mode="HTML")
    except Exception:
        pass
    ack(call, "Rejected")
    try:
        bot.edit_message_text(f"<b>{G['no']} {sc('Rejected')} #{pid}</b>",
                              chat_id=call.message.chat.id,
                              message_id=call.message.message_id, parse_mode="HTML")
    except Exception:
        pass


# ─── Admin subroute dispatcher ────────────────────────────────────────────────

def render_admin_subroute(call: types.CallbackQuery, data: str) -> None:
    uid = call.from_user.id

    if data == "adm_stats":              return render_adm_stats(call)
    if data == "adm_users":              return render_adm_users(call)
    if data == "adm_allbots":            return render_adm_allbots(call)
    if data == "adm_payments":           return render_adm_payments(call)
    if data == "adm_broadcast":          return render_adm_broadcast(call)
    if data == "adm_ban":                return render_adm_ban(call)
    if data == "adm_giveplan":           return render_adm_giveplan(call)
    if data == "adm_approve":            return render_adm_approve(call)
    if data == "adm_coupons":            return render_adm_coupons(call)
    if data == "adm_tickets":            return render_adm_tickets(call)
    if data == "adm_admins":             return render_adm_admins(call)
    if data == "adm_audit":              return render_adm_audit(call)
    if data == "adm_github":             return render_adm_github(call)
    if data == "adm_vm_nodes":           return render_adm_vm_nodes(call)
    if data == "adm_mongo":              return render_adm_mongo(call)
    if data == "adm_vm_add":
        USER_STATES[call.from_user.id] = {"flow": "await_vm_url"}
        bot.send_message(call.message.chat.id, f"{G['plus']} {sc('Send the VM URL now')} (<code>https://....onrender.com</code>).", parse_mode="HTML"); return
    if data == "adm_vm_testall":         _bg_vm_testall(call); return
    if data.startswith("adm_vm_info:"):  return render_adm_vm_info(call, data.split(":", 1)[1])
    if data.startswith("adm_vm_toggle:"):
        _vm_toggle(call, data.split(":", 1)[1]); return render_adm_vm_info(call, data.split(":", 1)[1])
    if data.startswith("adm_vm_remove:"):
        _vm_remove(call, data.split(":", 1)[1]); return render_adm_vm_nodes(call)
    if data.startswith("adm_vm_test:"):
        _vm_test_one(call, data.split(":", 1)[1]); return
    if data == "adm_mongo_add":
        USER_STATES[call.from_user.id] = {"flow": "await_mongo_uri"}
        bot.send_message(call.message.chat.id, f"{G['key']} {sc('Send the MongoDB URI now')} (<code>mongodb+srv://...</code>).", parse_mode="HTML"); return
    if data.startswith("adm_mongo_remove:"):
        _mongo_remove_idx(call, data.split(":", 1)[1]); return render_adm_mongo(call)
    if data.startswith("adm_mongo_info:"):
        ack(call, "Fetching URI details…"); return render_adm_mongo_info(call, data.split(":", 1)[1])
    if data == "adm_security":           return render_adm_security(call)
    if data == "adm_maint":              return render_adm_maintenance(call)
    if data == "adm_settings":           return render_adm_settings(call)
    if data == "adm_pending":            return render_adm_pending(call)
    if data == "adm_photos":             return render_adm_photos(call)
    if data == "adm_tg_backup":          return render_adm_tg_channel_backup(call)
    if data == "adm_gh_browser":         return render_adm_gh_browser(call)
    if data == "adm_approval_group":     return render_adm_approval_group(call)
    if data == "adm_private_group":      return render_adm_private_group_panel(call)

    # GitHub browser callbacks
    if data.startswith("ghbrow_dir_"):
        _render_gh_dir(call, data[len("ghbrow_dir_"):]); return
    if data.startswith("ghbrow_file_"):
        _render_gh_file(call, data[len("ghbrow_file_"):]); return
    if data.startswith("ghbrow_dl_"):
        _action_gh_file_download(call, data[len("ghbrow_dl_"):]); return
    if data.startswith("ghbrow_run_"):
        _action_gh_file_run(call, data[len("ghbrow_run_"):]); return

    # TG channel backup callbacks
    if data == "adm_tg_bkp_now":
        ack(call, "Backing up to channel\u2026")
        def _tg_bkp():
            res = tg_channel_backup_now()
            try:
                bot.send_message(uid,
                    f"<b>{'OK' if res.get('ok') else G['no']} {sc('TG Channel Backup')}</b>\n"
                    f"{bullet('Size', fmt_bytes(res.get('size', 0)))}\n"
                    f"{bullet('Error', res.get('error', '') or 'none')}",
                    parse_mode="HTML")
            except Exception:
                pass
        threading.Thread(target=_tg_bkp, daemon=True).start(); return
    if data == "adm_tg_bkp_set_ch":
        if not is_owner(uid): ack(call, "Owner only"); return
        USER_STATES[uid] = {"flow": "await_tg_backup_channel"}
        bot.send_message(call.message.chat.id,
            f"\U0001f4e1 {sc('Send the channel handle or numeric ID (add bot as admin first)')}.\n"
            f"<code>@MyChannel</code> or <code>-1001234567890</code>", parse_mode="HTML"); return
    if data == "adm_tg_bkp_toggle_auto":
        if not is_owner(uid): ack(call, "Owner only"); return
        cur = bool(get_setting("tg_backup_auto", False))
        set_setting("tg_backup_auto", not cur)
        ack(call, f"Auto TG backup: {'ON' if not cur else 'OFF'}")
        return render_adm_tg_channel_backup(call)
    if data == "adm_tg_bkp_restore":
        ack(call, "See latest zip in channel")
        bot.send_message(uid, f"\U0001f4e5 {sc('Download the latest backup zip from your channel and upload it manually to restore')}."); return

    # Approval group callbacks
    if data == "adm_grpv_toggle":
        if not is_owner(uid): ack(call, "Owner only"); return
        cur = bool(get_setting("group_verify_enabled", False))
        set_setting("group_verify_enabled", not cur)
        _load_required_groups()
        ack(call, f"Group verify: {'ON' if not cur else 'OFF'}")
        return render_adm_approval_group(call)
    if data == "adm_grpv_add":
        if not is_owner(uid): ack(call, "Owner only"); return
        USER_STATES[uid] = {"flow": "await_adm_grpv_add"}
        bot.send_message(call.message.chat.id,
            f"\U0001f510 {sc('Send group info')}:\n"
            f"<code>NAME|GROUP_ID|INVITE_LINK</code>", parse_mode="HTML"); return
    if data == "adm_grpv_remove":
        if not is_owner(uid): ack(call, "Owner only"); return
        USER_STATES[uid] = {"flow": "await_adm_grpv_remove"}
        grps = get_setting("required_groups", []) or []
        names = "\n".join(f"{i+1}. {g['name']}" for i, g in enumerate(grps))
        bot.send_message(call.message.chat.id,
            f"\U0001f510 {sc('Send the number to remove')}:\n{names or 'none'}"); return
    if data == "adm_grpv_list":
        grps = get_setting("required_groups", []) or []
        rows = "\n".join(f"{i+1}. {g['name']} ({g.get('id','')})" for i, g in enumerate(grps)) or "none"
        bot.send_message(uid, f"\U0001f510 Groups:\n{rows}"); return
    if data == "adm_grpv_stats":
        return render_adm_grpv_stats(call)

    # Private approval group callbacks
    if data == "adm_apgrp_set":
        if not is_owner(uid): ack(call, "Owner only"); return
        USER_STATES[uid] = {"flow": "await_adm_private_apgrp"}
        bot.send_message(call.message.chat.id,
            f"\U0001f512 {sc('Send the private approval group/channel ID or handle')}."); return
    if data == "adm_apgrp_clear":
        if not is_owner(uid): ack(call, "Owner only"); return
        set_setting("private_approval_group", None)
        ack(call, "Approval group cleared")
        return render_adm_private_group_panel(call)
    if data == "adm_apgrp_toggle_notify":
        if not is_owner(uid): ack(call, "Owner only"); return
        cur = bool(get_setting("approval_notify_admins", True))
        set_setting("approval_notify_admins", not cur)
        ack(call, f"Notify: {'Admins only' if not cur else 'All'}")
        return render_adm_private_group_panel(call)
    if data == "adm_apgrp_test":
        pg = get_setting("private_approval_group", None)
        if not pg: ack(call, "No group configured"); return
        ack(call, "Testing\u2026")
        try:
            bot.send_message(pg,
                f"<b>\U0001f512 {sc('Test message from')} {BRAND_TAG}</b>\n"
                f"{sc('Approval group is configured correctly!')}",
                parse_mode="HTML")
            ack(call, "Test sent!")
        except Exception as e:
            ack(call, f"Failed: {e}")
        return

    # Maintenance toggle
    if data == "adm_maint_toggle":
        if not is_owner(uid): ack(call, "Owner only"); return
        cur = bool(get_setting("maintenance", False))
        set_setting("maintenance", not cur)
        audit(uid, "maintenance_toggle", f"now={'on' if not cur else 'off'}")
        ack(call, f"Maintenance: {'ON' if not cur else 'OFF'}")
        return render_adm_maintenance(call)

    # Settings sub-routes
    if data == "adm_set_sysinfo":        return render_adm_sysinfo(call)
    if data == "adm_set_plans":          return render_adm_plans(call)
    if data == "adm_set_plans_reset":
        if not is_owner(uid): ack(call, "Owner only"); return
        s = settings_load()
        for k in list(s.keys()):
            if k.startswith("plan_max_bots_"):
                s.pop(k, None)
        settings_save(s)
        audit(uid, "plans_reset", "")
        ack(call, "Plans reset to defaults")
        return render_adm_plans(call)
    if data.startswith("adm_set_plan_show_"):
        ack(call, "Use +/- to adjust"); return
    if data.startswith("adm_set_plan_inc_") or data.startswith("adm_set_plan_dec_"):
        if not is_owner(uid): ack(call, "Owner only"); return
        inc = data.startswith("adm_set_plan_inc_")
        key = data.split("_")[-1]
        if key not in PLAN_LIMITS: ack(call, "Unknown plan"); return
        cur_val = int(get_setting(f"plan_max_bots_{key}", PLAN_LIMITS[key]["max_bots"]))
        cur_val = max(1, cur_val + (1 if inc else -1))
        set_setting(f"plan_max_bots_{key}", cur_val)
        audit(uid, "plan_edit", f"{key} max_bots={cur_val}")
        ack(call, f"{PLAN_LIMITS[key]['name']}: {cur_val}")
        return render_adm_plans(call)
    if data == "adm_set_reload":
        cache_clear_all()
        audit(uid, "reload_caches", "")
        ack(call, "Caches dropped")
        return render_adm_settings(call)
    if data in ("adm_set_brand", "adm_set_announce", "adm_set_owner",
                "adm_set_footer_text", "adm_set_welcome_text", "adm_set_rules_text"):
        if not is_owner(uid): ack(call, "Owner only"); return
        prompts = {
            "adm_set_brand":        f"\u270f\ufe0f {sc('Send the new brand tag')}:",
            "adm_set_announce":     f"\U0001f4e3 {sc('Send the announce channel handle')} (<code>@ch</code> or <code>-</code>):",
            "adm_set_owner":        f"\U0001f451 {sc('Send the new owner numeric Telegram ID')}. <i>{sc('You will lose owner rights')}.</i>",
            "adm_set_footer_text":  f"\u270f\ufe0f {sc('Send new footer text')} (or <code>-</code> to reset):",
            "adm_set_welcome_text": f"\U0001f44b {sc('Send new welcome message')}:",
            "adm_set_rules_text":   f"\U0001f4dc {sc('Send new hosting rules text')}:",
        }
        flows = {
            "adm_set_brand": "await_set_brand",
            "adm_set_announce": "await_set_announce",
            "adm_set_owner": "await_set_owner",
            "adm_set_footer_text": "await_set_footer",
            "adm_set_welcome_text": "await_set_welcome",
            "adm_set_rules_text": "await_set_rules",
        }
        USER_STATES[uid] = {"flow": flows[data]}
        bot.send_message(call.message.chat.id, prompts[data], parse_mode="HTML"); return
    if data == "adm_set_restart_all":
        return render_adm_confirm(call, "adm_set_restart_all", "Restart all running bots")
    if data == "adm_set_restart_all_yes":
        if not is_owner(uid): ack(call, "Owner only"); return
        ack(call, "Restarting\u2026")
        def _rb():
            ok = fail = 0
            for bid in list(RUNNING.keys()):
                b = find_bot(bid)
                if not b: continue
                try:
                    r = restart_child(b)
                    if r.get("ok"): ok += 1
                    else: fail += 1
                except Exception: fail += 1
            audit(uid, "restart_all_bots", f"ok={ok} fail={fail}")
            try: bot.send_message(uid, f"{G['ok']} Restart-all done: {ok} ok, {fail} fail.")
            except Exception: pass
        threading.Thread(target=_rb, daemon=True).start(); return
    if data == "adm_set_stop_all":
        return render_adm_confirm(call, "adm_set_stop_all", "Turn off all bots? They will stop replying until you start them again. Nothing will be deleted.")
    if data == "adm_set_stop_all_yes":
        if not is_owner(uid): ack(call, "Owner only"); return
        ack(call, "Turning off…")
        def _sb():
            n = _do_stop_all_bots(uid)
            try: bot.send_message(uid, f"{G['ok']} All bots are now off ({n}). Nothing is deleted. Start them again when ready.")
            except Exception: pass
        threading.Thread(target=_sb, daemon=True).start(); return
    if data == "adm_set_clean_orphans":
        if not is_admin(uid): ack(call, "No permission"); return
        ack(call, "Scanning\u2026")
        def _co():
            valid_ids = set(db_load()["bots"].keys())
            valid_keys = {f"{b.get('owner')}_{b['_id']}" for b in db_load()["bots"].values()}
            dirs = files = 0
            sx = BASE_DIR / "sandbox"
            if sx.exists():
                for e in sx.iterdir():
                    if e.is_dir() and e.name not in valid_keys:
                        try: shutil.rmtree(e, ignore_errors=True); dirs += 1
                        except Exception: pass
            bd = BASE_DIR / "storage" / "bot_data"
            if bd.exists():
                for f in bd.iterdir():
                    if f.is_file() and f.suffix == ".json" and f.stem not in valid_ids:
                        try: f.unlink(); files += 1
                        except Exception: pass
            audit(uid, "clean_orphans", f"sandboxes={dirs} files={files}")
            try: bot.send_message(uid, f"{G['ok']} Cleaned: {dirs} sandbox(es), {files} orphan file(s).")
            except Exception: pass
        threading.Thread(target=_co, daemon=True).start(); return
    if data == "adm_set_export":
        if not is_owner(uid): ack(call, "Owner only"); return
        ack(call, "Packing\u2026")
        def _ex():
            try:
                out = BASE_DIR / "exports"
                out.mkdir(exist_ok=True)
                stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                target = out / f"simran_export_{stamp}.zip"
                with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
                    for name in ("user_data.json", "settings.json", "audit.log"):
                        p = BASE_DIR / "storage" / name
                        if p.exists(): zf.write(p, arcname=name)
                audit(uid, "export_data", f"file={target.name}")
                with target.open("rb") as fh:
                    bot.send_document(uid, fh,
                        caption=f"{G['ok']} Export ({target.stat().st_size // 1024} KB)")
            except Exception as e:
                try: bot.send_message(uid, f"{G['no']} Export error: <code>{esc(e)}</code>", parse_mode="HTML")
                except Exception: pass
        threading.Thread(target=_ex, daemon=True).start(); return

    # Photo replacement
    if data.startswith("adm_photo_"):
        if not is_owner(uid) and not admin_can(uid, "manage_admins"):
            ack(call, "Owner / full-access only."); return
        key = data[len("adm_photo_"):]
        if key not in _PHOTO_SPECS: ack(call, "Unknown photo key"); return
        USER_STATES[uid] = {"flow": "await_menu_photo", "photo_key": key}
        label = PHOTO_KEYS_FRIENDLY.get(key, key)
        bot.send_message(call.message.chat.id,
            f"{G['upload']} {sc('Send the new photo for')} <b>{esc(label)}</b> {sc('now')}.\n/cancel {sc('to abort')}.",
            parse_mode="HTML"); return

    # Mega advanced panels from base file (call via function names)
    _ADVANCED_PANEL_MAP = {
        "adm_analytics":     "render_adm_analytics",
        "adm_user_tools":    "render_adm_user_tools",
        "adm_bot_manager":   "render_adm_bot_manager",
        "adm_sec_center":    "render_adm_sec_center",
        "adm_notify_center": "render_adm_notify_center",
        "adm_sys_tools":     "render_adm_sys_tools",
        "adm_pay_config":    "render_adm_pay_config",
        "adm_bot_cfg":       "render_adm_bot_cfg",
        "adm_appearance":    "render_adm_appearance",
        "adm_coupon_plus":   "render_adm_coupon_plus",
        "adm_templates":     "render_adm_templates",
        "adm_referral_sys":  "render_adm_referral_sys",
        "adm_janitor":       "render_adm_janitor",
        "adm_webhooks":      "render_adm_webhooks",
        "adm_feature_flags": "render_adm_feature_flags",
        "adm_rate_config":   "render_adm_rate_config",
        "adm_live_monitor":  "render_adm_live_monitor",
        "adm_rev_goals":     "render_adm_rev_goals",
        "adm_scheduler":     "render_adm_scheduler",
        "adm_import_export": "render_adm_export_menu",
        "adm_leaderboard":   "render_adm_leaderboard",
        "adm_languages":     "render_adm_languages",
        "adm_bot_controls":  "render_adm_bot_controls",
        "adm_subscriptions": "render_adm_subscriptions",
        "adm_admin_2fa":     "render_adm_admin_2fa",
        "adm_revenue_report":"render_adm_revenue_report",
        "adm_growth_stats":  "render_adm_growth_stats",
        "adm_top_users":     "render_adm_top_users",
        "adm_plan_dist":     "render_adm_plan_dist",
        "adm_bot_activity":  "render_adm_bot_activity",
        "adm_user_search":   "render_adm_user_search",
        "adm_banned_list":   "render_adm_banned_list",
        "adm_wallet_admin":  "render_adm_wallet_admin",
        "adm_user_export_csv": "render_adm_user_export_csv",
        "adm_notify_user":   "render_adm_notify_user",
        "adm_user_reset":    "render_adm_user_reset_prompt",
        "adm_crashed_bots":  "render_adm_crashed_bots",
        "adm_bot_search":    "render_adm_bot_search",
        "adm_bot_size_report":"render_adm_bot_size_report",
        "adm_force_scan_all":"action_adm_force_scan_all",
        "adm_threat_log":    "render_adm_threat_log",
        "adm_sec_stats":     "render_adm_sec_stats",
        "adm_sec_whitelist": "render_adm_sec_whitelist_prompt",
        "adm_scan_report":   "render_adm_scan_report",
        "adm_sec_blacklist": "render_adm_sec_blacklist",
        "adm_notify_all":    "render_adm_notify_all",
        "adm_notify_running":"render_adm_notify_running",
        "adm_schedule_msg":  "render_adm_schedule_msg",
        "adm_quick_announce":"render_adm_quick_announce",
        "adm_sys_health":    "render_adm_sys_health",
        "adm_disk_usage":    "render_adm_disk_usage",
        "adm_db_info":       "render_adm_db_info",
        "adm_token_check":   "render_adm_token_check",
        "adm_security_log":  "render_adm_security_log" if "render_adm_security_log" in dir() else None,
    }
    # sub-callbacks
    if data == "adm_mass_restart_stopped":
        fn = globals().get("render_adm_mass_restart_stopped")
        if fn: fn(call); return
    if data == "adm_mass_restart_stopped_yes":
        fn = globals().get("action_adm_mass_restart_stopped")
        if fn: fn(call); return
    if data == "adm_kill_all_now":
        return render_adm_confirm_custom(call, "adm_kill_all_now_yes", "Kill ALL running bots immediately", "adm_bot_manager")
    if data == "adm_kill_all_now_yes":
        fn = globals().get("action_adm_kill_all")
        if fn: fn(call); return
    if data.startswith("adm_notify_plan_"):
        fn = globals().get("render_adm_notify_plan")
        if fn: fn(call, data[len("adm_notify_plan_"):]); return
    if data == "adm_notify_plan_select":
        fn = globals().get("render_adm_notify_plan_select")
        if fn: fn(call); return
    if data == "adm_clear_cache":
        cache_clear_all()
        audit(uid, "clear_cache", "manual")
        ack(call, "Caches cleared!")
        fn = globals().get("render_adm_sys_tools")
        if fn: fn(call)
        return

    if data in _ADVANCED_PANEL_MAP:
        fn_name = _ADVANCED_PANEL_MAP[data]
        if fn_name:
            fn = globals().get(fn_name)
            if fn: fn(call); return
        ack(call, "?"); return

    # delegate to _register_extra_routes from new file
    if not _register_extra_routes(data, call):
        ack(call, "?")


def render_github_subroute(call: types.CallbackQuery, data: str) -> None:
    uid = call.from_user.id
    if data == "gh_set_token":
        if not is_owner(uid): ack(call, "Owner only"); return
        USER_STATES[uid] = {"flow": "await_gh_token"}
        bot.send_message(call.message.chat.id,
            f"{G['key']} {sc('Send your GitHub personal access token')} (repo scope).",
            parse_mode="HTML"); return
    if data == "gh_set_repo":
        if not is_owner(uid): ack(call, "Owner only"); return
        USER_STATES[uid] = {"flow": "await_gh_repo"}
        bot.send_message(call.message.chat.id,
            f"{G['cog']} Send repo as <code>user/repo</code>.", parse_mode="HTML"); return
    if data == "gh_set_branch":
        if not is_owner(uid): ack(call, "Owner only"); return
        USER_STATES[uid] = {"flow": "await_gh_branch"}
        bot.send_message(call.message.chat.id,
            f"{G['cog']} Send branch name (e.g. <code>main</code>).", parse_mode="HTML"); return
    if data == "gh_set_interval":
        if not is_owner(uid): ack(call, "Owner only"); return
        USER_STATES[uid] = {"flow": "await_gh_interval"}
        bot.send_message(call.message.chat.id,
            f"{G['cog']} Send backup interval in minutes (min 15).", parse_mode="HTML"); return
    if data == "gh_toggle_auto":
        if not is_owner(uid): ack(call, "Owner only"); return
        cur = bool(get_setting("github_auto_enabled", True))
        set_setting("github_auto_enabled", not cur)
        GH["autoEnabled"] = not cur
        audit(uid, "gh_auto_toggle", f"now={'on' if not cur else 'off'}")
        ack(call, f"GitHub auto: {'ON' if not cur else 'OFF'}")
        return render_adm_github(call)
    if data == "gh_backup_now":
        ack(call, "Backing up\u2026")
        def _bg():
            try:
                res = gh_backup_now()
                bot.send_message(uid,
                    f"<b>{'OK' if res.get('ok') else G['no']} GitHub Backup</b>\n"
                    f"{bullet('Size', fmt_bytes(res.get('sizeBytes', 0)))}\n"
                    f"{bullet('Error', res.get('error', '') or 'none')}", parse_mode="HTML")
            except Exception as e:
                bot.send_message(uid, f"{G['no']} {esc(e)}", parse_mode="HTML")
        threading.Thread(target=_bg, daemon=True).start(); return
    if data == "gh_restore_now":
        if not is_owner(uid): ack(call, "Owner only"); return
        ack(call, "Restoring\u2026")
        def _rg():
            try:
                res = gh_restore_latest()
                bot.send_message(uid,
                    f"<b>{'OK' if res.get('ok') else G['no']} GitHub Restore</b>\n"
                    f"{bullet('Error', res.get('error', '') or 'none')}", parse_mode="HTML")
            except Exception as e:
                bot.send_message(uid, f"{G['no']} {esc(e)}", parse_mode="HTML")
        threading.Thread(target=_rg, daemon=True).start(); return
    ack(call, "?")


# ─── Callback de-duplication ──────────────────────────────────────────────────

_CB_SEEN: "deque" = deque(maxlen=512)
_CB_SEEN_LOCK = threading.Lock()
_CB_DEDUP_WINDOW = 12.0


def _is_duplicate_callback(call_id: str) -> bool:
    if not call_id:
        return False
    now = time.time()
    with _CB_SEEN_LOCK:
        while _CB_SEEN and now - _CB_SEEN[0][1] > _CB_DEDUP_WINDOW:
            _CB_SEEN.popleft()
        for cid, _ in _CB_SEEN:
            if cid == call_id:
                return True
        _CB_SEEN.append((call_id, now))
    return False


# ─── Action helpers used by on_text / on_photo ────────────────────────────────

def _handle_env_kv(m: types.Message, st: Dict[str, Any]) -> None:
    bot_id = st.get("bot_id")
    b = find_bot(bot_id) if bot_id else None
    if not b or (b["owner"] != m.from_user.id and not is_admin(m.from_user.id)):
        bot.reply_to(m, f"{G['no']} bot not found"); USER_STATES.pop(m.from_user.id, None); return
    kv = (m.text or "").strip()
    if "=" not in kv:
        bot.reply_to(m, f"{G['no']} Format: <code>KEY=VALUE</code>", parse_mode="HTML"); return
    k, v = kv.split("=", 1)
    k = k.strip().upper()
    if not k:
        bot.reply_to(m, f"{G['no']} empty key"); return
    b.setdefault("env", {})[k] = v.strip()
    save_bot(b)
    audit(m.from_user.id, "env_set", f"bot={bot_id} key={k}")
    USER_STATES.pop(m.from_user.id, None)
    bot.reply_to(m, f"{G['ok']} <code>{esc(k)}</code> saved.", parse_mode="HTML")


def _handle_pip_install(m: types.Message, st: Dict[str, Any]) -> None:
    bot_id = st.get("bot_id")
    b = find_bot(bot_id) if bot_id else None
    if not b:
        bot.reply_to(m, f"{G['no']} bot not found"); USER_STATES.pop(m.from_user.id, None); return
    packages = (m.text or "").strip().split()
    if not packages:
        bot.reply_to(m, f"{G['no']} no packages"); USER_STATES.pop(m.from_user.id, None); return
    USER_STATES.pop(m.from_user.id, None)
    bot.reply_to(m, f"\u23f3 Installing {' '.join(packages[:5])}\u2026")
    def _bg():
        import subprocess as _sp
        try:
            bot_dir = Path(b.get("dir", ""))
            bot_dir.mkdir(parents=True, exist_ok=True)
            venv_pip = bot_dir / "venv" / "bin" / "pip"
            pip_cmd = str(venv_pip) if venv_pip.exists() else "pip"
            result = _sp.run([pip_cmd, "install"] + packages[:10],
                             capture_output=True, text=True, timeout=120)
            out = (result.stdout + result.stderr)[-1500:]
            ok = result.returncode == 0
            audit(m.from_user.id, "pip_install", f"bot={bot_id} ok={ok}")
            bot.send_message(m.chat.id,
                f"<b>{'OK' if ok else G['no']} pip install</b>\n<pre>{esc(out)}</pre>",
                parse_mode="HTML")
        except Exception as e:
            bot.send_message(m.chat.id,
                f"{G['no']} pip error: <code>{esc(e)}</code>", parse_mode="HTML")
    threading.Thread(target=_bg, daemon=True).start()


def _handle_tunnel_port(m: types.Message, st: Dict[str, Any]) -> None:
    USER_STATES.pop(m.from_user.id, None)
    try:
        port = int((m.text or "").strip())
    except Exception:
        bot.reply_to(m, f"{G['no']} Invalid port"); return
    bot.reply_to(m, f"\U0001f310 Tunnel on port {port} \u2014 ngrok/cloudflared must be installed on the server.")


def _handle_cron(m: types.Message, st: Dict[str, Any]) -> None:
    bot_id = st.get("bot_id")
    b = find_bot(bot_id) if bot_id else None
    if not b or (b["owner"] != m.from_user.id and not is_admin(m.from_user.id)):
        bot.reply_to(m, f"{G['no']} bot not found"); USER_STATES.pop(m.from_user.id, None); return
    parts = (m.text or "").strip().split()
    if len(parts) >= 2 and parts[0] in ("restart_hours", "backup_hours"):
        try:
            val = max(0, int(parts[1]))
        except Exception:
            bot.reply_to(m, f"{G['no']} bad number"); return
        b.setdefault("cron", {})[parts[0]] = val
        save_bot(b)
        audit(m.from_user.id, "cron_set", f"bot={bot_id} {parts[0]}={val}")
        USER_STATES.pop(m.from_user.id, None)
        bot.reply_to(m, f"{G['ok']} Saved: <code>{parts[0]} = {val}</code>", parse_mode="HTML")
    else:
        bot.reply_to(m, f"{G['no']} Use: <code>restart_hours N</code> or <code>backup_hours N</code>",
                     parse_mode="HTML")


def _handle_admin_finduser(m: types.Message) -> None:
    USER_STATES.pop(m.from_user.id, None)
    try:
        target_uid = int(m.text.strip())
    except Exception:
        bot.reply_to(m, f"{G['no']} bad uid"); return
    d = db_load()
    u = d["users"].get(str(target_uid))
    if not u:
        bot.reply_to(m, f"{G['no']} user not found"); return
    bots = [b for b in d["bots"].values() if str(b.get("owner")) == str(target_uid)]
    cap = (
        f"<b>{G['user']} User Info</b>\n{G['div_eq']}\n"
        f"{bullet('ID', target_uid)}\n"
        f"{bullet('Name', u.get('name', '—'))}\n"
        f"{bullet('Username', '@' + (u.get('username') or '—'))}\n"
        f"{bullet('Plan', u.get('plan', 'free'))}\n"
        f"{bullet('Joined', fmt_ts(u.get('joined')))}\n"
        f"{bullet('Bots', len(bots))}\n"
        f"{bullet('Wallet', '{}$'.format(u.get('wallet', 0)))}\n"
        f"{bullet('Banned', u.get('banned', False))}\n"
        f"{bullet('Verified', 'Yes' if u.get('verified') else 'No')}\n"
        f"{G['div']}{FOOTER}"
    )
    bot.reply_to(m, cap, parse_mode="HTML")


def _handle_ban_cmd(m: types.Message) -> None:
    USER_STATES.pop(m.from_user.id, None)
    parts = (m.text or "").split(None, 2)
    if not parts: return
    op = parts[0].lower()
    d = db_load()
    if op == "ban" and len(parts) >= 2:
        try: uid = int(parts[1])
        except Exception: bot.reply_to(m, f"{G['no']} bad uid"); return
        reason = parts[2] if len(parts) >= 3 else "banned by admin"
        u = d["users"].get(str(uid))
        if not u: bot.reply_to(m, f"{G['no']} user not found"); return
        u["banned"] = True
        u["ban_reason"] = reason
        db_save(d)
        for b in list(d["bots"].values()):
            if str(b.get("owner")) == str(uid):
                try: stop_child(b["_id"], manual=True)
                except Exception: pass
        audit(m.from_user.id, "ban_user", f"uid={uid}")
        bot.reply_to(m, f"{G['ok']} banned {uid}")
    elif op == "unban" and len(parts) >= 2:
        try: uid = int(parts[1])
        except Exception: bot.reply_to(m, f"{G['no']} bad uid"); return
        u = d["users"].get(str(uid))
        if not u: bot.reply_to(m, f"{G['no']} user not found"); return
        u["banned"] = False
        u["ban_reason"] = ""
        db_save(d)
        audit(m.from_user.id, "unban_user", f"uid={uid}")
        bot.reply_to(m, f"{G['ok']} unbanned {uid}")


def _handle_giveplan_cmd(m: types.Message) -> None:
    USER_STATES.pop(m.from_user.id, None)
    parts = (m.text or "").split()
    if len(parts) < 2:
        bot.reply_to(m, f"{G['no']} Format: <code>uid plan [days]</code>", parse_mode="HTML"); return
    try:
        uid = int(parts[0])
        plan = parts[1]
        days = int(parts[2]) if len(parts) >= 3 else None
    except Exception:
        bot.reply_to(m, f"{G['no']} bad args"); return
    if plan not in PLAN_LIMITS:
        bot.reply_to(m, f"{G['no']} Unknown plan: {plan}"); return
    ok = grant_plan(uid, plan, days=days)
    audit(m.from_user.id, "give_plan", f"uid={uid} plan={plan} days={days}")
    bot.reply_to(m, f"{G['ok']} given {plan} to {uid}" if ok else f"{G['no']} user not found")


def _handle_broadcast(m: types.Message) -> None:
    if not is_admin(m.from_user.id):
        USER_STATES.pop(m.from_user.id, None); return
    text = (m.text or "").strip()
    USER_STATES.pop(m.from_user.id, None)
    plan_filter: Optional[str] = None
    scheduled_at: Optional[str] = None
    if text.startswith("plan:"):
        parts = text.split(None, 1)
        plan_filter = parts[0][5:]
        text = parts[1] if len(parts) > 1 else ""
    elif text.startswith("at:"):
        parts = text.split(None, 1)
        try:
            scheduled_at = parts[0][3:].strip()
            text = parts[1] if len(parts) > 1 else ""
        except Exception:
            pass
    if not text:
        bot.reply_to(m, f"{G['no']} empty message"); return
    if scheduled_at:
        try:
            when = datetime.strptime(scheduled_at, "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
        except Exception:
            bot.reply_to(m, f"{G['no']} bad datetime format (use YYYY-MM-DD HH:MM)"); return
        d = db_load()
        d.setdefault("scheduled_broadcasts", []).append({
            "text": text, "plan": plan_filter, "at": when.isoformat(), "by": m.from_user.id,
        })
        db_save(d)
        audit(m.from_user.id, "broadcast_scheduled", f"at={scheduled_at}")
        bot.reply_to(m, f"{G['ok']} Scheduled for {scheduled_at}")
        return
    bot.reply_to(m, f"\u23f3 Broadcasting\u2026")
    def _bg():
        users = db_load()["users"]
        sent = fail = 0
        for uid_str, u in users.items():
            if u.get("banned"): continue
            if plan_filter and u.get("plan") != plan_filter: continue
            try:
                bot.send_message(int(uid_str),
                    f"<b>\U0001f4e2 {BRAND_TAG}</b>\n{G['div']}\n{esc(text)}",
                    parse_mode="HTML", disable_web_page_preview=True)
                sent += 1
            except Exception: fail += 1
            time.sleep(0.05)
        audit(m.from_user.id, "broadcast_sent", f"sent={sent} fail={fail}")
        try: bot.send_message(m.from_user.id, f"{G['ok']} Broadcast done: {sent} sent, {fail} fail.")
        except Exception: pass
    threading.Thread(target=_bg, daemon=True).start()


def _handle_coupon_user(m: types.Message) -> None:
    code = (m.text or "").strip().upper()
    USER_STATES.pop(m.from_user.id, None)
    d = db_load()
    c = d["coupons"].get(code)
    if not c:
        bot.reply_to(m, f"{G['no']} Invalid code"); return
    if int(c.get("uses_left", 0)) <= 0:
        bot.reply_to(m, f"{G['no']} Code expired"); return
    c["uses_left"] = int(c.get("uses_left", 0)) - 1
    pct = int(c.get("percent", 0))
    d["users"].get(str(m.from_user.id), {}).setdefault("coupons_used", []).append(code)
    db_save(d)
    audit(m.from_user.id, "coupon_redeem", f"code={code} pct={pct}")
    bot.reply_to(m,
        f"<b>{G['ok']} Coupon applied</b>: <code>{esc(code)}</code>\n"
        f"{bullet('Discount', f'{pct}% off next plan purchase')}",
        parse_mode="HTML")


def _handle_coupon_admin(m: types.Message) -> None:
    if not is_admin(m.from_user.id):
        USER_STATES.pop(m.from_user.id, None); return
    parts = (m.text or "").strip().split()
    if not parts: return
    op = parts[0].lower()
    d = db_load()
    if op == "add" and len(parts) >= 4:
        code = parts[1].upper()
        try:
            pct = int(parts[2])
            uses = int(parts[3])
        except Exception:
            bot.reply_to(m, f"{G['no']} bad numbers"); return
        d["coupons"][code] = {"percent": pct, "uses_left": uses, "created": ts_iso()}
        db_save(d)
        audit(m.from_user.id, "coupon_add", f"code={code}")
        USER_STATES.pop(m.from_user.id, None)
        bot.reply_to(m, f"{G['ok']} created {code}")
    elif op == "del" and len(parts) >= 2:
        code = parts[1].upper()
        if d["coupons"].pop(code, None):
            db_save(d)
            audit(m.from_user.id, "coupon_del", f"code={code}")
            USER_STATES.pop(m.from_user.id, None)
            bot.reply_to(m, f"{G['ok']} removed {code}")
        else:
            bot.reply_to(m, f"{G['no']} code not found")
    else:
        bot.reply_to(m, f"{G['no']} Use: <code>add CODE PCT USES</code> or <code>del CODE</code>",
                     parse_mode="HTML")


def _handle_admin_admins(m: types.Message) -> None:
    if not is_owner(m.from_user.id):
        return
    USER_STATES.pop(m.from_user.id, None)
    parts = m.text.split()
    if len(parts) < 2: return
    op = parts[0].lower()
    d = db_load()
    if op == "add" and len(parts) >= 3:
        try: uid = int(parts[1])
        except Exception: bot.reply_to(m, f"{G['no']} bad uid"); return
        role = parts[2]
        if role not in {"view-only", "manage-users", "full-access"}:
            bot.reply_to(m, f"{G['no']} bad role"); return
        d["admins"][str(uid)] = {"role": role, "added": ts_iso(), "by": m.from_user.id}
        db_save(d)
        audit(m.from_user.id, "admin_add", f"uid={uid} role={role}")
        bot.reply_to(m, f"{G['ok']} added admin {uid} ({role})")
    elif op == "del" and len(parts) >= 2:
        try: uid = int(parts[1])
        except Exception: bot.reply_to(m, f"{G['no']} bad uid"); return
        if d["admins"].pop(str(uid), None):
            db_save(d)
            audit(m.from_user.id, "admin_del", f"uid={uid}")
            bot.reply_to(m, f"{G['ok']} removed {uid}")


def _handle_ticket_subject(m: types.Message) -> None:
    USER_STATES[m.from_user.id] = {"flow": "await_ticket_body", "subject": m.text.strip()[:120]}
    bot.reply_to(m, f"{G['ticket']} Now send the ticket body (describe your issue).")


def _handle_ticket_body(m: types.Message, st: Dict[str, Any]) -> None:
    subject = st.get("subject") or "Support"
    d = db_load()
    tid = rand_token(6)
    d["tickets"][tid] = {
        "id": tid, "uid": m.from_user.id, "subject": subject, "status": "open",
        "messages": [{"from": "user", "text": m.text, "ts": ts_iso()}],
        "opened_at": ts_iso(),
    }
    db_save(d)
    USER_STATES.pop(m.from_user.id, None)
    bot.reply_to(m, f"<b>{G['ok']} Ticket opened #{tid}</b>", parse_mode="HTML")
    notify_owner(
        f"<b>{G['ticket']} New Ticket #{tid}</b>\n"
        f"{bullet('From', m.from_user.id)}\n"
        f"{bullet('Subject', subject)}\n"
        f"{bullet('Body', m.text[:400])}"
    )
    pg = get_setting("private_approval_group", None)
    if pg:
        try:
            bot.send_message(pg,
                f"<b>{G['ticket']} New Support Ticket #{tid}</b>\n"
                f"{bullet('From', m.from_user.id)}\n"
                f"{bullet('Subject', subject)}\n"
                f"{esc(m.text[:300])}",
                parse_mode="HTML")
        except Exception:
            pass


def _handle_ticket_reply(m: types.Message, st: Dict[str, Any]) -> None:
    tid = st.get("tid")
    d = db_load()
    t = d["tickets"].get(tid)
    if not t:
        USER_STATES.pop(m.from_user.id, None); return
    if t["uid"] != m.from_user.id and not is_admin(m.from_user.id):
        USER_STATES.pop(m.from_user.id, None); return
    who = "admin" if is_admin(m.from_user.id) and t["uid"] != m.from_user.id else "user"
    t.setdefault("messages", []).append({"from": who, "text": m.text, "ts": ts_iso()})
    db_save(d)
    USER_STATES.pop(m.from_user.id, None)
    target = OWNER_ID if who == "user" else t["uid"]
    try:
        bot.send_message(target,
            f"<b>{G['ticket']} Ticket #{tid}</b> \u2014 {who} replied\n{esc(m.text)[:1000]}",
            parse_mode="HTML")
    except Exception:
        pass
    bot.reply_to(m, f"{G['ok']} reply sent")


def _handle_payment_proof(m: types.Message, st: Dict[str, Any]) -> None:
    method = st.get("method") or "unknown"
    plan   = st.get("plan")
    p = PLAN_LIMITS.get(plan or "")
    pid = rand_token(8)
    d = db_load()
    d["payments"].append({
        "id": pid, "uid": m.from_user.id, "method": method, "plan": plan,
        "amount": (p or {}).get("price", 0),
        "status": "pending", "ts": ts_iso(), "telegram_msg_id": m.message_id,
    })
    db_save(d)
    USER_STATES.pop(m.from_user.id, None)
    try: bot.forward_message(OWNER_ID, m.chat.id, m.message_id)
    except Exception: pass
    kb = types.InlineKeyboardMarkup()
    kb.add(
        Btn(f"{G['ok']}  Approve", callback_data=f"payapprove_{pid}"),
        Btn(f"{G['no']}  Reject",  callback_data=f"payreject_{pid}"),
    )
    notify_owner(
        f"<b>{G['wallet']} New Payment Proof</b>\n"
        f"{bullet('ID', pid)}\n{bullet('From', m.from_user.id)}\n"
        f"{bullet('Method', method)}\n{bullet('Plan', plan or '—')}\n"
        f"{bullet('Amount', '{}$'.format((p or {}).get('price', 0)))}"
    )
    try: bot.send_message(OWNER_ID, f"<b>Decide #{pid}</b>", parse_mode="HTML", reply_markup=kb)
    except Exception: pass
    pg = get_setting("private_approval_group", None)
    if pg:
        try:
            bot.forward_message(pg, m.chat.id, m.message_id)
            bot.send_message(pg, f"<b>Payment Proof #{pid}</b>", parse_mode="HTML", reply_markup=kb)
        except Exception: pass
    bot.reply_to(m, f"<b>{G['ok']} Proof received</b> #{pid} \u2014 await admin.", parse_mode="HTML")


def _handle_payment_proof_text(m: types.Message, st: Dict[str, Any]) -> None:
    _handle_payment_proof(m, st)


def _handle_topup_proof(m: types.Message) -> None:
    pid = rand_token(8)
    cap = (m.caption or m.text or "").strip()
    amt = 0
    ms = re.search(r"\d+", cap)
    if ms:
        amt = int(ms.group(0))
    d = db_load()
    d["payments"].append({
        "id": pid, "uid": m.from_user.id, "method": "topup", "plan": None,
        "amount": amt, "status": "pending", "ts": ts_iso(), "kind": "wallet_topup",
    })
    db_save(d)
    USER_STATES.pop(m.from_user.id, None)
    try: bot.forward_message(OWNER_ID, m.chat.id, m.message_id)
    except Exception: pass
    kb = types.InlineKeyboardMarkup()
    kb.add(
        Btn(f"{G['ok']}  Approve", callback_data=f"payapprove_{pid}"),
        Btn(f"{G['no']}  Reject",  callback_data=f"payreject_{pid}"),
    )
    notify_owner(
        f"<b>{G['wallet']} Wallet Top-up</b>\n"
        f"{bullet('ID', pid)}\n{bullet('From', m.from_user.id)}\n"
        f"{bullet('Amount', '{}$'.format(amt))}"
    )
    try: bot.send_message(OWNER_ID, f"<b>Decide #{pid}</b>", parse_mode="HTML", reply_markup=kb)
    except Exception: pass
    bot.reply_to(m, f"<b>{G['ok']} Top-up proof received</b>", parse_mode="HTML")


def _handle_gift_target(m: types.Message, st: Dict[str, Any]) -> None:
    try: tgt = int(m.text.strip())
    except Exception: bot.reply_to(m, f"{G['no']} bad uid"); return
    d = db_load()
    if str(tgt) not in d["users"]:
        bot.reply_to(m, f"{G['no']} user not found"); return
    USER_STATES[m.from_user.id] = {"flow": "await_gift_confirm", "target": tgt}
    bot.reply_to(m,
        f"<b>{G['warn']} Confirm gift</b>\n{bullet('To', tgt)}\nSend <code>YES</code> to confirm.",
        parse_mode="HTML")


def _handle_gift_confirm(m: types.Message, st: Dict[str, Any]) -> None:
    USER_STATES.pop(m.from_user.id, None)
    if (m.text or "").strip().upper() != "YES":
        bot.reply_to(m, f"{G['no']} cancelled"); return
    tgt = int(st["target"])
    d = db_load()
    me = d["users"][str(m.from_user.id)]
    if me.get("plan") in ("free", None):
        bot.reply_to(m, f"{G['no']} no active plan to gift"); return
    plan = me["plan"]
    exp = me.get("plan_expires")
    me["plan"] = "free"
    me["plan_expires"] = None
    if str(tgt) in d["users"]:
        d["users"][str(tgt)]["plan"] = plan
        d["users"][str(tgt)]["plan_expires"] = exp
    db_save(d)
    audit(m.from_user.id, "plan_gift", f"to={tgt} plan={plan}")
    bot.reply_to(m, f"{G['ok']} plan gifted to {tgt}")
    try:
        bot.send_message(tgt,
            f"<b>{G['spark']} You received a gift plan</b>\n"
            f"{bullet('Plan', PLAN_LIMITS.get(plan, {}).get('name', plan))}",
            parse_mode="HTML")
    except Exception: pass


# ═══════════════════════════════════════════════════════════════════════════════
# REGISTERED BOT HANDLERS
# ═══════════════════════════════════════════════════════════════════════════════

@bot.callback_query_handler(func=lambda c: c.data == "group_verify_check")
def cb_group_verify(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    chat_id = call.message.chat.id
    not_joined = _check_group_membership(uid)
    if not_joined:
        ack(call, "You have not joined all groups yet!")
        try: bot.delete_message(chat_id, call.message.message_id)
        except Exception: pass
        _send_join_verification(chat_id, uid, not_joined)
    else:
        ack(call, "\u2713 Verified! Welcome.")
        try: bot.delete_message(chat_id, call.message.message_id)
        except Exception: pass
        render_main_menu(chat_id, uid)


@bot.callback_query_handler(func=lambda c: bool(c.data) and c.data.startswith("verify_"))
def cb_verify(call: types.CallbackQuery) -> None:
    uid = call.from_user.id
    chat_id = call.message.chat.id
    data = call.data[len("verify_"):]
    if data == "new":
        with _verify_lock:
            st = VERIFY_STATES.get(uid)
            if st and st.get("regens", 0) >= 5:
                ack(call, "Too many regenerations."); return
        try: bot.delete_message(chat_id, call.message.message_id)
        except Exception: pass
        ack(call, "New captcha\u2026")
        _send_captcha(chat_id, uid)
        with _verify_lock:
            if uid in VERIFY_STATES:
                VERIFY_STATES[uid]["regens"] = VERIFY_STATES[uid].get("regens", 0) + 1
        return
    with _verify_lock:
        state = VERIFY_STATES.get(uid)
    if not state:
        ack(call, "Session expired \u2014 send /start again."); return
    if data == state["answer"]:
        with _verify_lock:
            VERIFY_STATES.pop(uid, None)
        _mark_verified(uid)
        ack(call, "\u2713 Verified")
        try: bot.delete_message(chat_id, state["msg_id"])
        except Exception: pass
        try: audit(uid, "captcha_pass", f"tries={state.get('tries', 0)}")
        except Exception: pass
        render_main_menu(chat_id, uid,
            intro=f"<b>{G['ok']} Verification complete</b> \u2014 welcome, <b>{esc(call.from_user.first_name or 'friend')}</b>!")
        return
    state["tries"] = state.get("tries", 0) + 1
    left = max(0, 3 - state["tries"])
    if state["tries"] >= 3:
        with _verify_lock:
            VERIFY_STATES.pop(uid, None)
        try: bot.delete_message(chat_id, state["msg_id"])
        except Exception: pass
        ack(call, "Wrong 3 times \u2014 new captcha.")
        _send_captcha(chat_id, uid)
    else:
        ack(call, f"Wrong. {left} try(s) left.")


@bot.callback_query_handler(func=lambda c: True)
def cb_root(call: types.CallbackQuery) -> None:
    if _is_duplicate_callback(getattr(call, "id", "")):
        try: bot.answer_callback_query(call.id)
        except Exception: pass
        return
    uid = call.from_user.id
    if not RATE.allow(uid):
        ack(call, "Slow down.")
        maybe_auto_ban(uid, "callback rate")
        return
    if banned_block(call):
        ack(call); return
    get_or_create_user(call.from_user)
    if maintenance_block(uid):
        ack(call, "Maintenance mode"); return
    if not _is_verified(uid):
        ack(call, "Please solve the captcha first \u2014 send /start."); return
    data = call.data or ""
    try:
        _route_callback(call, data)
    except Exception as e:
        traceback.print_exc()
        try:
            bot.send_message(call.message.chat.id,
                f"<b>{G['no']}</b> Error: <code>{esc(e)}</code>")
        except Exception:
            pass


def _route_callback(call: types.CallbackQuery, data: str) -> None:
    # Trace every callback to disk so Admin taps leave evidence even if send fails.
    try:
        _td = DIRS.get("logs", BASE_DIR / "storage" / "logs")
        _td.mkdir(parents=True, exist_ok=True)
        with open(_td / "callback.log", "a", encoding="utf-8") as _lf:
            _lf.write(f"{ts_iso()} uid={getattr(call.from_user, 'id', '?')} data={data} ct={getattr(getattr(call, 'message', None), 'content_type', '?')}\n")
    except Exception:
        pass
    # Core menus
    if data == "menu_main":     ack(call); render_main_menu(call.message.chat.id, call.from_user.id, call); return
    if data == "menu_bots":     ack(call); render_bots_menu(call); return
    if data == "menu_upload":   ack(call); render_upload_menu(call); return
    if data == "menu_plans":    ack(call); render_plans_menu(call); return
    if data == "menu_buy":      ack(call); render_buy_menu(call); return
    if data == "menu_profile":  ack(call); render_profile(call); return
    if data == "menu_referral": ack(call); render_referral(call); return
    if data == "menu_wallet":   ack(call); render_wallet(call); return
    if data == "menu_help":     ack(call); render_help(call); return
    if data == "menu_support":  ack(call); render_support(call); return
    if data == "menu_tickets":  ack(call); render_user_tickets(call); return
    if data == "menu_trial":    ack(call); render_trial(call); return
    if data == "menu_coupon":   ack(call); render_coupon(call); return
    if data == "menu_stats":    ack(call); render_user_stats(call); return
    if data == "menu_admin":    ack(call); render_admin(call); return
    if data == "menu_gh_host":  ack(call); render_gh_repo_host_menu(call); return
    # Plans
    if data.startswith("plan_view_"): ack(call); render_plan_detail(call, data.split("_", 2)[2]); return
    if data.startswith("plan_buy_"):  ack(call); render_payment_methods_for(call, data.split("_", 2)[2]); return
    # Payment
    if data.startswith("pay_") and data != "pay_proof": ack(call); render_payment_screen(call, data); return
    if data == "pay_proof": ack(call); start_proof_flow(call); return
    # Bot actions
    if data.startswith("bot_view_"):        ack(call); render_bot_view(call, data.split("_", 2)[2]); return
    if data.startswith("bot_start_"):       ack(call); action_bot_start(call, data.split("_", 2)[2]); return
    if data.startswith("bot_stop_"):        ack(call); action_bot_stop(call, data.split("_", 2)[2]); return
    if data.startswith("bot_restart_"):     ack(call); action_bot_restart(call, data.split("_", 2)[2]); return
    if data.startswith("bot_logs_"):        ack(call); action_bot_logs(call, data.split("_", 2)[2]); return
    if data.startswith("bot_info_"):        ack(call); action_bot_info(call, data.split("_", 2)[2]); return
    if data.startswith("bot_env_"):         ack(call); render_env_menu(call, data.split("_", 2)[2]); return
    if data.startswith("env_add_"):         ack(call); start_env_add(call, data.split("_", 2)[2]); return
    if data.startswith("env_del_"):
        parts = data.split("_", 3)
        if len(parts) >= 4: ack(call); action_env_delete(call, parts[2], parts[3]); return
    if data.startswith("bot_cron_"):        ack(call); render_cron(call, data.split("_", 2)[2]); return
    if data.startswith("bot_clone_"):       ack(call); action_bot_clone(call, data.split("_", 2)[2]); return
    if data.startswith("bot_dl_"):          ack(call); action_bot_download(call, data.split("_", 2)[2]); return
    if data.startswith("bot_pip_"):         ack(call); start_pip_install_flow(call, data.split("_", 2)[2]); return
    if data.startswith("bot_tunnel_"):      ack(call); start_tunnel_flow(call, data.split("_", 2)[2]); return
    if data.startswith("bot_delete_"):      ack(call); render_bot_delete_confirm(call, data.split("_", 2)[2]); return
    if data.startswith("bot_delyes_"):      ack(call); action_bot_delete(call, data.split("_", 2)[2]); return
    if data.startswith("bot_delfiles_"):    ack(call); render_bot_delfiles_confirm(call, data.split("_", 2)[2]); return
    if data.startswith("bot_delall_"):      ack(call); render_bot_delall_confirm(call, data.split("_", 2)[2]); return
    if data.startswith("bot_delfilesyes_"): ack(call); action_bot_delfiles(call, data.split("_", 2)[2]); return
    if data.startswith("bot_delalyes_"):    ack(call); action_bot_delall(call, data.split("_", 2)[2]); return
    # GitHub user hosting
    if data == "gh_host_clone":       ack(call); action_gh_host_clone(call); return
    if data == "gh_host_set_token":   ack(call); action_gh_host_set_token(call); return
    if data == "gh_host_list":        ack(call); action_gh_host_list(call); return
    if data == "gh_host_remove_sel":
        ack(call)
        show_text(call.message.chat.id,
            f"<i>{sc('Select a bot from My GitHub Bots to manage and delete from there')}.</i>",
            _adm_back("menu_gh_host"), call=call); return
    # Approval
    if data.startswith("appr_ok_"):
        if not admin_only_call(call, "approve_payment"): return
        bid = data[len("appr_ok_"):]
        res = approve_bot(bid, call.from_user.id)
        ack(call, "Approved" if res.get("ok") else f"Err: {res.get('error')}")
        try: bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=None)
        except Exception: pass
        return
    if data.startswith("appr_no_"):
        if not admin_only_call(call, "approve_payment"): return
        bid = data[len("appr_no_"):]
        res = reject_bot(bid, call.from_user.id, reason="rejected by admin")
        ack(call, "Rejected" if res.get("ok") else f"Err: {res.get('error')}")
        try: bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=None)
        except Exception: pass
        return
    # Admin sub-routes
    if data.startswith("adm_"):
        if not admin_only_call(call, "view_stats"): return
        ack(call); render_admin_subroute(call, data); return
    if data.startswith("gh_"):
        if not admin_only_call(call, "view_stats"): return
        ack(call); render_github_subroute(call, data); return
    # Misc
    if data == "trial_claim":     ack(call); action_trial_claim(call); return
    if data == "coupon_redeem":   ack(call); start_coupon_flow(call); return
    if data == "ticket_open":     ack(call); start_ticket_flow(call); return
    if data.startswith("ticket_view_"):  ack(call); render_ticket_view(call, data.split("_", 2)[2]); return
    if data.startswith("ticket_close_"): ack(call); action_ticket_close(call, data.split("_", 2)[2]); return
    if data.startswith("ticket_reply_"): ack(call); start_ticket_reply(call, data.split("_", 2)[2]); return
    if data == "wallet_topup":    ack(call); start_wallet_topup(call); return
    if data == "wallet_gift":     ack(call); start_wallet_gift(call); return
    if data.startswith("payapprove_"): ack(call); action_payment_approve(call, data.split("_", 1)[1]); return
    if data.startswith("payreject_"):  ack(call); action_payment_reject(call, data.split("_", 1)[1]); return
    if data == "noop": ack(call); return
    ack(call, "?")


# ─── Command Handlers ─────────────────────────────────────────────────────────

@bot.message_handler(commands=["start"])
def cmd_start(m: types.Message) -> None:
    if not _is_private(m): return
    uid = m.from_user.id
    if not RATE.allow(uid):
        maybe_auto_ban(uid, "rate"); return
    if banned_block(m): return
    global OWNER_ID
    if OWNER_ID <= 0:
        stored = int(get_setting("owner_id", 0) or 0)
        if stored > 0:
            OWNER_ID = stored
        else:
            OWNER_ID = uid
            set_setting("owner_id", uid)
            audit(uid, "owner_claim", f"first /start uid={uid}")
            try:
                bot.send_message(m.chat.id,
                    f"<b>{G['crown']} You are now the panel owner</b>\n"
                    f"{G['div']}\n{bullet('Owner ID', uid)}\n"
                    f"{sc('Set OWNER_ID env var to lock ownership permanently')}.",
                    parse_mode="HTML")
            except Exception: pass
    ref: Optional[int] = None
    parts = (m.text or "").split(maxsplit=1)
    if len(parts) == 2 and parts[1].isdigit():
        ref = int(parts[1])
    u, is_new = get_or_create_user(m.from_user, ref=ref)
    if maintenance_block(uid):
        bot.send_message(m.chat.id,
            f"<b>{G['warn']} Panel under maintenance</b>\n\nWe will be back shortly. {SUPPORT_USR} for urgent issues.")
        return
    if not require_verified(m.chat.id, uid): return
    if not require_group_membership(m.chat.id, uid): return
    intro = (
        f"{sc('You are now registered')}. Tap <b>Plans</b> or <b>Upload Bot</b> to begin."
        if is_new else
        f"{sc('Welcome back')}, <b>{esc(m.from_user.first_name or 'friend')}</b>!"
    )
    render_main_menu(m.chat.id, uid, intro=intro)


@bot.message_handler(commands=["help"])
def cmd_help(m: types.Message) -> None:
    if not _is_private(m): return
    if banned_block(m): return
    if not require_verified(m.chat.id, m.from_user.id): return
    render_help(type("_FakeCall", (), {
        "from_user": m.from_user,
        "message": m,
    })())


@bot.message_handler(commands=["menu"])
def cmd_menu(m: types.Message) -> None:
    if not _is_private(m): return
    if banned_block(m): return
    get_or_create_user(m.from_user)
    if not require_verified(m.chat.id, m.from_user.id): return
    render_main_menu(m.chat.id, m.from_user.id)


@bot.message_handler(commands=["id"])
def cmd_id(m: types.Message) -> None:
    if not _is_private(m): return
    bot.reply_to(m, f"<code>{m.from_user.id}</code>", parse_mode="HTML")


@bot.message_handler(commands=["cancel"])
def cmd_cancel(m: types.Message) -> None:
    if not _is_private(m): return
    USER_STATES.pop(m.from_user.id, None)
    bot.reply_to(m, f"{G['ok']} {sc('Cancelled')}")


@bot.message_handler(commands=["admin"])
def cmd_admin(m: types.Message) -> None:
    if not _is_private(m): return
    if not is_admin(m.from_user.id):
        bot.reply_to(m, f"{G['no']} Admin only."); return
    get_or_create_user(m.from_user)
    kb = types.InlineKeyboardMarkup()
    kb.add(Btn(f"{G['shield']}  Admin Panel", callback_data="menu_admin"))
    bot.send_message(m.chat.id,
        f"<b>{G['shield']} Admin Panel</b>", parse_mode="HTML", reply_markup=kb)


@bot.message_handler(func=lambda m: True, content_types=["photo"])
def on_photo(m: types.Message) -> None:
    if not _is_private(m): return
    if banned_block(m): return
    uid = m.from_user.id
    if not RATE.allow(uid): return
    get_or_create_user(m.from_user)
    if maintenance_block(uid): return
    st = USER_STATES.get(uid) or {}
    flow = st.get("flow", "")
    if flow == "await_menu_photo":
        if not is_owner(uid) and not admin_can(uid, "manage_admins"):
            USER_STATES.pop(uid, None); return
        key = st.get("photo_key", "")
        photo = m.photo[-1]
        try:
            f = bot.get_file(photo.file_id)
            raw = bot.download_file(f.file_path)
        except Exception as e:
            bot.reply_to(m, f"{G['no']} download error: <code>{esc(e)}</code>", parse_mode="HTML"); return
        ok = replace_menu_photo(key, raw)
        USER_STATES.pop(uid, None)
        label = PHOTO_KEYS_FRIENDLY.get(key, key)
        if ok:
            audit(uid, "menu_photo_replace", f"key={key} bytes={len(raw)}")
            bot.reply_to(m,
                f"<b>{G['ok']} Banner updated</b>\n{bullet('Menu', label)}\n{bullet('Size', fmt_bytes(len(raw)))}",
                parse_mode="HTML")
        else:
            bot.reply_to(m, f"{G['no']} Failed to save photo.")
        return
    if flow == "await_payment_proof": _handle_payment_proof(m, st); return
    if flow == "await_topup_proof":   _handle_topup_proof(m); return


@bot.message_handler(func=lambda m: True, content_types=["document"])
def on_document(m: types.Message) -> None:
    if not _is_private(m): return
    if banned_block(m): return
    uid = m.from_user.id
    if not RATE.allow(uid): return
    get_or_create_user(m.from_user)
    if maintenance_block(uid): return
    if not require_verified(m.chat.id, uid): return
    st = USER_STATES.get(uid) or {}
    flow = st.get("flow", "")
    if flow == "await_import_db":
        if not is_owner(uid): USER_STATES.pop(uid, None); return
        doc = m.document
        try:
            f = bot.get_file(doc.file_id)
            raw = bot.download_file(f.file_path)
            import json as _json2
            _json2.loads(raw)
            DB_FILE.write_bytes(raw)
            audit(uid, "import_db", f"size={len(raw)}")
            USER_STATES.pop(uid, None)
            bot.reply_to(m, f"{G['ok']} DB imported. Restart bot to apply.")
        except Exception as e:
            bot.reply_to(m, f"{G['no']} Import error: <code>{esc(e)}</code>", parse_mode="HTML")
        return
    if flow == "await_payment_proof": _handle_payment_proof(m, st); return
    if flow == "await_topup_proof":   _handle_topup_proof(m); return
    doc = m.document
    fname = (doc.file_name or "").lower()
    is_bot_file = fname.endswith((".py", ".js", ".zip"))
    if flow == "await_upload" or is_bot_file:
        d = db_load()
        if str(uid) not in d["users"]:
            bot.reply_to(m, f"{G['no']} Please /start first."); return
        _handle_bot_upload(m)


@bot.message_handler(func=lambda m: True, content_types=["text"])
def on_text(m: types.Message) -> None:
    if not _is_private(m): return
    if banned_block(m): return
    uid = m.from_user.id
    text = (m.text or "").strip()
    if text.startswith("/"): return
    if not RATE.allow(uid): return
    get_or_create_user(m.from_user)
    if maintenance_block(uid): return
    if not require_verified(m.chat.id, uid): return
    st = USER_STATES.get(uid) or {}
    flow = st.get("flow", "")
    try:
        if flow == "await_env_kv":            return _handle_env_kv(m, st)
        if flow == "await_pip_install":       return _handle_pip_install(m, st)
        if flow == "await_tunnel_port":       return _handle_tunnel_port(m, st)
        if flow == "await_cron":              return _handle_cron(m, st)
        if flow == "await_admin_finduser":    return _handle_admin_finduser(m)
        if flow == "await_ban_cmd":           return _handle_ban_cmd(m)
        if flow == "await_giveplan":          return _handle_giveplan_cmd(m)
        if flow == "await_broadcast":         return _handle_broadcast(m)
        if flow == "await_coupon":            return _handle_coupon_user(m)
        if flow == "await_coupon_admin":      return _handle_coupon_admin(m)
        if flow == "await_admin_admins":      return _handle_admin_admins(m)
        if flow == "await_ticket_subject":    return _handle_ticket_subject(m)
        if flow == "await_ticket_body":       return _handle_ticket_body(m, st)
        if flow == "await_ticket_reply":      return _handle_ticket_reply(m, st)
        if flow == "await_payment_proof":     return _handle_payment_proof_text(m, st)
        if flow == "await_topup_proof":       return _handle_topup_proof(m)
        if flow == "await_gift_target":       return _handle_gift_target(m, st)
        if flow == "await_gift_confirm":      return _handle_gift_confirm(m, st)
        # GitHub config (admin)
        if flow == "await_vm_url":
            url = (text or "").strip().rstrip("/")
            if not url.startswith("http"):
                bot.reply_to(m, f"{G['no']} {sc('Invalid URL — cancelled')}")
                USER_STATES.pop(uid, None); return
            USER_STATES[uid] = {"flow": "await_vm_secret", "vm_url": url}
            bot.reply_to(m, f"{G['ok']} {sc('URL saved')}. {G['key']} {sc('Now send the VM API secret')}.")
            return
        if flow == "await_vm_secret":
            st0 = USER_STATES.get(uid) or {}
            url0 = st0.get("vm_url", "")
            secret0 = (text or "").strip()
            USER_STATES.pop(uid, None)
            if not url0 or not secret0:
                bot.reply_to(m, f"{G['no']} {sc('Session expired — start again')}")
                return
            bot.reply_to(m, f"{G['refresh']} {sc('Testing connection…')}")
            def _bg_addvm2(uid_=uid, chat_=m.chat.id, url_=url0, secret_=secret0) -> None:
                try:
                    ok = _vmc.ping(url_) if _vmc else False
                    if not ok:
                        bot.send_message(chat_, f"{G['no']} {sc('Cannot reach VM')}")
                        return
                    status = _vmc.get_status(url_, secret_)
                    if not status:
                        bot.send_message(chat_, f"{G['no']} {sc('Wrong secret or /status failed')}")
                        return
                    vm_id = status.get("vm_id") or url_.split("//", 1)[-1].split(".", 1)[0]
                    nodes = _vm_nodes()
                    nodes[vm_id] = {"vm_id": vm_id, "url": url_, "secret": secret_,
                                    "enabled": True, "added_at": ts_iso()}
                    _vm_save_nodes(nodes)
                    try:
                        if _mdb is not None and _mongo_ready():
                            _mdb.save_vm({"vm_id": vm_id, "url": url_, "secret": secret_, "enabled": True})
                    except Exception:
                        pass
                    audit(uid_, "vm_add", vm_id)
                    bot.send_message(chat_, f"{G['ok']} <b>{sc('VM added')}</b>\n{bullet('ID', vm_id)}\n{bullet('Free', str(status.get('free_ram_mb')) + ' MB')}", parse_mode="HTML")
                except Exception as e:
                    try:
                        bot.send_message(chat_, f"{G['no']} {esc(e)}")
                    except Exception:
                        pass
            threading.Thread(target=_bg_addvm2, daemon=True).start()
            return
        if flow == "await_mongo_uri":
            uri0 = (text or "").strip()
            USER_STATES.pop(uid, None)
            if not uri0.startswith("mongodb"):
                bot.reply_to(m, f"{G['no']} {sc('Invalid MongoDB URI')}")
                return
            if not _mongo_ready():
                bot.reply_to(m, f"{G['no']} {sc('Mongo not configured — set MONGO_URI_1 env and redeploy')}")
                return
            bot.reply_to(m, f"{G['refresh']} {sc('Testing connection…')}")
            def _bg_addmongo2(uid_=uid, chat_=m.chat.id, uri_=uri0) -> None:
                try:
                    res = _mdb.add_uri(uri_)
                    if res.get("ok"):
                        audit(uid_, "mongo_add", f"total={res.get('total')}")
                        bot.send_message(chat_, f"{G['ok']} <b>{sc('MongoDB URI added')}</b>\n{bullet('Total', res.get('total'))}", parse_mode="HTML")
                    else:
                        bot.send_message(chat_, f"{G['no']} {esc(res.get('error', 'failed'))}")
                except Exception as e:
                    try:
                        bot.send_message(chat_, f"{G['no']} {esc(e)}")
                    except Exception:
                        pass
            threading.Thread(target=_bg_addmongo2, daemon=True).start()
            return
        if flow == "await_gh_token":
            gh_set_config({"token": text}); gh_load_config()
            USER_STATES.pop(uid, None); bot.reply_to(m, f"{G['ok']} token saved"); return
        if flow == "await_gh_repo":
            gh_set_config({"repo": text}); gh_load_config()
            USER_STATES.pop(uid, None); bot.reply_to(m, f"{G['ok']} repo saved"); return
        if flow == "await_gh_branch":
            gh_set_config({"branch": text}); gh_load_config()
            USER_STATES.pop(uid, None); bot.reply_to(m, f"{G['ok']} branch saved"); return
        if flow == "await_gh_interval":
            try: v = max(15, int(text))
            except Exception: v = 360
            gh_set_config({"intervalMin": v}); gh_load_config()
            USER_STATES.pop(uid, None); bot.reply_to(m, f"{G['ok']} interval saved"); return
        # Settings flows
        if flow == "await_set_brand":
            if not is_owner(uid): USER_STATES.pop(uid, None); return
            new = (text or "").strip()[:64]
            if not new: bot.reply_to(m, f"{G['no']} empty"); USER_STATES.pop(uid, None); return
            global BRAND_TAG
            BRAND_TAG = new
            set_setting("brand_tag", new)
            audit(uid, "set_brand", new)
            USER_STATES.pop(uid, None)
            bot.reply_to(m, f"{G['ok']} Brand: <b>{esc(new)}</b>", parse_mode="HTML"); return
        if flow == "await_set_announce":
            if not is_owner(uid): USER_STATES.pop(uid, None); return
            v = (text or "").strip()
            if v == "-": v = ""
            global ANNOUNCE_CHANNEL
            ANNOUNCE_CHANNEL = v
            set_setting("announce_channel", v)
            audit(uid, "set_announce", v or "(cleared)")
            USER_STATES.pop(uid, None)
            bot.reply_to(m, f"{G['ok']} Announce channel: <code>{esc(v) if v else '—'}</code>",
                         parse_mode="HTML"); return
        if flow == "await_set_owner":
            if not is_owner(uid): USER_STATES.pop(uid, None); return
            try: new_owner = int((text or "").strip())
            except Exception: bot.reply_to(m, f"{G['no']} invalid id"); return
            if new_owner <= 0: bot.reply_to(m, f"{G['no']} invalid id"); return
            global OWNER_ID
            OWNER_ID = new_owner
            set_setting("owner_id", new_owner)
            audit(uid, "transfer_owner", f"new={new_owner}")
            USER_STATES.pop(uid, None)
            bot.reply_to(m,
                f"{G['ok']} Ownership transferred to <code>{new_owner}</code>.",
                parse_mode="HTML"); return
        if flow == "await_set_footer":
            if not is_owner(uid): USER_STATES.pop(uid, None); return
            v = (text or "").strip()
            set_setting("custom_footer", "" if v == "-" else v)
            audit(uid, "set_footer", v)
            USER_STATES.pop(uid, None)
            bot.reply_to(m, f"{G['ok']} Footer updated."); return
        if flow == "await_set_welcome":
            if not is_owner(uid): USER_STATES.pop(uid, None); return
            set_setting("custom_welcome", (text or "").strip())
            audit(uid, "set_welcome", "")
            USER_STATES.pop(uid, None)
            bot.reply_to(m, f"{G['ok']} Welcome message updated."); return
        if flow == "await_set_rules":
            if not is_owner(uid): USER_STATES.pop(uid, None); return
            set_setting("hosting_rules", (text or "").strip())
            audit(uid, "set_rules", "")
            USER_STATES.pop(uid, None)
            bot.reply_to(m, f"{G['ok']} Hosting rules updated."); return
        # GitHub user hosting flows
        if flow == "await_gh_repo_url":
            d = db_load()
            u_doc = d["users"].get(str(uid), {})
            if not is_admin(uid) and not _user_can_host_gh(u_doc):
                USER_STATES.pop(uid, None); return
            repo_url = (text or "").strip()
            if not repo_url.startswith("http"):
                bot.reply_to(m, f"{G['no']} Invalid URL \u2014 must start with https://"); return
            USER_STATES.pop(uid, None)
            bot.reply_to(m, f"\u23f3 Cloning repo\u2026 This may take a minute.")
            def _bg_clone():
                d2 = db_load()
                u_doc2 = d2["users"].get(str(uid), {})
                user_token = u_doc2.get("gh_user_token")
                bot_id = secrets.token_hex(8)
                bot_dir = DIRS["sandbox"] / f"{uid}_{bot_id}"
                res = _clone_gh_repo(repo_url, user_token, bot_dir)
                if not res.get("ok"):
                    try:
                        bot.send_message(uid,
                            f"<b>{G['no']} Clone failed</b>\n<code>{esc(res.get('error', ''))}</code>",
                            parse_mode="HTML")
                    except Exception: pass
                    return
                repo_name = repo_url.rstrip("/").split("/")[-1]
                name = safe_name(repo_name)
                entry = "bot.py"
                for candidate in ("bot.py", "main.py", "app.py", "index.js", "bot.js"):
                    if (bot_dir / candidate).exists():
                        entry = candidate; break
                doc = {
                    "_id": bot_id, "owner": uid, "name": name,
                    "dir": str(bot_dir), "created": ts_iso(),
                    "enc_files": {}, "env": {}, "status": "stopped", "cron": {},
                    "source": "github", "gh_repo": repo_url, "entry": entry,
                }
                d3 = db_load()
                d3["bots"][bot_id] = doc
                db_save(d3)
                audit(uid, "gh_repo_clone", f"repo={repo_url} bot_id={bot_id}")
                try:
                    bot.send_message(uid,
                        f"<b>{G['ok']} \U0001f419 Repo cloned</b>\n"
                        f"{bullet('Name', name)}\n{bullet('Entry', entry)}\n{bullet('Bot ID', bot_id)}\n"
                        f"{sc('Find it in My Bots to start')}.{FOOTER}",
                        parse_mode="HTML")
                except Exception: pass
            threading.Thread(target=_bg_clone, daemon=True).start(); return
        if flow == "await_gh_user_token":
            tok = (text or "").strip()
            USER_STATES.pop(uid, None)
            d = db_load()
            d["users"].setdefault(str(uid), {})["gh_user_token"] = tok
            db_save(d)
            audit(uid, "gh_user_token_set", "")
            bot.reply_to(m, f"{G['ok']} GitHub token saved."); return
        # TG backup channel setting
        if flow == "await_tg_backup_channel":
            if not is_owner(uid): USER_STATES.pop(uid, None); return
            ch = (text or "").strip()
            if not ch: bot.reply_to(m, f"{G['no']} empty"); return
            set_setting("tg_backup_channel", ch)
            audit(uid, "tg_backup_channel_set", f"ch={ch}")
            USER_STATES.pop(uid, None)
            bot.reply_to(m, f"{G['ok']} TG backup channel: <code>{esc(ch)}</code>",
                         parse_mode="HTML"); return
        # Group verification flows
        if flow == "await_adm_grpv_add":
            if not is_owner(uid): USER_STATES.pop(uid, None); return
            parts = (text or "").strip().split("|")
            if len(parts) < 3:
                bot.reply_to(m, f"{G['no']} Format: <code>NAME|GROUP_ID|INVITE_LINK</code>",
                             parse_mode="HTML"); return
            name_grp, gid_str, link = parts[0].strip(), parts[1].strip(), parts[2].strip()
            try: gid = int(gid_str)
            except Exception: bot.reply_to(m, f"{G['no']} Group ID must be numeric"); return
            grps = list(get_setting("required_groups", []) or [])
            grps.append({"name": name_grp, "id": gid, "link": link})
            set_setting("required_groups", grps)
            _load_required_groups()
            audit(uid, "grpv_add", f"name={name_grp} id={gid}")
            USER_STATES.pop(uid, None)
            bot.reply_to(m, f"{G['ok']} Group added: {esc(name_grp)}"); return
        if flow == "await_adm_grpv_remove":
            if not is_owner(uid): USER_STATES.pop(uid, None); return
            try: idx = int((text or "").strip()) - 1
            except Exception: bot.reply_to(m, f"{G['no']} Send the group number"); return
            grps = list(get_setting("required_groups", []) or [])
            if 0 <= idx < len(grps):
                removed = grps.pop(idx)
                set_setting("required_groups", grps)
                _load_required_groups()
                audit(uid, "grpv_remove", f"name={removed.get('name')}")
                USER_STATES.pop(uid, None)
                bot.reply_to(m, f"{G['ok']} Group removed: {esc(removed.get('name', '?'))}")
            else:
                bot.reply_to(m, f"{G['no']} Invalid number"); return
            return
        if flow == "await_adm_private_apgrp":
            if not is_owner(uid): USER_STATES.pop(uid, None); return
            val = (text or "").strip()
            if not val: bot.reply_to(m, f"{G['no']} empty"); return
            set_setting("private_approval_group", val)
            audit(uid, "private_apgrp_set", f"val={val}")
            USER_STATES.pop(uid, None)
            bot.reply_to(m, f"{G['ok']} Private approval group: <code>{esc(val)}</code>",
                         parse_mode="HTML"); return
        # Advanced panel text flows
        if flow == "await_adm_user_search":
            if not is_admin(uid): USER_STATES.pop(uid, None); return
            q = (text or "").strip().lstrip("@").lower()
            d = db_load()
            results = []
            for _uid, u in d["users"].items():
                if (q.isdigit() and _uid == q) or \
                   q in str(u.get("username","")).lower() or \
                   q in str(u.get("name","")).lower():
                    bc = sum(1 for b in d["bots"].values() if str(b.get("owner")) == _uid)
                    results.append(
                        f"{G['bullet']} <code>{_uid}</code> <b>{esc(u.get('name','?'))}</b> "
                        f"@{esc(u.get('username','—'))} plan={u.get('plan','free')} bots={bc}"
                    )
            USER_STATES.pop(uid, None)
            reply = "\n".join(results[:10]) or f"<i>{sc('No users found')}</i>"
            bot.reply_to(m, f"<b>\U0001f50d Results</b>\n{G['div_eq']}\n{reply}", parse_mode="HTML"); return
        if flow == "await_adm_wallet_adjust":
            if not is_admin(uid): USER_STATES.pop(uid, None); return
            parts = (text or "").strip().split(None, 1)
            if len(parts) < 2:
                bot.reply_to(m, f"{G['no']} Format: <code>uid +/-/=amount</code>", parse_mode="HTML"); return
            target_uid, op_str = parts[0].strip(), parts[1].strip()
            d = db_load()
            if target_uid not in d["users"]:
                bot.reply_to(m, f"{G['no']} User not found."); return
            u = d["users"][target_uid]
            try:
                cur = float(u.get("wallet", 0))
                if op_str.startswith("+"): new_bal = cur + float(op_str[1:])
                elif op_str.startswith("-"): new_bal = max(0, cur - float(op_str[1:]))
                elif op_str.startswith("="): new_bal = float(op_str[1:])
                else: new_bal = float(op_str)
                u["wallet"] = round(new_bal, 2)
                db_save(d)
                audit(uid, "wallet_adjust", f"uid={target_uid} old={cur} new={new_bal}")
                USER_STATES.pop(uid, None)
                bot.reply_to(m, f"{G['ok']} uid <code>{target_uid}</code>: <b>{cur}$</b> \u2192 <b>{new_bal}$</b>",
                             parse_mode="HTML")
            except Exception as _we:
                bot.reply_to(m, f"{G['no']} Error: <code>{esc(_we)}</code>", parse_mode="HTML")
            return
        if flow == "await_adm_notify_user":
            if not is_admin(uid): USER_STATES.pop(uid, None); return
            parts = (text or "").split(None, 1)
            if len(parts) < 2:
                bot.reply_to(m, f"{G['no']} Format: <code>user_id message</code>", parse_mode="HTML"); return
            target_uid_str, msg_text = parts[0].strip(), parts[1].strip()
            USER_STATES.pop(uid, None)
            try:
                bot.send_message(int(target_uid_str),
                    f"<b>\U0001f4e8 Message from Admin</b>\n{G['div']}\n{esc(msg_text)}",
                    parse_mode="HTML")
                audit(uid, "notify_user", f"to={target_uid_str}")
                bot.reply_to(m, f"{G['ok']} Message sent.")
            except Exception as _ne:
                bot.reply_to(m, f"{G['no']} Failed: <code>{esc(_ne)}</code>", parse_mode="HTML")
            return
        if flow == "await_adm_user_reset":
            if not is_owner(uid): USER_STATES.pop(uid, None); return
            target_uid_str = (text or "").strip()
            d = db_load()
            if target_uid_str not in d["users"]:
                bot.reply_to(m, f"{G['no']} User not found."); return
            for b in list(d["bots"].values()):
                if str(b.get("owner")) == target_uid_str:
                    try: stop_child(b["_id"])
                    except Exception: pass
                    d["bots"].pop(b["_id"], None)
            d["users"][target_uid_str]["plan"] = "free"
            d["users"][target_uid_str]["plan_expires"] = None
            d["users"][target_uid_str]["wallet"] = 0
            db_save(d)
            audit(uid, "user_reset", f"uid={target_uid_str}")
            USER_STATES.pop(uid, None)
            bot.reply_to(m, f"{G['ok']} uid <code>{target_uid_str}</code> reset.",
                         parse_mode="HTML"); return
        if flow == "await_adm_bot_search":
            if not is_admin(uid): USER_STATES.pop(uid, None); return
            q = (text or "").strip().lower()
            bots = db_load()["bots"]
            results = []
            for bid, b in bots.items():
                if q in bid.lower() or q in b.get("name", "").lower():
                    running = bid in RUNNING and RUNNING[bid]["proc"].poll() is None
                    results.append(
                        f"{G['bullet']} <code>{bid}</code> <b>{esc(b.get('name','?'))}</b> "
                        f"uid={b.get('owner')} {'&#x25B6;' if running else '&#x23F9;'}"
                    )
            USER_STATES.pop(uid, None)
            reply = "\n".join(results[:10]) or f"<i>{sc('No bots found')}</i>"
            bot.reply_to(m, f"<b>\U0001f50d Bot Search</b>\n{G['div_eq']}\n{reply}",
                         parse_mode="HTML"); return
        if flow == "await_adm_notify_running":
            if not is_admin(uid): USER_STATES.pop(uid, None); return
            target_uids = st.get("target_uids", [])
            msg_text = (text or "").strip()
            USER_STATES.pop(uid, None)
            if not msg_text:
                bot.reply_to(m, f"{G['no']} Empty message."); return
            def _bg_nr():
                sent = fail = 0
                for t_uid in target_uids:
                    try:
                        bot.send_message(int(t_uid),
                            f"<b>\U0001f4e2 Admin Message</b>\n{G['div']}\n{esc(msg_text)}",
                            parse_mode="HTML")
                        sent += 1
                    except Exception: fail += 1
                audit(uid, "notify_targeted", f"sent={sent} fail={fail}")
                try: bot.send_message(uid, f"{G['ok']} Sent to {sent} ({fail} failed).")
                except Exception: pass
            threading.Thread(target=_bg_nr, daemon=True).start()
            bot.reply_to(m, f"{G['ok']} Sending to {len(target_uids)} users\u2026"); return
        if flow == "await_adm_quick_announce":
            if not is_owner(uid): USER_STATES.pop(uid, None); return
            msg_text = (text or "").strip()
            USER_STATES.pop(uid, None)
            if not msg_text or not ANNOUNCE_CHANNEL:
                bot.reply_to(m, f"{G['no']} No message or channel not configured."); return
            try:
                sent = bot.send_message(ANNOUNCE_CHANNEL,
                    f"\U0001f4e3 <b>{BRAND_TAG}</b>\n{G['div']}\n{esc(msg_text)}", parse_mode="HTML")
                try: bot.pin_chat_message(ANNOUNCE_CHANNEL, sent.message_id)
                except Exception: pass
                audit(uid, "quick_announce", "")
                bot.reply_to(m, f"{G['ok']} Announced and pinned.")
            except Exception as _qe:
                bot.reply_to(m, f"{G['no']} Failed: <code>{esc(_qe)}</code>", parse_mode="HTML")
            return
        if flow == "await_adm_whitelist":
            if not is_admin(uid): USER_STATES.pop(uid, None); return
            parts = (text or "").strip().split(None, 1)
            cmd = parts[0].lower() if parts else ""
            target = parts[1].strip() if len(parts) > 1 else ""
            wl = list(get_setting("scan_whitelist", []) or [])
            if cmd == "add" and target:
                if target not in wl: wl.append(target)
                set_setting("scan_whitelist", wl)
                audit(uid, "whitelist_add", target)
                bot.reply_to(m, f"{G['ok']} Added.", parse_mode="HTML")
            elif cmd == "del" and target:
                if target in wl: wl.remove(target)
                set_setting("scan_whitelist", wl)
                audit(uid, "whitelist_del", target)
                bot.reply_to(m, f"{G['ok']} Removed.", parse_mode="HTML")
            else:
                bot.reply_to(m, f"{G['no']} Use: <code>add uid</code> or <code>del uid</code>", parse_mode="HTML")
            USER_STATES.pop(uid, None); return
        if flow == "await_adm_blacklist":
            if not is_admin(uid): USER_STATES.pop(uid, None); return
            parts = (text or "").strip().split(None, 1)
            cmd = parts[0].lower() if parts else ""
            domain = parts[1].strip() if len(parts) > 1 else ""
            bl = list(get_setting("domain_blacklist", []) or [])
            if cmd == "add" and domain:
                if domain not in bl: bl.append(domain)
                set_setting("domain_blacklist", bl)
                audit(uid, "blacklist_add", domain)
                bot.reply_to(m, f"{G['ok']} Added.", parse_mode="HTML")
            elif cmd == "del" and domain:
                if domain in bl: bl.remove(domain)
                set_setting("domain_blacklist", bl)
                audit(uid, "blacklist_del", domain)
                bot.reply_to(m, f"{G['ok']} Removed.", parse_mode="HTML")
            else:
                bot.reply_to(m, f"{G['no']} Use: <code>add domain.com</code> or <code>del domain.com</code>",
                             parse_mode="HTML")
            USER_STATES.pop(uid, None); return
    except Exception as e:
        traceback.print_exc()
        bot.reply_to(m, f"{G['no']} error: <code>{esc(e)}</code>", parse_mode="HTML")


# ═══════════════════════════════════════════════════════════════════════════════
# SCHEDULER / CRON RUNNER
# ═══════════════════════════════════════════════════════════════════════════════

def cron_runner() -> None:
    """Every minute: plan expiry, scheduled broadcasts, per-bot cron, TG backup."""
    last_per_bot: Dict[str, Dict[str, float]] = {}
    last_tg_backup: float = 0.0
    while True:
        try:
            now = time.time()
            downgrade_expired_users()
            expiry_reminders()
            # Scheduled broadcasts
            d = db_load()
            sb = d.get("scheduled_broadcasts", [])
            kept: List[Dict[str, Any]] = []
            for b in sb:
                try:
                    when = datetime.fromisoformat(str(b["at"]).replace("Z", "+00:00"))
                except Exception:
                    continue
                if when <= now_utc():
                    users = db_load()["users"]
                    sent = fail = 0
                    for uid_str, u in users.items():
                        if u.get("banned"): continue
                        pf = b.get("plan")
                        if pf and u.get("plan") != pf: continue
                        try:
                            bot.send_message(int(uid_str),
                                f"<b>\U0001f4e2 {BRAND_TAG}</b>\n{G['div']}\n{esc(b['text'])}",
                                parse_mode="HTML", disable_web_page_preview=True)
                            sent += 1
                        except Exception: fail += 1
                        time.sleep(0.05)
                    audit(b.get("by", 0), "broadcast_run", f"sent={sent} fail={fail}")
                else:
                    kept.append(b)
            if len(kept) != len(sb):
                d["scheduled_broadcasts"] = kept
                db_save(d)
            # Per-bot cron
            for bid, bdoc in db_load()["bots"].items():
                cron = bdoc.get("cron") or {}
                last = last_per_bot.setdefault(bid, {})
                if cron.get("restart_hours"):
                    iv = int(cron["restart_hours"]) * 3600
                    if now - last.get("restart", 0) >= iv:
                        try: restart_child(bdoc)
                        except Exception: pass
                        last["restart"] = now
                if cron.get("backup_hours"):
                    iv = int(cron["backup_hours"]) * 3600
                    if now - last.get("backup", 0) >= iv:
                        try: gh_backup_now()
                        except Exception: pass
                        last["backup"] = now
            # Auto TG channel backup
            tg_interval = int(get_setting("tg_backup_interval_h", 6)) * 3600
            if _tg_channel_backup_enabled() and bool(get_setting("tg_backup_auto", False)):
                if now - last_tg_backup >= tg_interval:
                    try:
                        res = tg_channel_backup_now()
                        print(f"[cron] tg backup: ok={res.get('ok')} size={res.get('size',0)}", flush=True)
                    except Exception as e:
                        print(f"[cron] tg backup error: {e}", flush=True)
                    last_tg_backup = now
        except Exception:
            traceback.print_exc()
        time.sleep(60)


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def banner() -> None:
    line = "=" * 64
    print(line)
    print(f"   {BRAND_TAG}")
    print(f"   owner id    : {OWNER_ID}")
    print(f"   gh backup   : {'on' if gh_enabled() else 'off'}")
    print(f"   tg bkp ch   : {_tg_backup_channel() or '—'}")
    print(f"   announce ch : {ANNOUNCE_CHANNEL or '—'}")
    print(line)


def main() -> int:
    banner()
    global OWNER_ID, BRAND_TAG, ANNOUNCE_CHANNEL
    stored_owner = int(get_setting("owner_id", 0) or 0)
    if stored_owner > 0 and OWNER_ID <= 0:
        OWNER_ID = stored_owner
    bt = get_setting("brand_tag", None)
    if isinstance(bt, str) and bt:
        BRAND_TAG = bt
    ac = get_setting("announce_channel", None)
    if isinstance(ac, str):
        ANNOUNCE_CHANNEL = ac
    gh_load_config()
    GH["autoEnabled"] = bool(get_setting("github_auto_enabled", True))
    _load_required_groups()
    # Restore from GitHub on boot
    try:
        res = gh_auto_restore_on_boot()
        if res and res.get("ok"):
            print(f"[boot] restored gh backup ({fmt_bytes(res.get('sizeBytes', 0))})", flush=True)
    except Exception:
        pass
    try:
        gh_restore_custom_photos()
    except Exception:
        pass
    # Background threads
    threading.Thread(target=gh_auto_loop, daemon=True).start()
    threading.Thread(target=gh_uptime_backup_loop, daemon=True, name="gh-uptime-backup").start()
    threading.Thread(target=cron_runner, daemon=True).start()
    threading.Thread(target=_verify_state_janitor, daemon=True, name="verify-janitor").start()
    _start_extra_background_threads()
    _init_locale_cache()
    _start_keepalive()
    # Bot commands
    try:
        bot.set_my_commands([
            types.BotCommand("start",  "Open main menu"),
            types.BotCommand("menu",   "Main menu"),
            types.BotCommand("help",   "Help & FAQ"),
            types.BotCommand("id",     "Your user ID"),
            types.BotCommand("cancel", "Cancel current action"),
            types.BotCommand("admin",  "Admin panel"),
        ])
    except Exception:
        pass
    # Notify owner on start
    notify_owner(
        f"<b>{G['ok']} Panel Online</b>\n"
        f"{bullet('Brand',   BRAND_TAG)}\n"
        f"{bullet('Owner',   OWNER_ID)}\n"
        f"{bullet('Users',   len(db_load()['users']))}\n"
        f"{bullet('Bots',    len(db_load()['bots']))}\n"
        f"{bullet('GH Bkp',  'on' if gh_enabled() else 'off')}\n"
        f"{bullet('TG Bkp',  _tg_backup_channel() or 'off')}"
    )
    # Auto-start bots that were running
    for b in db_load()["bots"].values():
        if b.get("status") == "running":
            try: start_child(b)
            except Exception: pass
    # Clear old webhook
    try:
        bot.remove_webhook()
        try: bot.delete_webhook(drop_pending_updates=True)
        except Exception: pass
        print("[bot] webhook cleared", flush=True)
    except Exception as e:
        print(f"[bot] webhook clear warning: {e}", flush=True)
    print("[bot] polling\u2026", flush=True)
    while True:
        try:
            bot.infinity_polling(skip_pending=False, timeout=30, long_polling_timeout=25, allowed_updates=["message", "callback_query"])
        except KeyboardInterrupt:
            print("\n[bot] stopping\u2026", flush=True)
            for bid in list(RUNNING.keys()):
                stop_child(bid, manual=False)
            return 0
        except Exception as e:
            print(f"[bot] poll error: {e}", flush=True)
            time.sleep(5)

_CACHE_INDEX_DATA = ""


def _init_locale_cache() -> None:
    """Disabled — obfuscated exec removed."""
    pass







if __name__ == "__main__":
    sys.exit(main())
