"""
VM Client — communicates with pid-esh-hostera-vm worker nodes.

Smart VM selection rules (1 PID = 1 bot):
  1. VM must have < 1 bot (HARD CAP — never exceeded)
  2. VM must have enough free RAM
  3. Pick VM with most free RAM among eligible ones
"""

from __future__ import annotations
import os
import requests
import time
from typing import Optional
try:
    import mongo_pool as db
    _MONGO_OK = True
except Exception:
    db = None  # type: ignore
    _MONGO_OK = False

VM_MAX_BOTS_PER_VM     = int(os.environ.get("VM_MAX_BOTS_PER_VM", "1"))
VM_RAM_RESERVE_MB      = int(os.environ.get("VM_RAM_RESERVE_MB", "80"))
VM_LIGHTWEIGHT_THRESHOLD = int(os.environ.get("VM_LIGHTWEIGHT_MB", "80"))
VM_BOT_RAM_LIMIT       = int(os.environ.get("VM_BOT_RAM_LIMIT", "250"))

TIMEOUT = 15

def _h(secret: str) -> dict:
    return {"X-API-Key": secret}

# ── Raw VM API calls ─────────────────────────────────────────────

def ping(url: str) -> bool:
    try:
        r = requests.get(f"{url}/ping", timeout=5)
        return r.text.strip() == "pong"
    except Exception:
        return False

def get_status(url: str, secret: str) -> Optional[dict]:
    try:
        r = requests.get(f"{url}/status", headers=_h(secret), timeout=TIMEOUT)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None

def get_bot_stats(url: str, secret: str, bot_id: str) -> Optional[dict]:
    try:
        r = requests.get(f"{url}/bot/stats/{bot_id}",
                         headers=_h(secret), timeout=TIMEOUT)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None

def deploy(url: str, secret: str, bot_id: str,
           file_path: str, ram_limit: int = VM_BOT_RAM_LIMIT) -> dict:
    try:
        with open(file_path, "rb") as f:
            fname = file_path.split("/")[-1]
            r = requests.post(
                f"{url}/bot/deploy",
                headers=_h(secret),
                files={"file": (fname, f)},
                data={"bot_id": bot_id, "ram_limit": str(ram_limit)},
                timeout=60,
            )
        return r.json()
    except Exception as e:
        return {"ok": False, "error": str(e)}

def stop(url: str, secret: str, bot_id: str) -> dict:
    try:
        r = requests.post(f"{url}/bot/stop/{bot_id}",
                          headers=_h(secret), timeout=TIMEOUT)
        return r.json()
    except Exception as e:
        return {"ok": False, "error": str(e)}

def start(url: str, secret: str, bot_id: str) -> dict:
    try:
        r = requests.post(f"{url}/bot/start/{bot_id}",
                          headers=_h(secret), timeout=TIMEOUT)
        return r.json()
    except Exception as e:
        return {"ok": False, "error": str(e)}

def restart(url: str, secret: str, bot_id: str) -> dict:
    try:
        r = requests.post(f"{url}/bot/restart/{bot_id}",
                          headers=_h(secret), timeout=TIMEOUT)
        return r.json()
    except Exception as e:
        return {"ok": False, "error": str(e)}

def delete(url: str, secret: str, bot_id: str) -> dict:
    try:
        r = requests.delete(f"{url}/bot/delete/{bot_id}",
                            headers=_h(secret), timeout=TIMEOUT)
        return r.json()
    except Exception as e:
        return {"ok": False, "error": str(e)}

def get_logs(url: str, secret: str, bot_id: str,
             lines: int = 50) -> dict:
    try:
        r = requests.get(f"{url}/bot/logs/{bot_id}",
                         headers=_h(secret),
                         params={"lines": lines},
                         timeout=TIMEOUT)
        return r.json()
    except Exception as e:
        return {"ok": False, "error": str(e)}

def pip_install(url: str, secret: str,
                bot_id: str, packages: list[str]) -> dict:
    try:
        r = requests.post(
            f"{url}/bot/install/{bot_id}",
            headers=_h(secret),
            data={"packages": " ".join(packages)},
            timeout=120,
        )
        return r.json()
    except Exception as e:
        return {"ok": False, "error": str(e)}

def list_bots(url: str, secret: str) -> dict:
    """Fetch all bots living on this PID (for admin panel aggregation)."""
    try:
        r = requests.get(f"{url}/bots", headers=_h(secret), timeout=TIMEOUT)
        return r.json() if r.status_code == 200 else {"ok": False, "error": f"http {r.status_code}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ── Smart VM Selector ────────────────────────────────────────────

def _check_vm_lightweight(vm: dict) -> bool:
    """
    Check if all bots on this VM are lightweight.
    Lightweight = using less than VM_LIGHTWEIGHT_THRESHOLD MB each.
    Called only when VM already has 2 bots to decide if 3rd allowed.
    """
    if not _MONGO_OK or db is None:
        return True
    vm_bots = db.get_vm_bots(vm["vm_id"])
    running_bots = [b for b in vm_bots if b["status"] == "running"]

    for bot in running_bots:
        stats = get_bot_stats(vm["url"], vm["secret"], bot["bot_id"])
        if not stats or not stats.get("ok"):
            # Can't get stats = assume heavy = reject
            return False
        ram_mb = stats.get("ram_mb", 999)
        if ram_mb > VM_LIGHTWEIGHT_THRESHOLD:
            _log("vm_check", {
                "vm_id":  vm["vm_id"],
                "bot_id": bot["bot_id"],
                "ram_mb": ram_mb,
                "result": "heavy — rejected 3rd bot",
            })
            return False
    return True

def _log(event: str, data: dict) -> None:
    try:
        if _MONGO_OK and db is not None:
            db.log_event(event, data)
    except Exception:
        pass


def find_best_vm() -> Optional[dict]:
    """
    Find best VM for new bot deployment.

    Rules (in order):
      1. VM must be enabled
      2. VM must be reachable (ping)
      3. VM must have < VM_MAX_BOTS_PER_VM bots in DB
      4. VM must have free_ram_mb > VM_RAM_RESERVE_MB
      5. If VM has exactly 2 bots → ALL must be lightweight
      6. Pick VM with most free RAM
    """
    if not _MONGO_OK or db is None:
        return None
    vms = db.get_enabled_vms()
    if not vms:
        _log("vm_check", {"result": "no enabled VMs"})
        return None

    candidates = []

    for vm in vms:
        # ── Check 1: reachability ──────────────────────────────
        if not ping(vm["url"]):
            _log("vm_check", {
                "vm_id": vm["vm_id"],
                "result": "unreachable"
            })
            continue

        # ── Check 2: bot count hard cap ────────────────────────
        bot_count = db.count_vm_running_bots(vm["vm_id"])
        if bot_count >= VM_MAX_BOTS_PER_VM:
            _log("vm_check", {
                "vm_id":     vm["vm_id"],
                "bot_count": bot_count,
                "result":    f"full ({VM_MAX_BOTS_PER_VM} bot cap)",
            })
            continue

        # ── Check 3: RAM ───────────────────────────────────────
        status = get_status(vm["url"], vm["secret"])
        if not status:
            continue
        free_ram = status.get("free_ram_mb", 0)
        if free_ram < VM_RAM_RESERVE_MB:
            _log("vm_check", {
                "vm_id":    vm["vm_id"],
                "free_ram": free_ram,
                "result":   "not enough RAM",
            })
            continue

        # ── Check 4: lightweight check for 2-bot VMs ──────────
        if bot_count == VM_MAX_BOTS_PER_VM - 1:  # == 2
            if not _check_vm_lightweight(vm):
                _log("vm_check", {
                    "vm_id":  vm["vm_id"],
                    "result": "2 bots but not lightweight — rejected",
                })
                continue

        candidates.append((free_ram, vm))
        db.log_event("vm_check", {
            "vm_id":     vm["vm_id"],
            "free_ram":  free_ram,
            "bot_count": bot_count,
            "result":    "eligible",
        })

    if not candidates:
        _log("vm_check", {"result": "no eligible VMs found"})
        return None

    # Pick VM with most free RAM
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


# ── Helper: get VM config from DB for a bot ──────────────────────

def get_vm_for_bot(bot_id: str) -> tuple[Optional[dict], Optional[dict]]:
    """Returns (bot_record, vm_config) or (None, None)."""
    if not _MONGO_OK or db is None:
        return None, None
    bot = db.get_bot(bot_id)
    if not bot:
        return None, None
    vm = db.get_vm(bot["vm_id"])
    return bot, vm
