"""
MongoDB Overflow + Auto-Unlock Storage Manager
===============================================

URI States:
  "active"   -> accepting reads + writes (current write target)
  "readonly" -> full (used >= 462MB), reads only, no new writes
  "unlocked" -> was readonly, user deleted data, now writable again
  "offline"  -> unreachable

Write Rule:
  Find first URI that is "active" or "unlocked".
  Only ONE write target at a time.
  If active URI hits 462MB -> mark "readonly" instantly.
  When data is deleted -> check if readonly URIs dropped
  below 437MB -> if yes mark "unlocked" -> writable again.

Read Rule:
  Search ALL URIs (active + readonly + unlocked) until found.
  Data never moves between URIs.

50MB Buffer Rule:
  Each URI keeps 50MB free at all times.
  READONLY_MB = 462  (512 - 50 = readonly threshold)
  WRITABLE_MB = 437  (512 - 75 = safe to write again)
  Gap between readonly and writable = 25MB wiggle room
  So small up/down fluctuations don't flip state constantly.

Example flow:
  URI-1: 463MB used -> readonly  (old bots ESH-0001..0600)
  User deletes 30 bots -> URI-1: 430MB used -> unlocked
  New bots go to URI-1 again until 462MB
  URI-1: 464MB used -> readonly again
  URI-2: 0MB -> becomes active <- overflow kicks in
  URI-3: not added yet, admin adds when URI-2 fills
"""

from __future__ import annotations

import os
import threading
import time
from typing import Optional, Any
from pymongo import MongoClient, DESCENDING
from pymongo.errors import PyMongoError

# Standalone config (no config.py dependency — main bot keeps inline config).
# Values match fresh-panel config.py; ADMIN_IDS/BOT_TOKEN read lazily via env
# so main bot.py can also inject them via set_notifier().
MONGO_LIMIT_MB    = int(os.environ.get("MONGO_LIMIT_MB", "512"))
MONGO_READONLY_MB = int(os.environ.get("MONGO_READONLY_MB", "462"))
MONGO_WRITABLE_MB = int(os.environ.get("MONGO_WRITABLE_MB", "437"))
MONGO_WARN_MB     = int(os.environ.get("MONGO_WARN_MB", "420"))
ADMIN_IDS: list = []
BOT_TOKEN = ""


def set_notifier(bot_token: str, admin_ids: list) -> None:
    """Called by main bot.py at startup to wire Telegram notifications."""
    global BOT_TOKEN, ADMIN_IDS
    BOT_TOKEN = bot_token or BOT_TOKEN
    ADMIN_IDS = list(admin_ids) if admin_ids else ADMIN_IDS

DB_NAME = "esh_hostera"

# ── URI Pool ─────────────────────────────────────────────────────
# Each entry is a dict:
# {
#   "uri":    str,
#   "client": MongoClient,
#   "state":  "active" | "readonly" | "unlocked" | "offline",
#   "index":  int   (1-based, for display)
# }
_pool: list[dict] = []
_initialized = False
_pool_lock = threading.RLock()

_notify_bot = None  # lazy singleton for admin notifications


# ────────────────────────────────────────────────────────────────
#  INIT
# ────────────────────────────────────────────────────────────────

def init_db():
    global _initialized
    with _pool_lock:
        if _initialized:
            return

        primary = os.environ.get("MONGO_URI_1", "") or "mongodb+srv://Esh:1234567890ukwhat@cluster0.mnbnc7a.mongodb.net"
        if not primary:
            raise RuntimeError("MONGO_URI_1 is required!")

        _connect_uri_locked(primary)

        # Load additional URIs saved by admin
        try:
            saved = _pool[0]["client"][DB_NAME]["db_uris"].find(
                {}, {"_id": 0, "uri": 1}
            )
            for doc in saved:
                if not _in_pool_locked(doc["uri"]):
                    _connect_uri_locked(doc["uri"])
        except Exception as e:
            print(f"[db] Could not load saved URIs: {e}", flush=True)

        _ensure_indexes_locked()

        _initialized = True
        print(f"[db] {len(_pool)} MongoDB URI(s) connected", flush=True)
        for e in _pool:
            mb = _get_used_mb(e["client"])
            print(
                f"[db]   URI-{e['index']}: {mb:.1f}MB used "
                f"/ {MONGO_LIMIT_MB}MB -> state={e['state']}",
                flush=True,
            )


def _ensure_indexes_locked():
    """Create indexes on every connected URI (best-effort)."""
    for entry in _pool:
        try:
            d = entry["client"][DB_NAME]
            d["users"].create_index("user_id", unique=True)
            d["hosted_bots"].create_index("bot_id", unique=True)
            d["hosted_bots"].create_index("owner_id")
            d["hosted_bots"].create_index([("vm_id", 1), ("status", 1)])
            d["vms"].create_index("vm_id", unique=True)
            d["settings"].create_index("key", unique=True)
            d["system_logs"].create_index("timestamp")
        except Exception as e:
            print(f"[db] index warn URI-{entry['index']}: {e}", flush=True)


def _connect_uri(uri: str) -> bool:
    with _pool_lock:
        return _connect_uri_locked(uri)


def _connect_uri_locked(uri: str) -> bool:
    """Connect to URI, detect initial state, add to pool. Lock must be held."""
    if _in_pool_locked(uri):
        return True
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        client.admin.command("ping")
        used_mb = _get_used_mb(client)
        state = _calc_state(used_mb)
        index = len(_pool) + 1
        _pool.append({
            "uri": uri,
            "client": client,
            "state": state,
            "index": index,
        })
        print(
            f"[db] Connected URI-{index}: {_mask(uri)} "
            f"({used_mb:.1f}MB, state={state})",
            flush=True,
        )
        return True
    except Exception as e:
        print(f"[db] Connect failed {_mask(uri)}: {e}", flush=True)
        return False


def _in_pool(uri: str) -> bool:
    with _pool_lock:
        return _in_pool_locked(uri)


def _in_pool_locked(uri: str) -> bool:
    return any(e["uri"] == uri for e in _pool)


def _mask(uri: str) -> str:
    return uri[:20] + "..." + uri[-10:] if len(uri) > 35 else uri


def _calc_state(used_mb: float) -> str:
    """Calculate state from usage."""
    if used_mb >= MONGO_READONLY_MB:
        return "readonly"
    return "active"


def _get_used_mb(client: MongoClient) -> float:
    """Get actual storage used in MB (storageSize preferred, fallback dataSize)."""
    try:
        stats = client[DB_NAME].command("dbStats")
        # storageSize includes preallocated extents; most accurate for Atlas quota.
        # dataSize undercounts indexes. Prefer storageSize when present.
        b = stats.get("storageSize", 0) or stats.get("dataSize", 0)
        return b / (1024 * 1024)
    except Exception:
        return 0.0


# ────────────────────────────────────────────────────────────────
#  STATE MANAGEMENT
# ────────────────────────────────────────────────────────────────

def _check_states():
    """
    Recheck all URI states based on current usage.
    Called after every write AND after every delete.

    Transitions:
      active   -> readonly  when used_mb >= READONLY_MB (462)
      readonly -> unlocked  when used_mb <= WRITABLE_MB (437)
      unlocked -> readonly  when used_mb >= READONLY_MB again
      unlocked -> active    it is active for writes
    """
    with _pool_lock:
        for entry in _pool:
            if entry["state"] == "offline":
                # retry ping — may have come back
                try:
                    entry["client"].admin.command("ping")
                    entry["state"] = _calc_state(_get_used_mb(entry["client"]))
                    continue
                except Exception:
                    continue
            try:
                entry["client"].admin.command("ping")
            except Exception:
                entry["state"] = "offline"
                continue

            used_mb = _get_used_mb(entry["client"])
            old_state = entry["state"]

            if used_mb >= MONGO_READONLY_MB:
                # Full -> readonly no matter what
                if entry["state"] != "readonly":
                    entry["state"] = "readonly"
                    print(
                        f"[db] URI-{entry['index']} READONLY "
                        f"({used_mb:.1f}MB >= {MONGO_READONLY_MB}MB)",
                        flush=True,
                    )
                    _notify_admin_readonly(entry["index"], used_mb)

            elif used_mb <= MONGO_WRITABLE_MB:
                # Enough space freed -> unlock
                if entry["state"] == "readonly":
                    entry["state"] = "unlocked"
                    print(
                        f"[db] URI-{entry['index']} UNLOCKED "
                        f"({used_mb:.1f}MB <= {MONGO_WRITABLE_MB}MB)",
                        flush=True,
                    )
                    _notify_admin_unlocked(entry["index"], used_mb)

            # Warn admin at 420MB
            if MONGO_WARN_MB <= used_mb < MONGO_READONLY_MB:
                if old_state == "active":
                    _notify_admin_warn(entry["index"], used_mb)


def _get_write_entry() -> Optional[dict]:
    """
    Get the current write target URI entry.
    Priority:
      1. First "unlocked" URI  (freed up space, use it first)
      2. First "active" URI    (normal write target)
      3. None                  (all full -> notify admin)
    """
    _check_states()
    with _pool_lock:
        # Try unlocked first (space was freed, use it before overflow)
        for entry in _pool:
            if entry["state"] == "unlocked":
                return entry

        # Then try active
        for entry in _pool:
            if entry["state"] == "active":
                return entry

    # All full
    _notify_admin_all_full()
    return None


# ────────────────────────────────────────────────────────────────
#  ADMIN NOTIFICATIONS
# ────────────────────────────────────────────────────────────────

def _get_notify_bot():
    global _notify_bot
    if _notify_bot is not None:
        return _notify_bot
    if not BOT_TOKEN:
        return None
    try:
        import telebot
        _notify_bot = telebot.TeleBot(BOT_TOKEN, threaded=False)
        return _notify_bot
    except Exception:
        return None


def _notify(msg: str):
    """Send message to all admins."""
    if not ADMIN_IDS:
        return
    try:
        b = _get_notify_bot()
        if not b:
            return
        for admin_id in ADMIN_IDS:
            try:
                b.send_message(admin_id, msg, parse_mode="HTML")
            except Exception:
                pass
    except Exception:
        pass


def _notify_admin_warn(index: int, used_mb: float):
    free = MONGO_LIMIT_MB - used_mb
    _notify(
        f"⚠️ <b>MongoDB URI-{index} Getting Full</b>\n\n"
        f"Used: <b>{used_mb:.0f}MB / {MONGO_LIMIT_MB}MB</b>\n"
        f"Free: <b>{free:.0f}MB</b>\n\n"
        f"Add a new MongoDB URI soon!\n"
        f"Admin Panel → DB Manager → Add URI"
    )


def _notify_admin_readonly(index: int, used_mb: float):
    _notify(
        f"🔒 <b>MongoDB URI-{index} is now READ-ONLY</b>\n\n"
        f"Used: <b>{used_mb:.0f}MB / {MONGO_LIMIT_MB}MB</b>\n"
        f"New data will overflow to next URI.\n\n"
        f"Add a new URI if not done already!\n"
        f"Admin Panel → DB Manager → Add URI"
    )


def _notify_admin_unlocked(index: int, used_mb: float):
    free = MONGO_LIMIT_MB - used_mb
    _notify(
        f"🔓 <b>MongoDB URI-{index} Unlocked!</b>\n\n"
        f"Users freed up space.\n"
        f"Used: <b>{used_mb:.0f}MB</b> | Free: <b>{free:.0f}MB</b>\n"
        f"Writes resuming on this URI."
    )


def _notify_admin_all_full():
    _notify(
        f"🚨 <b>ALL MongoDB URIs Are Full!</b>\n\n"
        f"Cannot save new data!\n"
        f"Add a new URI immediately:\n"
        f"Admin Panel → DB Manager → Add URI"
    )


# ────────────────────────────────────────────────────────────────
#  CORE READ / WRITE
# ────────────────────────────────────────────────────────────────

def _write(col: str, op: str, *args, **kwargs):
    """Write to current active URI."""
    entry = _get_write_entry()
    if not entry:
        raise RuntimeError("All MongoDB URIs are full!")
    return getattr(entry["client"][DB_NAME][col], op)(*args, **kwargs)


def _find_one(col: str, query: dict) -> Optional[dict]:
    """Search ALL URIs for one document."""
    with _pool_lock:
        pool = list(_pool)
    for entry in pool:
        if entry["state"] == "offline":
            continue
        try:
            doc = entry["client"][DB_NAME][col].find_one(
                query, {"_id": 0}
            )
            if doc:
                return doc
        except Exception:
            continue
    return None


def _find_many(col: str, query: dict,
               sort_key: str = None,
               limit: int = 0) -> list[dict]:
    """Search ALL URIs, combine + deduplicate results."""
    results = []
    seen = set()
    with _pool_lock:
        pool = list(_pool)
    for entry in pool:
        if entry["state"] == "offline":
            continue
        try:
            cur = entry["client"][DB_NAME][col].find(query, {"_id": 0})
            if sort_key:
                cur = cur.sort(sort_key, DESCENDING)
            if limit:
                cur = cur.limit(limit)
            for doc in cur:
                key = (
                    doc.get("bot_id") or
                    doc.get("user_id") or
                    doc.get("vm_id") or
                    doc.get("key") or
                    str(doc)
                )
                if key not in seen:
                    seen.add(key)
                    results.append(doc)
        except Exception:
            continue
    return results


def _find_owner(col: str, query: dict) -> Optional[MongoClient]:
    """Find which URI already has this document."""
    with _pool_lock:
        pool = list(_pool)
    for entry in pool:
        if entry["state"] == "offline":
            continue
        try:
            if entry["client"][DB_NAME][col].find_one(query, {"_id": 1}):
                return entry["client"]
        except Exception:
            continue
    return None


def _update_existing_or_write(col: str, query: dict, update: dict):
    """
    Update on the URI that already has the document.
    If not found anywhere -> write to active URI.
    This keeps documents on their original URI.
    """
    owner = _find_owner(col, query)
    if owner:
        owner[DB_NAME][col].update_one(query, update, upsert=True)
    else:
        _write(col, "update_one", query, update, upsert=True)


# ────────────────────────────────────────────────────────────────
#  URI MANAGEMENT (Admin Panel)
# ────────────────────────────────────────────────────────────────

def add_uri(uri: str) -> dict:
    """Add new MongoDB URI from admin panel."""
    if _in_pool(uri):
        return {"ok": False, "error": "URI already connected"}

    ok = _connect_uri(uri)
    if not ok:
        return {"ok": False, "error": "Could not connect to this URI"}

    # Persist to primary DB so it loads on restart
    try:
        with _pool_lock:
            primary = _pool[0]["client"]
        primary[DB_NAME]["db_uris"].update_one(
            {"uri": uri},
            {"$set": {"uri": uri, "added_at": time.time()}},
            upsert=True,
        )
    except Exception as e:
        print(f"[db] Could not persist URI: {e}", flush=True)

    with _pool_lock:
        total = len(_pool)
    return {"ok": True, "total": total}


def remove_uri(uri: str) -> dict:
    """Remove URI from pool. Cannot remove primary (index 0)."""
    with _pool_lock:
        entry = next((e for e in _pool if e["uri"] == uri), None)
        if not entry:
            return {"ok": False, "error": "URI not found"}
        if entry["index"] == 1:
            return {"ok": False, "error": "Cannot remove primary URI"}

    try:
        entry["client"].close()
    except Exception:
        pass
    with _pool_lock:
        if entry in _pool:
            _pool.remove(entry)

    # Remove from primary DB
    try:
        with _pool_lock:
            primary = _pool[0]["client"] if _pool else None
        if primary is not None:
            primary[DB_NAME]["db_uris"].delete_one({"uri": uri})
    except Exception:
        pass

    return {"ok": True}


def list_uris() -> list[dict]:
    """Full URI status list for admin panel."""
    result = []
    with _pool_lock:
        pool = list(_pool)
    for entry in pool:
        used_mb = _get_used_mb(entry["client"])
        free_mb = MONGO_LIMIT_MB - used_mb
        online = True
        try:
            entry["client"].admin.command("ping")
        except Exception:
            online = False
            with _pool_lock:
                entry["state"] = "offline"
        result.append({
            "index": entry["index"],
            "masked": _mask(entry["uri"]),
            "uri": entry["uri"],
            "primary": entry["index"] == 1,
            "state": entry["state"],
            "online": online,
            "used_mb": round(used_mb, 1),
            "free_mb": round(free_mb, 1),
            "pct": round(used_mb / MONGO_LIMIT_MB * 100, 1),
        })
    return result


def totals() -> dict:
    """Aggregate totals across every URI (for Mongo menu header)."""
    uris = list_uris()
    n = len(uris)
    used = round(sum(u.get("used_mb", 0) for u in uris), 1)
    free = round(n * MONGO_LIMIT_MB - used, 1)
    online = sum(1 for u in uris if u.get("online"))
    return {"uris": n, "limit_mb": MONGO_LIMIT_MB, "used_mb": used,
            "free_mb": free, "online": online}


def uri_details(index: int) -> dict:
    """Fetch all details for one URI: stats + per-collection counts."""
    with _pool_lock:
        entry = next((e for e in _pool if e.get("index") == index), None)
    if not entry:
        return {"ok": False, "error": "URI not found"}
    client = entry["client"]
    try:
        client.admin.command("ping")
        online = True
    except Exception as e:
        return {"ok": False, "error": f"offline: {e}"}
    try:
        stats = client[DB_NAME].command("dbStats")
    except Exception:
        stats = {}
    cols = {}
    for c in ("users", "hosted_bots", "vms", "settings", "system_logs",
              "db_uris", "counters", "fs.files", "fs.chunks"):
        try:
            cols[c] = client[DB_NAME][c].count_documents({})
        except Exception:
            cols[c] = -1
    try:
        running = client[DB_NAME]["hosted_bots"].count_documents({"status": "running"})
    except Exception:
        running = -1
    used_mb = _get_used_mb(client)
    return {"ok": True, "index": entry["index"], "masked": _mask(entry["uri"]),
            "primary": entry["index"] == 1, "state": entry["state"], "online": online,
            "used_mb": round(used_mb, 1), "free_mb": round(MONGO_LIMIT_MB - used_mb, 1),
            "limit_mb": MONGO_LIMIT_MB,
            "storage_mb": round((stats.get("storageSize", 0) or 0) / 1048576, 1),
            "data_mb": round((stats.get("dataSize", 0) or 0) / 1048576, 1),
            "indexes_mb": round((stats.get("indexSize", 0) or 0) / 1048576, 1),
            "collections": cols, "running_bots": running}


# ────────────────────────────────────────────────────────────────
#  USER OPERATIONS
# ────────────────────────────────────────────────────────────────

def get_user(user_id: int) -> Optional[dict]:
    return _find_one("users", {"user_id": user_id})


def save_user(user: dict):
    _update_existing_or_write(
        "users",
        {"user_id": user["user_id"]},
        {"$set": {**user, "updated_at": time.time()}},
    )


def ensure_user(user_id: int, username: str = "") -> dict:
    user = get_user(user_id)
    if not user:
        user = {
            "user_id": user_id,
            "username": username,
            "plan": "free",
            "joined_at": time.time(),
            "banned": False,
        }
        save_user(user)
    return user


def get_all_users() -> list[dict]:
    return _find_many("users", {})


# ────────────────────────────────────────────────────────────────
#  VM OPERATIONS
# ────────────────────────────────────────────────────────────────

def get_vm(vm_id: str) -> Optional[dict]:
    return _find_one("vms", {"vm_id": vm_id})


def get_all_vms() -> dict:
    return {v["vm_id"]: v for v in _find_many("vms", {})}


def get_enabled_vms() -> list[dict]:
    return _find_many("vms", {"enabled": True})


def save_vm(vm: dict):
    _update_existing_or_write(
        "vms",
        {"vm_id": vm["vm_id"]},
        {"$set": vm},
    )


def remove_vm(vm_id: str):
    with _pool_lock:
        pool = list(_pool)
    for entry in pool:
        if entry["state"] == "offline":
            continue
        try:
            entry["client"][DB_NAME]["vms"].delete_one({"vm_id": vm_id})
        except Exception:
            pass
    _check_states()   # deletion may unlock a readonly URI


# ────────────────────────────────────────────────────────────────
#  BOT FILE STORAGE (GridFS)
# ────────────────────────────────────────────────────────────────

def save_bot_file(bot_id: str, filename: str, data: bytes) -> bool:
    """Save bot file to active URI using GridFS."""
    try:
        import gridfs as gfs
        entry = _get_write_entry()
        if not entry:
            return False
        fs = gfs.GridFS(entry["client"][DB_NAME])
        # Remove old version
        for f in fs.find({"bot_id": bot_id}):
            fs.delete(f._id)
        fs.put(data, filename=filename,
               bot_id=bot_id, uploaded_at=time.time())
        _check_states()
        return True
    except Exception as e:
        print(f"[db] GridFS save error: {e}", flush=True)
        return False


def get_bot_file(bot_id: str) -> Optional[bytes]:
    """Get bot file from any URI (for redeployment)."""
    try:
        import gridfs as gfs
        with _pool_lock:
            pool = list(_pool)
        for entry in pool:
            if entry["state"] == "offline":
                continue
            try:
                fs = gfs.GridFS(entry["client"][DB_NAME])
                file = fs.find_one({"bot_id": bot_id})
                if file:
                    return file.read()
            except Exception:
                continue
    except Exception as e:
        print(f"[db] GridFS read error: {e}", flush=True)
    return None


def delete_bot_file(bot_id: str):
    """Delete bot file from all URIs + recheck states."""
    try:
        import gridfs as gfs
        with _pool_lock:
            pool = list(_pool)
        for entry in pool:
            if entry["state"] == "offline":
                continue
            try:
                fs = gfs.GridFS(entry["client"][DB_NAME])
                for f in fs.find({"bot_id": bot_id}):
                    fs.delete(f._id)
            except Exception:
                pass
    except Exception:
        pass
    # Deletion may free enough space to unlock a readonly URI
    _check_states()


# ────────────────────────────────────────────────────────────────
#  HOSTED BOT OPERATIONS
# ────────────────────────────────────────────────────────────────

def get_bot(bot_id: str) -> Optional[dict]:
    return _find_one("hosted_bots", {"bot_id": bot_id})


def save_bot(bot_record: dict):
    _update_existing_or_write(
        "hosted_bots",
        {"bot_id": bot_record["bot_id"]},
        {"$set": {**bot_record, "updated_at": time.time()}},
    )
    _check_states()


def delete_bot_record(bot_id: str):
    """Delete bot record + file, then recheck URI states."""
    with _pool_lock:
        pool = list(_pool)
    for entry in pool:
        if entry["state"] == "offline":
            continue
        try:
            entry["client"][DB_NAME]["hosted_bots"].delete_one(
                {"bot_id": bot_id}
            )
        except Exception:
            pass
    delete_bot_file(bot_id)
    # _check_states() already called inside delete_bot_file


def get_user_bots(user_id: int) -> list[dict]:
    return _find_many("hosted_bots", {"owner_id": user_id})


def get_vm_bots(vm_id: str) -> list[dict]:
    return _find_many("hosted_bots", {"vm_id": vm_id})


def count_vm_running_bots(vm_id: str) -> int:
    total = 0
    with _pool_lock:
        pool = list(_pool)
    for entry in pool:
        if entry["state"] == "offline":
            continue
        try:
            total += entry["client"][DB_NAME]["hosted_bots"].count_documents(
                {"vm_id": vm_id, "status": "running"}
            )
        except Exception:
            pass
    return total


# ────────────────────────────────────────────────────────────────
#  BOT ID COUNTER
# ────────────────────────────────────────────────────────────────

def get_next_bot_id() -> str:
    """Use first writable URI for counter (primary preferred)."""
    with _pool_lock:
        pool = list(_pool)
    # Prefer primary if writable, else first unlocked/active
    ordered = sorted(pool, key=lambda e: (0 if e["index"] == 1 else 1, e["index"]))
    for entry in ordered:
        if entry["state"] not in ("active", "unlocked"):
            continue
        try:
            result = entry["client"][DB_NAME]["counters"].find_one_and_update(
                {"_id": "bot_counter"},
                {"$inc": {"seq": 1}},
                upsert=True,
                return_document=True,
            )
            if result and "seq" in result:
                return f"ESH-{result['seq']:04d}"
        except Exception:
            continue
    print("[db] Counter error: no writable URI", flush=True)
    return f"ESH-{int(time.time()) % 9999:04d}"


# ────────────────────────────────────────────────────────────────
#  SYSTEM LOGS
# ────────────────────────────────────────────────────────────────

def log_event(event_type: str, data: dict):
    try:
        doc = {
            "type": event_type,
            "timestamp": time.time(),
            "ts_str": time.strftime("%Y-%m-%d %H:%M:%S"),
            **data,
        }
        _write("system_logs", "insert_one", doc)
    except Exception as e:
        print(f"[db] Log failed: {e}", flush=True)


def get_logs(event_type: str = None, limit: int = 50) -> list[dict]:
    query = {"type": event_type} if event_type else {}
    return _find_many("system_logs", query,
                      sort_key="timestamp", limit=limit)


# ────────────────────────────────────────────────────────────────
#  SETTINGS
# ────────────────────────────────────────────────────────────────

def get_setting(key: str, default=None):
    doc = _find_one("settings", {"key": key})
    return doc["value"] if doc else default


def set_setting(key: str, value: Any):
    _update_existing_or_write(
        "settings",
        {"key": key},
        {"$set": {"key": key, "value": value}},
    )
