#!/usr/bin/env python3
"""
core/logger.py — sqlmap-style logging engine for php2shell
Author: ATHEX BLACK HAT

Features:
  - Levels: DEBUG, INFO, SUCCESS, WARNING, ERROR, CRITICAL + custom (VULN, FIXED, WAF, BYPASS, ...)
  - Timestamps (HH:MM:SS)
  - Thread-safe (global lock)
  - tqdm-safe (external_write_mode when progress bar active)
  - Optional file logging (rotating)
  - NO_COLOR / non-TTY auto-detect
  - Structured context (target, module, duration)
  - Optional JSON-lines log for machine parsing
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional

from core.config import TOOL_NAME, TOOL_VERSION

# tqdm optional (already a dependency, but guard anyway)
try:
    from tqdm import tqdm as _tqdm
except ImportError:
    _tqdm = None


# ═══════════════════════════════════════════════════════════════════════════
#  COLORS
# ═══════════════════════════════════════════════════════════════════════════

class Colors:
    """ANSI escape codes. Mutated to empty strings when color is disabled."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"

    BLACK = "\033[30m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"

    # Background
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"


def _strip_colors() -> None:
    """Zero out all color codes (used when NO_COLOR / non-TTY)."""
    for attr in dir(Colors):
        if attr.isupper() and not attr.startswith("_"):
            setattr(Colors, attr, "")


# ═══════════════════════════════════════════════════════════════════════════
#  LOG LEVELS
# ═══════════════════════════════════════════════════════════════════════════

# Numeric level → (tag, color, python_logging_level)
LEVELS: Dict[str, Dict[str, Any]] = {
    "DEBUG":     {"tag": "DEBUG",     "color": "GRAY",                "numeric": 10},
    "INFO":      {"tag": "INFO",      "color": "CYAN",                "numeric": 20},
    "SUCCESS":   {"tag": "SUCCESS",   "color": "GREEN",               "numeric": 25},
    "FIXED":     {"tag": "FIXED",     "color": "GREEN",               "numeric": 25},
    "WARNING":   {"tag": "WARNING",   "color": "YELLOW",              "numeric": 30},
    "WARN":      {"tag": "WARNING",   "color": "YELLOW",              "numeric": 30},
    "ERROR":     {"tag": "ERROR",     "color": "RED",                 "numeric": 40},
    "CRITICAL":  {"tag": "CRITICAL",  "color": "RED",                 "numeric": 50},
    # Custom semantic levels
    "VULN":      {"tag": "VULN",      "color": "RED",                 "numeric": 60},
    "WAF":       {"tag": "WAF",       "color": "YELLOW",              "numeric": 35},
    "BYPASS":    {"tag": "BYPASS",    "color": "GREEN",               "numeric": 55},
    "PAYLOAD":   {"tag": "PAYLOAD",   "color": "MAGENTA",             "numeric": 15},
    "FP":        {"tag": "FP",        "color": "BLUE",                "numeric": 20},
    "AUDIT":     {"tag": "AUDIT",     "color": "BLUE",                "numeric": 20},
    "TLS":       {"tag": "TLS",       "color": "CYAN",                "numeric": 20},
    "NOTICE":    {"tag": "NOTICE",    "color": "WHITE",               "numeric": 25},
}

# Aliases (shortcuts)
LEVEL_ALIASES: Dict[str, str] = {
    "V": "VULN",
    "W": "WARNING",
    "E": "ERROR",
    "I": "INFO",
    "D": "DEBUG",
    "S": "SUCCESS",
}


# ═══════════════════════════════════════════════════════════════════════════
#  LOGGER
# ═══════════════════════════════════════════════════════════════════════════

class Logger:
    """
    Thread-safe, tqdm-safe, sqlmap-style logger.

    Usage:
        Logger.info("Loaded 5 hosts")
        Logger.vuln("target.com is vulnerable")
        Logger.error("connection failed", extra={"target": "example.com"})

    Config:
        Logger.configure(level="INFO", color=True, log_file=None, json_log=None)
    """

    _lock = threading.RLock()
    _color_enabled = True
    _level_threshold = 20  # INFO by default
    _log_file_handler: Optional[logging.Handler] = None
    _json_log_handler: Optional[logging.Handler] = None
    _quiet = False
    _silent_modules: set = set()
    _verbosity_count = 0  # -v / -vv
    _start_time = time.perf_counter()

    # ─────────────────────────────────────────────────────────────────────
    #  CONFIGURATION
    # ─────────────────────────────────────────────────────────────────────

    @classmethod
    def configure(
        cls,
        level: str = "INFO",
        color: Optional[bool] = None,
        log_file: Optional[str] = None,
        json_log: Optional[str] = None,
        quiet: bool = False,
        no_color: bool = False,
        verbosity: int = 0,
    ) -> None:
        """
        Configure the logger. Safe to call multiple times.

        Args:
            level: min level name (DEBUG, INFO, WARNING, ERROR)
            color: True/False to force, None = auto-detect
            log_file: path for plaintext log (rotating, 10MB x 5)
            json_log: path for JSON-lines log
            quiet: suppress all non-VULN/CRITICAL output
            no_color: force disable color
            verbosity: 0=normal, 1=-v, 2=-vv
        """
        with cls._lock:
            # Level
            lvl = LEVELS.get((level or "INFO").upper(), LEVELS["INFO"])
            cls._level_threshold = lvl["numeric"]

            # Quiet
            cls._quiet = quiet

            # Verbosity
            cls._verbosity_count = max(0, verbosity)
            if verbosity >= 2:
                cls._level_threshold = min(cls._level_threshold, LEVELS["DEBUG"]["numeric"])
            elif verbosity >= 1:
                cls._level_threshold = min(cls._level_threshold, LEVELS["INFO"]["numeric"])

            # Color
            if no_color:
                cls._color_enabled = False
            elif color is not None:
                cls._color_enabled = color
            else:
                cls._color_enabled = cls._auto_color()
            if not cls._color_enabled:
                _strip_colors()

            # Plaintext log file
            cls._detach_handler("_log_file_handler")
            if log_file:
                cls._attach_file_handler(log_file)

            # JSON log
            cls._detach_handler("_json_log_handler")
            if json_log:
                cls._attach_json_handler(json_log)

    @classmethod
    def _auto_color(cls) -> bool:
        if os.environ.get("NO_COLOR") is not None:
            return False
        if os.environ.get("FORCE_COLOR") is not None:
            return True
        if os.environ.get("TERM", "") == "dumb":
            return False
        return sys.stdout.isatty()

    @classmethod
    def _attach_file_handler(cls, path: str) -> None:
        try:
            p = Path(path).expanduser()
            p.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(
                p, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
            )
            handler.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            ))
            py_logger = logging.getLogger(TOOL_NAME)
            py_logger.setLevel(logging.DEBUG)
            py_logger.addHandler(handler)
            cls._log_file_handler = handler
            cls.debug(f"Log file attached: {p}")
        except OSError as exc:
            print(f"[WARNING] Could not open log file {path}: {exc}", file=sys.stderr)

    @classmethod
    def _attach_json_handler(cls, path: str) -> None:
        try:
            p = Path(path).expanduser()
            p.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(
                p, maxBytes=50 * 1024 * 1024, backupCount=3, encoding="utf-8"
            )
            handler.setFormatter(JSONLineFormatter())
            py_logger = logging.getLogger(f"{TOOL_NAME}.json")
            py_logger.setLevel(logging.DEBUG)
            py_logger.addHandler(handler)
            cls._json_log_handler = handler
            cls.debug(f"JSON log attached: {p}")
        except OSError as exc:
            print(f"[WARNING] Could not open JSON log {path}: {exc}", file=sys.stderr)

    @classmethod
    def _detach_handler(cls, attr: str) -> None:
        handler = getattr(cls, attr, None)
        if handler is None:
            return
        for name in (TOOL_NAME, f"{TOOL_NAME}.json"):
            py_logger = logging.getLogger(name)
            py_logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass
        setattr(cls, attr, None)

    # ─────────────────────────────────────────────────────────────────────
    #  SILENCING (per-module)
    # ─────────────────────────────────────────────────────────────────────

    @classmethod
    def silence_module(cls, name: str) -> None:
        cls._silent_modules.add(name.lower())

    @classmethod
    def unsilence_module(cls, name: str) -> None:
        cls._silent_modules.discard(name.lower())

    # ─────────────────────────────────────────────────────────────────────
    #  CORE EMIT
    # ─────────────────────────────────────────────────────────────────────

    @classmethod
    def _should_emit(cls, level_key: str, numeric: int, module: Optional[str]) -> bool:
        if module and module.lower() in cls._silent_modules:
            return False
        if cls._quiet:
            # In quiet mode, only VULN / CRITICAL / BYPASS pass through
            return level_key in ("VULN", "CRITICAL", "BYPASS")
        return numeric >= cls._level_threshold

    @classmethod
    def log(
        cls,
        level: str,
        message: str,
        *,
        module: Optional[str] = None,
        target: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
        exc_info: bool = False,
    ) -> None:
        """Core logging entry point. Thread-safe."""
        key = LEVEL_ALIASES.get(level.upper(), level.upper())
        meta = LEVELS.get(key)
        if meta is None:
            key = "INFO"
            meta = LEVELS["INFO"]

        if not cls._should_emit(key, meta["numeric"], module):
            return

        ts = datetime.now().strftime("%H:%M:%S")
        tag = meta["tag"]
        color = getattr(Colors, meta["color"], "")
        tag_colored = f"{color}{Colors.BOLD}[{tag}]{Colors.RESET}" if cls._color_enabled else f"[{tag}]"
        ts_colored = f"{Colors.GRAY}[{ts}]{Colors.RESET}" if cls._color_enabled else f"[{ts}]"

        # Optional context prefix:  (module) (target)
        ctx_parts = []
        if module:
            ctx_parts.append(f"({Colors.BLUE}{module}{Colors.RESET})" if cls._color_enabled else f"({module})")
        if target:
            ctx_parts.append(f"({Colors.WHITE}{target}{Colors.RESET})" if cls._color_enabled else f"({target})")
        ctx = " ".join(ctx_parts)
        ctx_str = f" {ctx}" if ctx else ""

        line = f"{ts_colored} {tag_colored}{ctx_str} {message}"

        with cls._lock:
            # tqdm-safe output
            if _tqdm is not None and _is_tqdm_active():
                with _tqdm.external_write_mode():
                    print(line, file=sys.stdout, flush=True)
            else:
                print(line, file=sys.stdout, flush=True)

            # Plaintext log
            if cls._log_file_handler is not None:
                py_logger = logging.getLogger(TOOL_NAME)
                py_logger.log(
                    min(meta["numeric"], logging.CRITICAL) if meta["numeric"] <= 50 else logging.CRITICAL,
                    message if not (module or target) else f"[{module or '-'}|{target or '-'}] {message}",
                )

            # JSON log
            if cls._json_log_handler is not None:
                record = {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "level": key,
                    "module": module,
                    "target": target,
                    "message": message,
                }
                if extra:
                    record["extra"] = extra
                py_logger = logging.getLogger(f"{TOOL_NAME}.json")
                py_logger.log(logging.INFO, record)

    # ─────────────────────────────────────────────────────────────────────
    #  PUBLIC API
    # ─────────────────────────────────────────────────────────────────────

    @classmethod
    def debug(cls, msg: str, **kw: Any) -> None:     cls.log("DEBUG", msg, **kw)
    @classmethod
    def info(cls, msg: str, **kw: Any) -> None:      cls.log("INFO", msg, **kw)
    @classmethod
    def success(cls, msg: str, **kw: Any) -> None:   cls.log("SUCCESS", msg, **kw)
    @classmethod
    def notice(cls, msg: str, **kw: Any) -> None:    cls.log("NOTICE", msg, **kw)
    @classmethod
    def warning(cls, msg: str, **kw: Any) -> None:   cls.log("WARNING", msg, **kw)
    @classmethod
    def error(cls, msg: str, **kw: Any) -> None:     cls.log("ERROR", msg, **kw)
    @classmethod
    def critical(cls, msg: str, **kw: Any) -> None:  cls.log("CRITICAL", msg, **kw)

    # Semantic helpers
    @classmethod
    def vuln(cls, msg: str, **kw: Any) -> None:      cls.log("VULN", msg, **kw)
    @classmethod
    def fixed(cls, msg: str, **kw: Any) -> None:     cls.log("FIXED", msg, **kw)
    @classmethod
    def waf(cls, msg: str, **kw: Any) -> None:       cls.log("WAF", msg, **kw)
    @classmethod
    def bypass(cls, msg: str, **kw: Any) -> None:    cls.log("BYPASS", msg, **kw)
    @classmethod
    def payload(cls, msg: str, **kw: Any) -> None:   cls.log("PAYLOAD", msg, **kw)
    @classmethod
    def fingerprint(cls, msg: str, **kw: Any) -> None: cls.log("FP", msg, **kw)
    @classmethod
    def audit(cls, msg: str, **kw: Any) -> None:     cls.log("AUDIT", msg, **kw)
    @classmethod
    def tls(cls, msg: str, **kw: Any) -> None:       cls.log("TLS", msg, **kw)

    # ─────────────────────────────────────────────────────────────────────
    #  HELPERS: colorize, header, separator
    # ─────────────────────────────────────────────────────────────────────

    @classmethod
    def colorize(cls, text: str, color_name: str, bold: bool = False) -> str:
        if not cls._color_enabled:
            return text
        color = getattr(Colors, color_name.upper(), "")
        bold_code = Colors.BOLD if bold else ""
        return f"{bold_code}{color}{text}{Colors.RESET}"

    @classmethod
    def header(cls, title: str, width: int = 64) -> None:
        """Print a section header line."""
        bar = "═" * width
        with cls._lock:
            print()
            print(cls.colorize(bar, "CYAN"))
            print(cls.colorize(f"  {title}", "BOLD"))
            print(cls.colorize(bar, "CYAN"))

    @classmethod
    def subheader(cls, title: str, width: int = 64) -> None:
        """Print a subheader (thin line)."""
        bar = "─" * width
        with cls._lock:
            print(cls.colorize(f"  {bar}", "GRAY"))
            print(cls.colorize(f"  {title}", "CYAN"))
            print(cls.colorize(f"  {bar}", "GRAY"))

    @classmethod
    def separator(cls, width: int = 64, char: str = "─") -> None:
        with cls._lock:
            print(cls.colorize(char * width, "GRAY"))

    @classmethod
    def blank(cls) -> None:
        with cls._lock:
            print()

    # ─────────────────────────────────────────────────────────────────────
    #  CONTEXT MANAGER: timed block
    # ─────────────────────────────────────────────────────────────────────

    @classmethod
    @contextmanager
    def timed(cls, label: str, level: str = "INFO", **kw: Any):
        """
        Context manager that logs duration.

        with Logger.timed("WAF detection"):
            ...
        # logs:  WAF detection completed in 1.23s
        """
        start = time.perf_counter()
        try:
            yield
        finally:
            elapsed = time.perf_counter() - start
            cls.log(
                level,
                f"{label} completed in {elapsed*1000:.0f}ms",
                extra={"duration_ms": round(elapsed * 1000, 1)},
                **kw,
            )

    @classmethod
    def progress(cls, *args: Any, **kwargs: Any):
        """
        Wrapper around tqdm so it's consistent across the codebase.

        Returns a tqdm instance (or a no-op if tqdm missing).
        Disabled automatically if quiet.
        """
        if _tqdm is None:
            return _NullProgress()
        kwargs.setdefault("ncols", 80)
        kwargs.setdefault("disable", cls._quiet)
        if "desc" in kwargs and isinstance(kwargs["desc"], str):
            kwargs["desc"] = cls.colorize(kwargs["desc"], "CYAN")
        return _tqdm(*args, **kwargs)

    # ─────────────────────────────────────────────────────────────────────
    #  MISC
    # ─────────────────────────────────────────────────────────────────────

    @classmethod
    def uptime(cls) -> float:
        """Seconds since process start."""
        return time.perf_counter() - cls._start_time

    @classmethod
    def banner_info(cls) -> Dict[str, str]:
        """Return standard banner metadata (for reporters)."""
        return {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "uptime_s": f"{cls.uptime():.2f}",
        }


# ═══════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _is_tqdm_active() -> bool:
    """Return True if a tqdm progress bar is currently active."""
    if _tqdm is None:
        return False
    try:
        # tqdm keeps a global list of active instances
        from tqdm.std import tqdm as tqdm_std
        return bool(tqdm_std._instances)
    except Exception:
        return False


class JSONLineFormatter(logging.Formatter):
    """Format log records as one JSON object per line."""
    def format(self, record: logging.LogRecord) -> str:
        if isinstance(record.msg, dict):
            data = record.msg
        else:
            data = {"msg": record.getMessage()}
        return json.dumps(data, ensure_ascii=False, default=str)


class _NullProgress:
    """No-op stand-in for tqdm when disabled/missing."""
    def __init__(self, *a, **k): pass
    def update(self, *a, **k): pass
    def close(self): pass
    def set_description(self, *a, **k): pass
    def set_postfix(self, *a, **k): pass
    def __enter__(self): return self
    def __exit__(self, *a): pass


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE-LEVEL CONVENIENCE (so `from core.logger import info` works)
# ═══════════════════════════════════════════════════════════════════════════

def configure(**kwargs: Any) -> None:
    Logger.configure(**kwargs)


def debug(msg: str, **kw: Any) -> None:      Logger.debug(msg, **kw)
def info(msg: str, **kw: Any) -> None:       Logger.info(msg, **kw)
def success(msg: str, **kw: Any) -> None:    Logger.success(msg, **kw)
def warning(msg: str, **kw: Any) -> None:    Logger.warning(msg, **kw)
def error(msg: str, **kw: Any) -> None:      Logger.error(msg, **kw)
def critical(msg: str, **kw: Any) -> None:   Logger.critical(msg, **kw)

def vuln(msg: str, **kw: Any) -> None:       Logger.vuln(msg, **kw)
def fixed(msg: str, **kw: Any) -> None:      Logger.fixed(msg, **kw)
def waf(msg: str, **kw: Any) -> None:        Logger.waf(msg, **kw)
def bypass(msg: str, **kw: Any) -> None:     Logger.bypass(msg, **kw)
def payload(msg: str, **kw: Any) -> None:    Logger.payload(msg, **kw)
def audit(msg: str, **kw: Any) -> None:      Logger.audit(msg, **kw)
def fp(msg: str, **kw: Any) -> None:         Logger.fingerprint(msg, **kw)
def tls(msg: str, **kw: Any) -> None:        Logger.tls(msg, **kw)

def colorize(text: str, color: str, bold: bool = False) -> str:
    return Logger.colorize(text, color, bold)


# ═══════════════════════════════════════════════════════════════════════════
#  EXPORTS
# ═══════════════════════════════════════════════════════════════════════════

__all__ = [
    "Logger", "Colors", "LEVELS", "LEVEL_ALIASES",
    "configure",
    "debug", "info", "success", "warning", "error", "critical",
    "vuln", "fixed", "waf", "bypass", "payload", "audit", "fp", "tls",
    "colorize",
]