"""Application configuration.

Configuration precedence (highest wins):

1. Environment variables: ``DETECTLENS_LLM_KEY``, ``DETECTLENS_PROVIDER``,
   ``DETECTLENS_BASE_URL``, ``DETECTLENS_MODEL``, ``DETECTLENS_LOCAL_ONLY``,
   ``DETECTLENS_RULES_DIR``, ``DETECTLENS_ALERTS``.
2. The YAML config file at ``~/.detectlens/config.yaml``.
3. Built-in defaults.

If the config file exists but its permissions are not exactly 0600, a
warning is printed to stderr and loading continues — the key inside
deserves stricter handling.  :func:`save_config` always writes with 0600
permissions and never prints or logs the API key.
"""

from __future__ import annotations

import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

import yaml


CONFIG_DIR_NAME = ".detectlens"
CONFIG_FILE_NAME = "config.yaml"
VALID_PROVIDERS = ("none", "openai_compat", "anthropic", "ollama")

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


@dataclass
class AppConfig:
    """DetectLens configuration."""

    provider: str = "none"  # "none" | "openai_compat" | "anthropic" | "ollama"
    base_url: str | None = None
    model: str | None = None
    api_key: str | None = None
    redact_ips: bool = True
    redact_hostnames: bool = True
    redact_usernames: bool = True
    local_only: bool = True
    rules_dir: str = ""
    alerts_path: str | None = None
    window_days: int = 30


def config_path() -> Path:
    """Path of the user config file: ``~/.detectlens/config.yaml``."""
    return Path.home() / CONFIG_DIR_NAME / CONFIG_FILE_NAME


def _env_bool(name: str) -> bool | None:
    """Parse a boolean env var; None when unset or unparseable."""
    raw = os.environ.get(name)
    if raw is None:
        return None
    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    print(
        f"warning: {name}={raw!r} is not a recognised boolean; ignoring",
        file=sys.stderr,
    )
    return None


def _apply_file_config(cfg: AppConfig, data: dict, path: Path) -> None:
    for key in (
        "provider",
        "base_url",
        "model",
        "api_key",
        "redact_ips",
        "redact_hostnames",
        "redact_usernames",
        "local_only",
        "rules_dir",
        "alerts_path",
        "window_days",
    ):
        if key in data and data[key] is not None:
            setattr(cfg, key, data[key])
    if cfg.provider not in VALID_PROVIDERS:
        print(
            f"warning: {path}: unknown provider {cfg.provider!r}; "
            f"expected one of {VALID_PROVIDERS}; using 'none'",
            file=sys.stderr,
        )
        cfg.provider = "none"


def load_config() -> AppConfig:
    """Load configuration: defaults, then the YAML file, then environment
    variables.  Never raises on a missing or unreadable file."""
    cfg = AppConfig()
    path = config_path()
    if path.is_file():
        mode = path.stat().st_mode & 0o777
        if mode != 0o600:
            print(
                f"warning: {path} has permissions {oct(mode)}; "
                "expected 0600 to protect the API key",
                file=sys.stderr,
            )
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception as exc:  # malformed YAML must not crash startup
            print(f"warning: {path}: could not parse config: {exc}", file=sys.stderr)
            data = {}
        if isinstance(data, dict):
            _apply_file_config(cfg, data, path)

    # Environment overrides (highest precedence).
    provider = os.environ.get("DETECTLENS_PROVIDER")
    if provider:
        if provider in VALID_PROVIDERS:
            cfg.provider = provider
        else:
            print(
                f"warning: DETECTLENS_PROVIDER={provider!r} is not one of "
                f"{VALID_PROVIDERS}; ignoring",
                file=sys.stderr,
            )
    if os.environ.get("DETECTLENS_BASE_URL"):
        cfg.base_url = os.environ["DETECTLENS_BASE_URL"]
    if os.environ.get("DETECTLENS_MODEL"):
        cfg.model = os.environ["DETECTLENS_MODEL"]
    if os.environ.get("DETECTLENS_LLM_KEY"):
        cfg.api_key = os.environ["DETECTLENS_LLM_KEY"]
    local_only = _env_bool("DETECTLENS_LOCAL_ONLY")
    if local_only is not None:
        cfg.local_only = local_only
    if os.environ.get("DETECTLENS_RULES_DIR"):
        cfg.rules_dir = os.environ["DETECTLENS_RULES_DIR"]
    if os.environ.get("DETECTLENS_ALERTS"):
        cfg.alerts_path = os.environ["DETECTLENS_ALERTS"]
    return cfg


def save_config(cfg: AppConfig) -> None:
    """Write the config to ``~/.detectlens/config.yaml`` with 0600
    permissions.  The API key is written to the file but never printed or
    logged by this function."""
    path = config_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Restrict the directory too if we just created it.
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    payload = asdict(cfg)
    path.write_text(yaml.safe_dump(payload, sort_keys=True), encoding="utf-8")
    os.chmod(path, 0o600)
