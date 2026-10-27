"""
scripts/bootstrap_env.py — Create a local .env from .env.example with random secrets.

Usage:
    python scripts/bootstrap_env.py            # refuses to overwrite an existing .env
    python scripts/bootstrap_env.py --force    # regenerate (destroys the old .env values)

Generates cryptographically random values for SECRET_KEY, database passwords,
and the three demo API keys (viewer / analyst / approver). Values that point at
external systems you own (Wazuh, MISP, LLM) are left as placeholders, which the
application treats as "integration not configured".

The generated API keys are printed once so you can paste one into the dashboard
sign-in screen. They are stored only in .env, which is git-ignored.
"""

from __future__ import annotations

import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / ".env.example"
TARGET = ROOT / ".env"


def _token(nbytes: int = 24) -> str:
    return secrets.token_urlsafe(nbytes)


def main() -> int:
    force = "--force" in sys.argv[1:]
    if TARGET.exists() and not force:
        print(f"{TARGET} already exists; refusing to overwrite (pass --force to regenerate).")
        return 1

    keys = {
        "viewer": f"tfv_{_token()}",
        "analyst": f"tfa_{_token()}",
        "approver": f"tfp_{_token()}",
    }
    replacements = {
        "SECRET_KEY": secrets.token_hex(32),
        "POSTGRES_PASSWORD": _token(),
        "REDIS_PASSWORD": _token(),
        "NEO4J_PASSWORD": _token(),
        "API_KEYS": (
            f"viewer:viewer:{keys['viewer']},"
            f"analyst:analyst:{keys['analyst']},"
            f"approver:approver:{keys['approver']}"
        ),
    }

    lines_out: list[str] = []
    for line in EXAMPLE.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            name = stripped.split("=", 1)[0].strip()
            if name in replacements:
                line = f"{name}={replacements[name]}"
        lines_out.append(line)

    TARGET.write_text("\n".join(lines_out) + "\n", encoding="utf-8")
    TARGET.chmod(0o600)

    print(f"Wrote {TARGET} (mode 600).")
    print("Dashboard / API keys (also stored in .env as API_KEYS):")
    for role, key in keys.items():
        print(f"  {role:<9} {key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
