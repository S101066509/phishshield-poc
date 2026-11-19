# 檔案功能：只調整容器程序的本機模型路由，先執行資料庫遷移再以原程序啟動網站。
"""Container startup; never persist environment values or print underlying exceptions."""

import json
import os
import subprocess
import sys
from urllib.parse import urlsplit

HOST_GATEWAY = "host.docker.internal"
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
POOL_VARIABLES = ("PHISHSHIELD_LLM_ENDPOINTS_A", "PHISHSHIELD_LLM_ENDPOINTS_B")
ROUTING_FLAG = "PHISHSHIELD_LLM_ALLOW_DOCKER_HOST_HTTP"
MIGRATION = [sys.executable, "-m", "alembic", "-c", "backend/alembic.ini", "upgrade", "head"]
SERVER = [
    sys.executable,
    "-m",
    "uvicorn",
    "app.main:create_app",
    "--factory",
    "--app-dir",
    "backend",
    "--host",
    "0.0.0.0",
    "--port",
    "8000",
    "--no-access-log",
]


class ContainerConfigurationError(ValueError):
    pass


def unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ContainerConfigurationError("CONTAINER_LLM_CONFIGURATION_INVALID")
        result[key] = value
    return result


def container_endpoint(value):
    """Rewrite only a valid HTTP loopback host, preserving path, port and invalid inputs."""
    if not isinstance(value, str):
        raise ContainerConfigurationError("CONTAINER_LLM_CONFIGURATION_INVALID")
    # Never salvage a URL that the product's strict connection policy must reject.
    if any(character.isspace() or ord(character) < 32 for character in value):
        return value
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in LOOPBACK_HOSTS
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.netloc.endswith(":")
            or "\\" in value
        ):
            return value
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            return value
    except ValueError:
        return value
    # Replacing only the netloc avoids re-encoding data or dropping empty URL delimiters.
    start = value.find("://") + 3
    end = start + len(parsed.netloc)
    return value[:start] + HOST_GATEWAY + (f":{port}" if port is not None else "") + value[end:]


def container_environment(environment):
    """Return process-only routing; do not modify the caller, .env, models or credentials."""
    output = dict(environment)
    if output.get(ROUTING_FLAG, "").strip().lower() not in {"1", "true", "yes", "on"}:
        return output
    for key in POOL_VARIABLES:
        if key not in output or not output[key].strip():
            continue
        try:
            entries = json.loads(output[key], object_pairs_hook=unique_object)
            if not isinstance(entries, list) or not all(isinstance(item, dict) for item in entries):
                raise ContainerConfigurationError("CONTAINER_LLM_CONFIGURATION_INVALID")
            for entry in entries:
                entry["endpoint"] = container_endpoint(entry["endpoint"])
            output[key] = json.dumps(entries, ensure_ascii=False, separators=(",", ":"))
        except (ValueError, TypeError, KeyError):
            raise ContainerConfigurationError("CONTAINER_LLM_CONFIGURATION_INVALID") from None
    if "PHISHSHIELD_LLM_ENDPOINT" in output:
        output["PHISHSHIELD_LLM_ENDPOINT"] = container_endpoint(output["PHISHSHIELD_LLM_ENDPOINT"])
    return output


def main():
    try:
        environment = container_environment(os.environ)
    except ContainerConfigurationError:
        print("CONTAINER_LLM_CONFIGURATION_INVALID", file=sys.stderr)
        return 2
    try:
        # Errors may contain database credentials, so expose a fixed code instead of raw output.
        result = subprocess.run(MIGRATION, env=environment, capture_output=True, check=False)
        if result.returncode:
            print("DATABASE_MIGRATION_FAILED", file=sys.stderr)
            return result.returncode
        os.execvpe(sys.executable, SERVER, environment)
    except OSError:
        print("CONTAINER_STARTUP_FAILED", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
