from fastapi import FastAPI
from fastapi.responses import JSONResponse
from urllib.parse import urlparse
import os
import posixpath
import re
import shlex
import base64

app = FastAPI()

RESTRICTED_FILE = "/home/agent/.bashrc"
WORKSPACE = "/home/agent/workspace"
OUTBOX = "/data/agent/outbox"

ALLOWED_HOSTS = {
    "api.github.com",
    "registry.npmjs.org",
}


def decision(allow: bool, reason: str):
    return JSONResponse(
        content={
            "decision": "allow" if allow else "block",
            "reason": reason,
        }
    )


def normalize_path(path: str) -> str:
    if not path:
        return ""

    path = path.replace("\\", "/")
    path = path.replace("$HOME", "/home/agent")
    path = path.replace("${HOME}", "/home/agent")

    if path.startswith("~"):
        path = path.replace("~", "/home/agent", 1)

    if not path.startswith("/"):
        path = posixpath.join(WORKSPACE, path)

    return posixpath.normpath(path)


def contains_restricted(text: str) -> bool:
    text = text.replace("\\", "/")
    text = text.replace("$HOME", "/home/agent")
    text = text.replace("${HOME}", "/home/agent")
    text = text.replace("~", "/home/agent")

    if RESTRICTED_FILE in text:
        return True

    for token in re.split(r"\s+", text):
        if normalize_path(token) == RESTRICTED_FILE:
            return True

    return False


def decode_base64_strings(command: str):
    results = []

    for s in re.findall(r"[A-Za-z0-9+/=]{12,}", command):
        try:
            decoded = base64.b64decode(s).decode("utf-8", errors="ignore")
            results.append(decoded)
        except Exception:
            pass

    return results


@app.get("/")
def home():
    return {"status": "ok"}


@app.post("/")
def guardrail(body: dict):
    tool = body.get("tool")

    if tool == "write_file":
        path = normalize_path(body.get("path", ""))

        outbox = posixpath.normpath(OUTBOX)

        if path == outbox or path.startswith(outbox + "/"):
            return decision(True, "Write allowed inside outbox.")

        return decision(False, "Writes are only allowed inside outbox.")

    elif tool == "http_request":
        url = body.get("url", "")

        try:
            host = urlparse(url).hostname or ""
        except Exception:
            host = ""

        if host in ALLOWED_HOSTS:
            return decision(True, "Host allowed.")

        return decision(False, "Host not permitted.")

    elif tool == "bash":
        command = body.get("command", "")

        if contains_restricted(command):
            return decision(False, "Reading .bashrc is forbidden.")

        for decoded in decode_base64_strings(command):
            if contains_restricted(decoded):
                return decision(False, "Reading .bashrc is forbidden.")

        try:
            tokens = shlex.split(command)
            for token in tokens:
                if normalize_path(token) == RESTRICTED_FILE:
                    return decision(False, "Reading .bashrc is forbidden.")
        except Exception:
            pass

        return decision(True, "Command allowed.")

    return decision(False, "Unknown tool.")