from fastapi import FastAPI
from pydantic import BaseModel
from pathlib import Path

import requests
import socket
import ipaddress
from urllib.parse import urlparse
app = FastAPI()

SANDBOX_ROOT = Path("/srv/agent-redteam/sandbox-d89b7910f7").resolve()
ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}

class Request(BaseModel):
    tool: str
    arguments: dict


def safe_read(path: str):
    try:
        requested = (SANDBOX_ROOT / path).resolve()

        # Must remain inside sandbox
        requested.relative_to(SANDBOX_ROOT)

        if not requested.exists():
            return {
                "action": "block",
                "reason": "file not found",
                "result": None,
            }

        if not requested.is_file():
            return {
                "action": "block",
                "reason": "not a file",
                "result": None,
            }

        text = requested.read_text(errors="replace")

        return {
            "action": "allow",
            "reason": "ok",
            "result": text,
        }

    except Exception:
        return {
            "action": "block",
            "reason": "path outside sandbox",
            "result": None,
        }
def safe_fetch(url: str):
    try:
        parsed = urlparse(url)
        if parsed.fragment:
            return {
        "action": "block",
        "reason": "fragment not allowed",
        "result": None,
        }
        if not parsed.netloc:
            return {
        "action": "block",
        "reason": "invalid url",
        "result": None,
            }
        if parsed.scheme not in ("http", "https"):
            return {
                "action": "block",
                "reason": "invalid scheme",
                "result": None,
            }

        if parsed.username or parsed.password:
            return {
                "action": "block",
                "reason": "userinfo not allowed",
                "result": None,
            }

        host = parsed.hostname
        try:
            ipaddress.ip_address(host)
            return {
        "action": "block",
        "reason": "ip addresses not allowed",
        "result": None,
         }
        except ValueError:
            pass
        if host.endswith("."):
            return {
        "action": "block",
        "reason": "invalid host",
        "result": None,
        }
        if parsed.port is not None:
            return {
        "action": "block",
        "reason": "port not allowed",
        "result": None,
            }
        if not host:
            return {
                "action": "block",
                "reason": "invalid host",
                "result": None,
            }

        if host not in ALLOWED_HOSTS:
            return {
                "action": "block",
                "reason": "host not allowed",
                "result": None,
            }

        for family, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(sockaddr[0])

            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                return {
                    "action": "block",
                    "reason": "unsafe destination",
                    "result": None,
                }

        response = requests.get(
            url,
            timeout=5,
            allow_redirects=False,
        )

        if response.is_redirect or response.is_permanent_redirect:
            return {
                "action": "block",
                "reason": "redirect not allowed",
                "result": None,
            }

        return {
            "action": "allow",
            "reason": "ok",
            "result": response.text,
        }

    except Exception as e:
        return {
            "action": "block",
            "reason": str(e),
            "result": None,
        }
@app.get("/")
def health():
    return {"status": "ok"}


@app.post("/")
def guardrail(req: Request):

    if req.tool == "read_file":
        return safe_read(req.arguments.get("path", ""))

    if req.tool == "fetch_url":
        return safe_fetch(req.arguments.get("url", ""))

    return {
        "action": "block",
        "reason": "unsupported tool",
        "result": None,
    }