"""Passive HTTP reconnaissance: headers, cookies, server banner, page title, redirect info."""
import requests
from bs4 import BeautifulSoup
import config as cfg


def run_recon(target: str) -> dict:
    result = {
        "target": target, "status_code": None, "server": None,
        "content_type": None, "headers": {}, "cookies": [], "title": None,
        "redirect_url": None, "response_obj": None, "error": None,
    }
    try:
        response = requests.get(target, timeout=cfg.HTTP_TIMEOUT, allow_redirects=True)
        result["status_code"] = response.status_code
        result["server"] = response.headers.get("Server")
        result["content_type"] = response.headers.get("Content-Type")
        result["headers"] = dict(response.headers)
        result["cookies"] = [c.name for c in response.cookies]
        result["response_obj"] = response  # needed by cookie checks

        # Track redirects
        if response.history:
            result["redirect_url"] = response.url

        ct = result.get("content_type") or ""
        if "text/html" in ct:
            soup = BeautifulSoup(response.text, "html.parser")
            if soup.title:
                result["title"] = soup.title.get_text(strip=True)
    except requests.RequestException as error:
        result["error"] = str(error)
    return result
