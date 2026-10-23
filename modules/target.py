"""Validates and parses the target URL before anything touches the network."""
from urllib.parse import urlparse


def validate_target(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Target must use HTTP or HTTPS.")
    if not parsed.netloc:
        raise ValueError("Invalid target URL.")
    return url
