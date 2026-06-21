import re
import socket
from urllib.parse import urlparse


def extract_urls(text):
    if not text:
        return []

    pattern = (
        r'(https?://[^\s]+|www\.[^\s]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})'
    )

    urls = re.findall(pattern, text)

    normalized = []

    for url in urls:
        if not url.startswith(("http://", "https://")):
            normalized.append("https://" + url)
        else:
            normalized.append(url)

    return normalized


def extract_domain(url):
    try:
        netloc = urlparse(url).netloc.lower()
        netloc = netloc.strip()

        if netloc.startswith("www."):
            netloc = netloc[4:]

        netloc = netloc.split(":")[0]

        return netloc

    except Exception:
        return ""


def domain_resolves(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False