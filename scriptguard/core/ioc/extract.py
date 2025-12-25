# scriptguard/core/ioc/extract.py

import re
import ipaddress
from urllib.parse import urlparse


# -------------------------
# REGEX
# -------------------------

_URL_RE = re.compile(
    r'\b(?:https?|ftp)://[^\s"\'<>]+',
    re.IGNORECASE
)

_DOMAIN_RE = re.compile(
    r'\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b',
    re.IGNORECASE
)

_EMAIL_RE = re.compile(
    r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
)

_HASH_RE = {
    "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
    "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
}


# -------------------------
# EXTRACTORS
# -------------------------

def _extract_ips(text: str) -> set:
    """
    Извлекает валидные IPv4 адреса
    """
    ips = set()
    for m in re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', text):
        try:
            ip = ipaddress.ip_address(m)
            ips.add(str(ip))
        except ValueError:
            pass
    return ips


def _extract_urls(text: str) -> set:
    """
    Извлекает валидные URL
    """
    urls = set()
    for m in _URL_RE.findall(text):
        try:
            parsed = urlparse(m)
            if parsed.scheme and parsed.netloc:
                urls.add(m)
        except Exception:
            pass
    return urls


def _extract_domains(text: str, known_urls: set) -> set:
    """
    Извлекает домены:
    - из URL
    - напрямую из текста
    """
    domains = set()

    # домены из URL
    for u in known_urls:
        try:
            host = urlparse(u).hostname
            if host:
                domains.add(host.lower())
        except Exception:
            pass

    # домены напрямую из текста
    for d in _DOMAIN_RE.findall(text):
        domains.add(d.lower())

    return domains


def _extract_hashes(text: str) -> dict:
    """
    Извлекает хэши (MD5, SHA1, SHA256)
    """
    result = {}
    for name, rx in _HASH_RE.items():
        found = {h.lower() for h in rx.findall(text)}
        if found:
            result[name] = sorted(found)
    return result


# -------------------------
# PUBLIC API
# -------------------------

def extract_ioc(text: str) -> dict:
    """
    Главная функция извлечения IOC
    """

    urls = _extract_urls(text)
    ips = _extract_ips(text)
    domains = _extract_domains(text, urls)
    emails = set(_EMAIL_RE.findall(text))
    hashes = _extract_hashes(text)

    return {
        "ips": sorted(ips),
        "urls": sorted(urls),
        "domains": sorted(domains),
        "emails": sorted(emails),
        "hashes": hashes,
    }
