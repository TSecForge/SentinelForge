"""Observable extraction. An observable is something *seen* in the detection, not a verdict: nothing here
labels a value as malicious. Structured fields are used first; free text (command lines, task actions)
is scanned with conservative patterns and every IP candidate is validated with the ipaddress module."""

import ipaddress
import re
from typing import Any

from sentinelforge.registry import registry
from sentinelforge._util import get_path

_URL = re.compile(r"\b(?:https?|ftp)://[^\s'\"<>()\[\]{}|\\^`]+", re.I)
_DOMAIN = re.compile(r"(?<![\w.\-@])(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w\-])", re.I)
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:%\w+)?(?![\w:])", re.I)
_HASHES = [("hash_sha256", re.compile(r"\b[a-f0-9]{64}\b", re.I)), ("hash_sha1", re.compile(r"\b[a-f0-9]{40}\b", re.I)),
           ("hash_md5", re.compile(r"\b[a-f0-9]{32}\b", re.I))]
_WIN_PATH = re.compile(r"\b[a-z]:\\[^\s'\"<>|*?]+", re.I)

# Tokens like powershell.exe / Net.WebClient / script.ps1 are not domains.
_FILE_EXT = {"exe", "dll", "sys", "ps1", "psm1", "psd1", "bat", "cmd", "vbs", "vbe", "js", "jse", "hta", "msi", "lnk",
             "txt", "log", "xml", "json", "yml", "yaml", "ini", "cfg", "conf", "doc", "docx", "docm", "xls", "xlsx", "xlsm",
             "ppt", "pptx", "pdf", "zip", "rar", "7z", "gz", "tar", "iso", "img", "py", "sh", "ps", "md", "csv", "tmp", "dat", "bin"}
_GTLD = {"com", "net", "org", "io", "info", "biz", "gov", "edu", "mil", "int", "xyz", "top", "online", "site", "dev", "app",
         "cloud", "tech", "store", "live", "club", "shop", "link", "click", "local", "internal", "corp", "lan", "home",
         "example", "test", "invalid", "localhost", "onion", "arpa"}

TEXT_FIELDS = ["process.command_line", "process.parent_command_line", "service.path", "task.command", "message"]


def _looks_like_domain(tok: str) -> bool:
    tld = tok.rsplit(".", 1)[-1].lower()
    if tld in _FILE_EXT:
        return False
    return tld in _GTLD or len(tld) == 2


def _ip_type(v: str) -> str | None:
    try:
        return f"ipv{ipaddress.ip_address(v.split('%')[0]).version}"
    except ValueError:
        return None


def extract_from_text(text: str, context: str) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    urls = _URL.findall(text)
    for u in urls:
        out.append(("url", u.rstrip(".,;'\")"), context))
    rest = _URL.sub(" ", text)
    for u in urls:  # the host part of a URL is a useful domain/ip observable too
        hostpart = re.sub(r"^\w+://", "", u).split("/")[0].split("@")[-1].rsplit(":", 1)[0].strip("[]")
        t = _ip_type(hostpart)
        out.append((t, hostpart, context) if t else ("domain", hostpart.lower(), context))
    for m in _IPV4.findall(rest):
        if _ip_type(m):
            out.append(("ipv4", m, context))
    for m in _IPV6.findall(rest):
        if m.count(":") >= 2 and _ip_type(m) == "ipv6":
            out.append(("ipv6", m, context))
    for m in _DOMAIN.findall(rest):
        if not _IPV4.fullmatch(m) and _looks_like_domain(m):
            out.append(("domain", m.lower(), context))
    for kind, rx in _HASHES:
        for m in rx.findall(rest):
            out.append((kind, m.lower(), context))
        rest = rx.sub(" ", rest)
    for m in _WIN_PATH.findall(rest):
        out.append(("file_path", m.rstrip(".,;'\")"), context))
    return out


def _structured(ev: dict) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []

    def add(kind: str, path: str) -> None:
        v = get_path(ev, path)
        for x in (v if isinstance(v, list) else [v]):
            if x not in (None, "", []):
                out.append((kind, str(x), path))

    for p in ("network.src_ip", "network.dst_ip"):
        v = get_path(ev, p)
        if v and (t := _ip_type(str(v))):
            out.append((t, str(v), p))
    add("domain", "network.dst_domain")
    add("port", "network.dst_port")
    add("port", "container.host_ports")
    add("process", "process.name")
    add("process", "process.parent_name")
    add("file_path", "process.path")
    add("file_path", "service.path")
    add("file_path", "file.path")
    add("hash_sha256", "process.hash_sha256")
    add("hash_sha256", "file.hash_sha256")
    add("command_line", "process.command_line")
    add("user", "actor.user")
    add("user", "actor.target_user")
    add("hostname", "host")
    add("container_image", "container.image")
    return out


def extract_observables(ev: dict) -> list[dict[str, Any]]:
    found = _structured(ev)
    for f in TEXT_FIELDS:
        if v := get_path(ev, f):
            found += extract_from_text(str(v), f)
    for extra in registry.ioc_extractors:
        try:
            found += extra(ev)
        except Exception:  # plugin bug must not drop the detection
            continue
    seen: set[tuple[str, str]] = set()
    result = []
    for kind, value, ctx in found:
        key = (kind, value.lower())
        if key in seen or not value or len(value) > 2048:
            continue
        seen.add(key)
        result.append({"type": kind, "value": value, "context": ctx})
    return result
