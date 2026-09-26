from sentinelforge.ioc import extract_from_text, extract_observables
from app.services.simulation import CRADLE


def kinds(text):
    return {(k, v) for k, v, _ in extract_from_text(text, "t")}


def test_ipv4_ipv6_and_invalid_ip():
    got = kinds("connect 203.0.113.50 and 2001:db8::1 but not 999.1.1.1 or 10:22:11")
    assert ("ipv4", "203.0.113.50") in got and ("ipv6", "2001:db8::1") in got
    assert not any(v == "999.1.1.1" for _, v in got)
    assert not any(v == "10:22:11" for _, v in got)


def test_domain_and_url():
    got = kinds(CRADLE)
    assert ("domain", "updates.example.net") in got
    assert any(k == "url" and "updates.example.net/stage.ps1" in v for k, v in got)


def test_file_names_and_dotnet_types_are_not_domains():
    got = kinds("powershell.exe loads System.Net.WebClient and runs script.ps1 from notes.txt")
    assert not any(k == "domain" for k, _ in got)


def test_hashes():
    sha256, sha1, md5 = "a" * 64, "b" * 40, "c" * 32
    got = kinds(f"h1={sha256} h2={sha1} h3={md5}")
    assert ("hash_sha256", sha256) in got and ("hash_sha1", sha1) in got and ("hash_md5", md5) in got
    assert ("hash_md5", "a" * 32) not in got  # a sha256 must not also be reported as md5


def test_windows_path():
    assert ("file_path", "C:\\Users\\Public\\tools.txt") in kinds("copy to C:\\Users\\Public\\tools.txt now")


def test_structured_observables_deduplicated():
    ev = {"host": "H", "network": {"src_ip": "203.0.113.5", "dst_port": 3389}, "actor": {"user": "bob"},
          "process": {"name": "cmd.exe", "command_line": "ping 203.0.113.5"}, "container": {"image": "nginx:1.25", "host_ports": [80]}}
    obs = extract_observables(ev)
    pairs = [(o["type"], o["value"]) for o in obs]
    assert pairs.count(("ipv4", "203.0.113.5")) == 1
    assert {("user", "bob"), ("hostname", "H"), ("process", "cmd.exe"), ("container_image", "nginx:1.25"), ("port", "3389"), ("port", "80")} <= set(pairs)
    assert all("malicious" not in str(o) for o in obs)  # observables are not verdicts
