"""Environment Profiler: turns a raw inventory into derived characteristics that decide which rules matter.

It does not repeat the inventory; it answers "what is this host, what does it expose, what should we
watch for" and records the evidence behind every conclusion so an analyst can check it.
"""

import ipaddress
import re
from collections import defaultdict

from sentinelforge.log import get_logger
from sentinelforge.schemas.profile import EnvironmentProfile, ExposedService, NetworkSummary, RiskContext, RuleParameters
from sentinelforge.schemas.inventory import Inventory

log = get_logger("profiling")

WELL_KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 88: "Kerberos", 123: "NTP", 135: "MS-RPC",
    139: "NetBIOS", 389: "LDAP", 443: "HTTPS", 445: "SMB", 636: "LDAPS", 1433: "MSSQL", 2375: "Docker API",
    2376: "Docker API (TLS)", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5985: "WinRM (HTTP)",
    5986: "WinRM (HTTPS)", 6443: "Kubernetes API", 8080: "HTTP-alt", 8443: "HTTPS-alt", 10250: "Kubelet",
}

DEFAULT_INTERNAL = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10",
]

# technology / environment type -> rule categories that become relevant
CATEGORY_MAP = {
    "windows": ["windows_process", "windows_account", "windows_persistence", "authentication"],
    "linux": ["linux_process", "authentication"],
    "PowerShell": ["powershell"],
    "IIS": ["web_iis"],
    "RDP": ["remote_access"],
    "WinRM": ["remote_access"],
    "SSH": ["remote_access"],
    "Docker": ["container"],
    "Kubernetes": ["kubernetes"],
}


def _is_loopback(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr.split("%")[0]).is_loopback
    except ValueError:
        return False


def normalize_image(image: str) -> str:
    """'nginx' -> 'nginx:latest' so approved-image comparisons are tag-aware."""
    image = image.strip().lower()
    if not image or "@" in image:
        return image
    last = image.rsplit("/", 1)[-1]
    return image if ":" in last else f"{image}:latest"


_PUBLISHED_PORT = re.compile(r":(\d{1,5})->")


def _published_ports(port_specs: list[str]) -> list[int]:
    out = []
    for spec in port_specs:
        out += [int(p) for p in _PUBLISHED_PORT.findall(spec)]
        if re.fullmatch(r"\d{1,5}:\d{1,5}(/\w+)?", spec.strip()):  # "443:443" short form
            out.append(int(spec.split(":")[0]))
    return sorted(set(p for p in out if 0 < p < 65536))


def _detect_technologies(inv: Inventory, ports: set[int]) -> dict[str, list[str]]:
    svc = {s.name.lower(): s.status.lower() for s in inv.services}
    procs = {p.name.lower() for p in inv.processes}
    software = " | ".join(s.name.lower() for s in inv.software)
    ev: dict[str, list[str]] = defaultdict(list)

    def add(tech: str, cond: bool, why: str) -> None:
        if cond:
            ev[tech].append(why)

    win, lin = inv.host.platform == "windows", inv.host.platform == "linux"
    add("PowerShell", win, "Windows PowerShell ships with Windows")
    add("PowerShell", "powershell 7" in software or "pwsh.exe" in procs, "PowerShell 7 installed/running")
    add("IIS", inv.web_servers.iis, "collector reported IIS")
    add("IIS", "w3svc" in svc, "service W3SVC present")
    add("IIS", "w3wp.exe" in procs, "w3wp.exe running")
    add("Apache", inv.web_servers.apache, "collector reported Apache")
    add("Nginx", inv.web_servers.nginx, "collector reported Nginx")
    add("RDP", win and inv.remote_access.rdp_enabled, "RDP enabled (fDenyTSConnections=0)")
    add("RDP", (inv.remote_access.rdp_port or 3389) in ports and win, f"TCP {inv.remote_access.rdp_port or 3389} listening")
    add("WinRM", inv.remote_access.winrm_enabled, "WinRM service running")
    add("WinRM", bool({5985, 5986} & ports), "TCP 5985/5986 listening")
    add("SSH", inv.remote_access.ssh_present, "sshd present")
    add("SSH", 22 in ports, "TCP 22 listening")
    add("MSSQL", "mssqlserver" in svc or 1433 in ports, "SQL Server service or TCP 1433")
    add("Active Directory", "ntds" in svc, "NTDS service present")
    add("SMB", 445 in ports, "TCP 445 listening")
    add("Docker", inv.containers.docker, f"Docker present ({len(inv.containers.containers)} containers)")
    add("Kubernetes", inv.containers.kubernetes, "kubelet / kube-proxy present")
    add("Kubernetes", bool({6443, 10250} & ports), "Kubernetes API/kubelet port listening")
    add("Defender", bool(inv.security.defender.get("realtime_enabled")), "Defender real-time protection on")
    add("Linux", lin, "platform=linux")
    return dict(ev)


def build_profile(inv: Inventory) -> EnvironmentProfile:
    listening = inv.network.listening_ports
    exposed_ports = {lp.port for lp in listening if lp.protocol == "tcp" and not _is_loopback(lp.address)}
    evidence = _detect_technologies(inv, exposed_ports)
    tech = sorted(evidence)

    # --- environment types ---
    os_l = inv.host.os.lower()
    types = [inv.host.platform]
    if inv.host.platform == "windows":
        types.append("server" if "server" in os_l else "workstation")
    elif inv.host.platform == "linux":
        types.append("server")
    if {"IIS", "Apache", "Nginx"} & set(tech) or {80, 443} & exposed_ports:
        types.append("web_server")
    if {"RDP", "WinRM", "SSH"} & set(tech):
        types.append("remote_access")
    if "Docker" in tech:
        types.append("container_host")
    if "Kubernetes" in tech:
        types.append("kubernetes_node")
    if "MSSQL" in tech or {3306, 5432} & exposed_ports:
        types.append("database_server")
    if "Active Directory" in tech:
        types.append("domain_controller")
    if inv.host.part_of_domain:
        types.append("domain_joined")

    # --- exposed services (service-to-port relationships) ---
    seen: set[tuple[str, int]] = set()
    exposed: list[ExposedService] = []
    for lp in sorted(listening, key=lambda p: (p.protocol, p.port)):
        if _is_loopback(lp.address) or (lp.protocol, lp.port) in seen:
            continue
        if lp.protocol == "udp" and lp.port >= 1024:
            continue
        seen.add((lp.protocol, lp.port))
        exposed.append(ExposedService(port=lp.port, protocol=lp.protocol, service=WELL_KNOWN_PORTS.get(lp.port, "unknown"),
                                      process=lp.process, bind=lp.address))

    # --- network ---
    ips, cidrs, gateways, dns, public_ips = [], [], [], [], []
    for iface in inv.network.interfaces:
        for a in [*iface.ipv4, *iface.ipv6]:
            try:
                ip = ipaddress.ip_address(a.address.split("%")[0])
            except ValueError:
                continue
            if ip.is_loopback:
                continue
            ips.append(str(ip))
            if a.prefix_length is not None:
                try:
                    cidrs.append(str(ipaddress.ip_interface(f"{ip}/{a.prefix_length}").network))
                except ValueError:
                    pass
            if ip.is_global:
                public_ips.append(str(ip))
        gateways += iface.gateways
        dns += iface.dns_servers
    cidrs = sorted(set(cidrs))
    wildcard_bind = any(lp.address in ("0.0.0.0", "::", "*", "") or lp.address in public_ips for lp in listening)

    fw_off = [p.name for p in inv.security.firewall_profiles if p.enabled is False]
    risk = RiskContext(
        remote_access="remote_access" in types,
        internet_facing_indicator=bool(public_ips) and wildcard_bind,
        containerized="container_host" in types or "kubernetes_node" in types,
        firewall_disabled_profiles=fw_off,
        defender_realtime_disabled=inv.security.defender.get("realtime_enabled") is False,
    )

    images = {normalize_image(i) for i in inv.containers.images}
    images |= {normalize_image(c.image) for c in inv.containers.containers if c.image}
    container_ports: list[int] = []
    for c in inv.containers.containers:
        container_ports += _published_ports(c.ports)

    params = RuleParameters(
        listening_ports=sorted({lp.port for lp in listening if lp.protocol == "tcp"}),
        approved_images=sorted(i for i in images if i),
        container_ports=sorted(set(container_ports)),
        internal_cidrs=sorted(set(DEFAULT_INTERNAL) | {c for c in cidrs if not ipaddress.ip_network(c).is_global}),
        known_admins=sorted({m.split("\\")[-1].lower() for m in inv.admin_group_members} | {u.name.lower() for u in inv.users if u.is_admin}),
    )

    categories = {"network"}
    for key in [inv.host.platform, *tech]:
        categories.update(CATEGORY_MAP.get(key, []))

    profile = EnvironmentProfile(
        hostname=inv.host.hostname, platform=inv.host.platform, os=inv.host.os,
        environment_type=list(dict.fromkeys(types)), technologies=tech, exposed_services=exposed, risk_context=risk,
        network=NetworkSummary(ip_addresses=ips, cidrs=cidrs, gateways=sorted(set(gateways)), dns_servers=sorted(set(dns)),
                               route_count=len(inv.network.routes)),
        rule_categories=sorted(categories), parameters=params, evidence=evidence,
    )
    log.info("profile.created", host=profile.hostname, technologies=tech, environment_type=profile.environment_type)
    return profile
