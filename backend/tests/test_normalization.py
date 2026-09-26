import pytest

from sentinelforge.schemas.event import EventIn
from sentinelforge.normalize import NormalizationError, normalize


def n(source, data):
    return normalize(EventIn(source=source, data=data))


def test_windows_4688():
    e = n("windows", {"EventID": 4688, "Computer": "WEB-SRV-01", "TimeCreated": "2026-09-23T10:22:11Z", "EventRecordID": 99,
                      "EventData": {"NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                    "ParentProcessName": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                                    "CommandLine": "powershell.exe -nop", "NewProcessId": "0x1a2c", "ProcessId": "0x0f10",
                                    "SubjectUserName": "admin", "SubjectDomainName": "CORP"}})
    assert e.event_type == "process_creation" and e.host == "WEB-SRV-01" and e.source == "windows"
    assert e.process.name == "powershell.exe" and e.process.parent_name == "winword.exe"
    assert e.process.pid == 0x1A2C and e.process.parent_pid == 0x0F10
    assert e.actor.user == "admin" and e.actor.domain == "CORP"
    assert e.raw_reference == "windows/4688/99"
    assert e.timestamp.isoformat().startswith("2026-09-23T10:22:11")


def test_sysmon_process_and_network():
    p = n("windows", {"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "H",
                      "EventData": {"Image": "C:\\x\\a.exe", "ParentImage": "C:\\x\\b.exe", "User": "CORP\\bob",
                                    "Hashes": "MD5=00,SHA256=" + "ab" * 32, "ProcessId": 10, "ParentProcessId": 5}})
    assert p.process.name == "a.exe" and p.actor.user == "bob" and p.process.hash_sha256 == "ab" * 32 and p.process.parent_pid == 5
    c = n("windows", {"EventID": 3, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "H",
                      "EventData": {"Image": "C:\\x\\a.exe", "DestinationIp": "198.51.100.1", "DestinationPort": "8081", "Initiated": "true"}})
    assert c.event_type == "network_connection" and c.network.dst_port == 8081 and c.network.direction == "outbound"


def test_windows_logon_group_service():
    f = n("windows", {"EventID": 4625, "Computer": "H", "EventData": {"TargetUserName": "Admin", "LogonType": "10", "IpAddress": "203.0.113.5"}})
    assert f.event_type == "authentication" and f.auth.outcome == "failure" and f.auth.logon_type == 10 and f.actor.user == "admin"
    g = n("windows", {"EventID": 4732, "Computer": "H", "EventData": {"TargetUserName": "Administrators", "MemberName": "CN=Eve,OU=x,DC=corp"}})
    assert g.group.name == "Administrators" and g.group.member == "eve" and g.group.action == "added"
    s = n("windows", {"EventID": 7045, "Channel": "System", "Computer": "H", "EventData": {"ServiceName": "S", "ImagePath": "C:\\p.exe"}})
    assert s.event_type == "service_creation" and s.service.path == "C:\\p.exe"


def test_log_cleared_and_kerberos_ticket():
    c = n("windows", {"EventID": 1102, "Channel": "Security", "Computer": "H",
                      "UserData": {"LogFileCleared": {"SubjectUserName": "Eve", "SubjectDomainName": "CORP"}}})
    assert c.event_type == "log_cleared" and c.actor.user == "eve"
    s = n("windows", {"EventID": 104, "Channel": "System", "Computer": "H", "EventData": {"SubjectUserName": "eve", "Channel": "Application"}})
    assert s.event_type == "log_cleared" and "Application" in s.message
    k = n("windows", {"EventID": 4769, "Computer": "DC1", "EventData": {"TargetUserName": "jdoe@CORP.EXAMPLE", "ServiceName": "svc-sql",
                                                                         "TicketEncryptionType": "0x17", "Status": "0x0", "IpAddress": "::ffff:10.1.1.5"}})
    assert k.event_type == "kerberos_service_ticket" and k.auth.method == "0x17" and k.service.name == "svc-sql" and k.auth.outcome == "success"


def test_scheduled_task_command_extracted():
    t = n("windows", {"EventID": 4698, "Computer": "H", "EventData": {"TaskName": "\\T",
          "TaskContent": "<Task><Actions><Exec><Command>cmd.exe</Command><Arguments>/c echo hi</Arguments></Exec></Actions></Task>"}})
    assert t.task.command == "cmd.exe /c echo hi"


def test_docker_engine_event():
    d = n("docker", {"host": "DOCKER-01", "Type": "container", "Action": "start", "time": 1790000000,
                     "Actor": {"ID": "f" * 64, "Attributes": {"image": "NGINX", "name": "web"}}, "host_ports": ["443", "8080"]})
    assert d.event_type == "container_start" and d.container.image == "nginx:latest"
    assert d.container.host_ports == [443, 8080] and d.container.id == "f" * 12


def test_kubernetes_audit_event():
    k = n("kubernetes", {"host": "cluster-a", "verb": "create", "user": {"username": "dev"}, "sourceIPs": ["10.1.1.1"],
                         "objectRef": {"resource": "pods", "namespace": "prod", "name": "p"},
                         "requestObject": {"spec": {"containers": [{"image": "busybox", "securityContext": {"privileged": True}}]}}})
    assert k.event_type == "k8s_audit" and k.k8s.privileged is True and k.container.image == "busybox:latest"


def test_linux_sshd_lines():
    f = n("linux", {"hostname": "L", "message": "Failed password for invalid user root from 203.0.113.4 port 5555 ssh2"})
    assert f.event_type == "authentication" and f.auth.outcome == "failure" and f.network.src_ip == "203.0.113.4"
    ok = n("linux", {"hostname": "L", "message": "Accepted publickey for deploy from 10.0.0.2 port 1 ssh2"})
    assert ok.auth.outcome == "success" and ok.actor.user == "deploy"


def test_generic_passthrough_and_validation():
    g = n("generic", {"host": "H", "event_type": "custom_thing", "process": {"name": "x"}})
    assert g.event_type == "custom_thing" and g.event_id.startswith("evt-")
    with pytest.raises(NormalizationError):
        n("generic", {"host": "H", "event_type": "x", "process": {"evil_field": 1}})  # extra fields forbidden
    with pytest.raises(NormalizationError, match="no host"):
        n("windows", {"EventID": 4688, "EventData": {}})


def test_same_record_gets_same_id():
    rec = {"EventID": 4624, "Computer": "H", "TimeCreated": "2026-09-23T10:00:00Z", "EventData": {"TargetUserName": "a"}}
    assert n("windows", rec).event_id == n("windows", dict(rec)).event_id
