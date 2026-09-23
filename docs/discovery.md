# Agentless discovery

## What "agentless" means here

SentinelForge installs nothing on the target. The Windows collector is a PowerShell script that uses built-in
cmdlets, CIM, and the registry. It runs locally or over WinRM (`Invoke-Command`) with the operator's existing
Windows credentials and exits when it is done. No service, scheduled task, or file is left behind unless
`-OutFile` is used.

```
Agentless discovery  ≠  no telemetry mechanism at all
```

Discovery answers *what exists*. Detection needs *what is happening*, and that telemetry must still arrive
through native or existing mechanisms:

- Windows Event Forwarding (WEF/WEC), Security + Sysmon channels, forwarded into `/api/v1/events/batch`
  (planned: v2)
- existing log shippers (Winlogbeat, Fluent Bit, NXLog, Splunk UF) posting JSON
- Docker Engine events API and Kubernetes audit webhooks (planned: v4)

## Windows collector

`collectors/windows/discovery.ps1` targets PowerShell 5.1 and later.

| Area | Collected | Source |
|---|---|---|
| System | hostname, OS, version, build, arch, domain, boot time, uptime | `Win32_OperatingSystem`, `Win32_ComputerSystem` |
| Network | adapters, IPv4/IPv6 with prefix, gateways, DNS, routes (500 max), TCP listeners, UDP < 49152, owning process | `Get-NetAdapter/IPAddress/Route`, `Get-DnsClientServerAddress`, `Get-NetTCPConnection`, `Get-NetUDPEndpoint` |
| Services | name, display name, state, start mode, path | `Win32_Service` |
| Processes | name, PID, PPID, path, command line (**redacted**) | `Win32_Process` |
| Users | local users, enabled, admin membership, last logon | `Get-LocalUser`, `Get-LocalGroupMember -SID S-1-5-32-544` |
| Software | display name, version, publisher | Uninstall registry keys (x64 + WOW6432Node) |
| Scheduled tasks | name, path, state, actions (**redacted**) | `Get-ScheduledTask` |
| Security | Defender state, firewall profiles, selected audit subcategories, security services | `Get-MpComputerStatus`, `Get-NetFirewallProfile`, `auditpol` (needs elevation) |
| Remote access | RDP enabled and port, WinRM running, sshd present | Terminal Server registry keys, services |
| Web | IIS (+ sites/bindings), Apache, Nginx | services, processes, `WebAdministration` |
| Docker | presence, service state, containers (id, name, image, ports, state), images | `docker ps` / `docker images` |
| Kubernetes | indicators: `kubectl`, kubelet, kube-proxy, containerd, `C:\k`, and whether a kubeconfig **exists** | commands, services, paths |

### Not collected

Passwords, hashes, private keys, tokens, cookies, environment variables, kubeconfig **contents**, Docker
`inspect` output (env vars, mounts), and registry secrets.

Command lines and task actions pass through `Redact`, which masks values after `-p/-pw/-password/-token/-key/
-secret/-credential` style switches, `password=`-style assignments, and `user:pass@` in URLs. Use `-NoCommandLine`
to skip command lines entirely. Redaction is best-effort pattern matching, so review inventories before sharing
them. `.gitignore` excludes `inventory*.json`.

Kubernetes is only reported as `true` when kubelet or kube-proxy is present. `kubectl` or a kubeconfig on its own
(Docker Desktop ships both) is recorded as an *indicator*.

### Running

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File collectors\windows\discovery.ps1 -OutFile inventory.json
.\collectors\windows\discovery.ps1 -ComputerName WEB-SRV-01 -OutFile web-srv-01.json   # WinRM
.\collectors\windows\discovery.ps1 -NoCommandLine
```

`-ExecutionPolicy Bypass` applies only to that PowerShell process. It does not change machine policy. Sign
the script if your policy requires signed code.

Via the API (only when `ENABLE_LIVE_DISCOVERY=true`):

```http
POST /api/v1/discovery/run   {"mode": "local"}
POST /api/v1/discovery/run   {"mode": "remote", "target": "WEB-SRV-01"}
POST /api/v1/discovery/run   {"mode": "import", "inventory": { ...schema 1.0... }}
POST /api/v1/discovery/run   {"mode": "demo", "template": "windows-web-server"}
```

The API only ever runs the bundled script. The argument list is fixed (`shell=False`), and `target` must match a
hostname regex and cannot start with `-`. The call is subject to a timeout.

In development, a full local collection on Windows 11 took about 23 seconds. It returned 8 interfaces, 89 listeners,
333 services, 398 processes, and 336 software entries.

## Inventory schema

Version `1.0`: `backend/app/schemas/inventory.py`, exported to `schemas/inventory.schema.json`.

The parser treats collector output as untrusted:
- unknown keys are dropped
- strings are truncated (512 characters for most fields, 8192 for paths and command lines)
- list sizes are bounded
- the hostname is pattern-checked
- PowerShell 5.1's habit of turning a one-element array into an object is tolerated

## Writing another collector

Emit JSON that validates against `schemas/inventory.schema.json` and POST it with `mode: import`. A Linux
collector would fill the same `host`, `network`, `services`, `processes`, `users`, `containers`, and
`remote_access` fields. See `sample-data/environments/docker-host.json` and `linux-k8s-node.json` for
Linux-shaped examples.
