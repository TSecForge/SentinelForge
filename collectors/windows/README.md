# Windows agentless discovery collector

`discovery.ps1` produces a SentinelForge **inventory (schema 1.0)** as JSON. It is read-only, uses only built-in
Windows features, and installs or leaves nothing behind.

```powershell
# Local
powershell -NoProfile -ExecutionPolicy Bypass -File .\discovery.ps1 -OutFile .\inventory.json

# Remote over WinRM (uses your current Windows credentials; nothing is passed to or stored by the script)
.\discovery.ps1 -ComputerName WEB-SRV-01 -OutFile .\web-srv-01.json

# Skip command lines entirely
.\discovery.ps1 -NoCommandLine
```

Then import the result in the UI (Environments → Import inventory), or run:

```bash
cd backend && python -m app.cli discovery --file ../collectors/windows/inventory.json --save
```

## Requirements

- Windows PowerShell 5.1 or PowerShell 7 on Windows. Tested on Windows 11 (PowerShell 5.1).
- A standard user can collect most data. **Administrator** rights add audit policy (`auditpol`), some
  process command lines and owners, and full service paths.
- Remote mode needs WinRM enabled on the target and rights to use it (Remote Management Users or admin).

## Collected

System, network (interfaces, CIDRs, gateways, DNS, routes, TCP/UDP listeners with owning process), services,
processes (command lines redacted), local users and admins, installed software, scheduled tasks, Defender,
firewall and audit posture, RDP/WinRM/SSH state, IIS/Apache/Nginx, Docker containers and images (metadata only), and
Kubernetes indicators.

## Never collected

Passwords, password hashes, private keys, tokens, browser data or cookies, environment variables, kubeconfig or
Docker credential file **contents**, and `docker inspect` output (env vars, mounts).

The redaction filter masks values that follow credential-looking switches (`-p`, `-password`, `-token`,
`-apikey`, `-secret`, `-credential`, …), `password=` style assignments, and `user:pass@` in URLs. It is pattern-based,
so review output before sharing it. `inventory*.json` is git-ignored.

See [docs/discovery.md](../../docs/discovery.md) for the full field list.
