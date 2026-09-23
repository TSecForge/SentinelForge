<#
.SYNOPSIS
    SentinelForge agentless Windows discovery collector (inventory schema 1.0).

.DESCRIPTION
    Read-only. Uses built-in cmdlets / CIM / registry only. Installs nothing, changes nothing,
    leaves nothing running. Prints one JSON document to stdout (or -OutFile).

    Deliberately NOT collected: passwords, hashes, private keys, tokens, cookies, kubeconfig or
    Docker credential contents, environment variables. Command lines are collected (useful for
    baselining) but passed through a redaction filter for credential-looking arguments; use
    -NoCommandLine to skip them entirely.

    Part of SentinelForge - originally created by Sujhal Gurav. Apache-2.0.

.PARAMETER ComputerName
    Optional remote target. Collection runs over WinRM (Invoke-Command) with the caller's
    existing Windows credentials; no credentials are accepted or stored by this script.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\discovery.ps1 -OutFile .\inventory.json
.EXAMPLE
    .\discovery.ps1 -ComputerName WEB-SRV-01
#>
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}$')]
    [string]$ComputerName,
    [string]$OutFile,
    [switch]$NoCommandLine
)

$collect = {
    param([bool]$NoCommandLine)
    $ErrorActionPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'

    function Redact([string]$s) {
        if (-not $s) { return '' }
        $s = $s -replace '(?i)((?:-|/|--)(?:p|pw|pwd|pass|password|passwd|secret|token|apikey|api-key|key|credential|cred)(?:\s+|[:=]))("[^"]*"|''[^'']*''|\S+)', '$1[REDACTED]'
        $s = $s -replace '(?i)((?:password|passwd|pwd|secret|token|apikey|api_key|access_key)\s*=\s*)("[^"]*"|''[^'']*''|[^\s;&]+)', '$1[REDACTED]'
        $s = $s -replace '(?i)(\b[a-z][a-z0-9+.\-]*://[^:/\s@]+:)[^@\s]+@', '$1[REDACTED]@'
        return $s
    }
    function Iso($d) { if ($d) { ([datetime]$d).ToUniversalTime().ToString('o') } else { $null } }

    $procById = @{}
    foreach ($p in @(Get-Process)) { $procById[[int]$p.Id] = $p.ProcessName }

    # ---------------- host ----------------
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $boot = $os.LastBootUpTime
    $hostInfo = [ordered]@{
        hostname       = $env:COMPUTERNAME
        platform       = 'windows'
        os             = "$($os.Caption)".Trim()
        os_version     = "$($os.Version)"
        build          = "$($os.BuildNumber)"
        architecture   = "$($os.OSArchitecture)"
        domain         = "$($cs.Domain)"
        part_of_domain = [bool]$cs.PartOfDomain
        boot_time      = (Iso $boot)
        uptime_seconds = if ($boot) { [int]((Get-Date) - $boot).TotalSeconds } else { $null }
    }

    # ---------------- network ----------------
    $ips = @(Get-NetIPAddress)
    $routesAll = @(Get-NetRoute)
    $dns = @(Get-DnsClientServerAddress)
    $interfaces = @(foreach ($a in @(Get-NetAdapter)) {
        $idx = $a.ifIndex
        [ordered]@{
            name        = "$($a.Name)"
            description = "$($a.InterfaceDescription)"
            mac         = "$($a.MacAddress)"
            status      = "$($a.Status)"
            ipv4        = @($ips | Where-Object { $_.InterfaceIndex -eq $idx -and "$($_.AddressFamily)" -eq 'IPv4' } | ForEach-Object { [ordered]@{ address = "$($_.IPAddress)"; prefix_length = [int]$_.PrefixLength } })
            ipv6        = @($ips | Where-Object { $_.InterfaceIndex -eq $idx -and "$($_.AddressFamily)" -eq 'IPv6' } | ForEach-Object { [ordered]@{ address = "$($_.IPAddress)"; prefix_length = [int]$_.PrefixLength } })
            gateways    = @($routesAll | Where-Object { $_.InterfaceIndex -eq $idx -and ($_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq '::/0') -and $_.NextHop -ne '0.0.0.0' -and $_.NextHop -ne '::' } | ForEach-Object { "$($_.NextHop)" })
            dns_servers = @($dns | Where-Object { $_.InterfaceIndex -eq $idx } | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ })
        }
    })
    $routes = @($routesAll | Select-Object -First 500 | ForEach-Object {
        [ordered]@{ destination = "$($_.DestinationPrefix)"; next_hop = "$($_.NextHop)"; interface = "$($_.InterfaceAlias)"; metric = [int]$_.RouteMetric }
    })
    $listening = @()
    $listening += @(Get-NetTCPConnection -State Listen | ForEach-Object {
        [ordered]@{ protocol = 'tcp'; address = "$($_.LocalAddress)"; port = [int]$_.LocalPort; pid = [int]$_.OwningProcess; process = "$($procById[[int]$_.OwningProcess])" }
    })
    $listening += @(Get-NetUDPEndpoint | Where-Object { $_.LocalPort -lt 49152 } | ForEach-Object {
        [ordered]@{ protocol = 'udp'; address = "$($_.LocalAddress)"; port = [int]$_.LocalPort; pid = [int]$_.OwningProcess; process = "$($procById[[int]$_.OwningProcess])" }
    })

    # ---------------- services / processes ----------------
    $servicesRaw = @(Get-CimInstance Win32_Service)
    $services = @($servicesRaw | ForEach-Object {
        [ordered]@{ name = "$($_.Name)"; display_name = "$($_.DisplayName)"; status = "$($_.State)"; start_type = "$($_.StartMode)"; path = (Redact "$($_.PathName)") }
    })
    $svc = @{}; foreach ($s in $servicesRaw) { $svc["$($s.Name)".ToLower()] = "$($s.State)" }

    $processes = @(Get-CimInstance Win32_Process | ForEach-Object {
        [ordered]@{
            name         = "$($_.Name)"
            pid          = [int]$_.ProcessId
            parent_pid   = [int]$_.ParentProcessId
            path         = "$($_.ExecutablePath)"
            command_line = if ($NoCommandLine) { '' } else { Redact "$($_.CommandLine)" }
        }
    })
    $procNames = @($processes | ForEach-Object { $_.name.ToLower() })

    # ---------------- users ----------------
    $admins = @()
    try { $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { "$($_.Name)" }) } catch {}
    $users = @(Get-LocalUser | ForEach-Object {
        $n = "$($_.Name)"
        [ordered]@{ name = $n; enabled = [bool]$_.Enabled; is_admin = [bool]($admins | Where-Object { $_ -like "*\$n" -or $_ -eq $n }); last_logon = (Iso $_.LastLogon) }
    })

    # ---------------- software ----------------
    $software = @(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
        Where-Object { $_.DisplayName } | Sort-Object DisplayName -Unique | ForEach-Object {
            [ordered]@{ name = "$($_.DisplayName)"; version = "$($_.DisplayVersion)"; publisher = "$($_.Publisher)" }
        })

    # ---------------- scheduled tasks ----------------
    $tasks = @(Get-ScheduledTask | Select-Object -First 2000 | ForEach-Object {
        [ordered]@{
            name    = "$($_.TaskName)"
            path    = "$($_.TaskPath)"
            state   = "$($_.State)"
            actions = @($_.Actions | Where-Object { $_.Execute } | ForEach-Object { Redact ("$($_.Execute) $($_.Arguments)".Trim()) })
        }
    })

    # ---------------- security posture ----------------
    $defender = [ordered]@{}
    $mp = Get-MpComputerStatus
    if ($mp) {
        $defender = [ordered]@{
            antivirus_enabled      = [bool]$mp.AntivirusEnabled
            realtime_enabled       = [bool]$mp.RealTimeProtectionEnabled
            tamper_protected       = [bool]$mp.IsTamperProtected
            signature_last_updated = (Iso $mp.AntivirusSignatureLastUpdated)
        }
    }
    $firewall = @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ name = "$($_.Name)"; enabled = [bool]$_.Enabled } })
    $audit = [ordered]@{}
    # auditpol needs elevation and its labels are localized; we only keep a handful of subcategories when readable.
    $auditOut = & auditpol.exe /get /category:* 2>$null
    foreach ($line in @($auditOut)) {
        if ($line -match '^\s{2}(Process Creation|Logon|Security Group Management|User Account Management|Other Object Access Events|Security System Extension)\s{2,}(.+)$') {
            $audit[$Matches[1]] = $Matches[2].Trim()
        }
    }
    $securityServices = @('WinDefend', 'MpsSvc', 'EventLog', 'Sysmon', 'Sysmon64', 'wecsvc', 'WinRM', 'SecurityHealthService') |
        Where-Object { $svc.ContainsKey($_.ToLower()) } | ForEach-Object { "$_=$($svc[$_.ToLower()])" }

    # ---------------- remote access ----------------
    $ts = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
    $rdpTcp = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    $remote = [ordered]@{
        rdp_enabled   = ($ts -and $ts.fDenyTSConnections -eq 0)
        rdp_port      = if ($rdpTcp) { [int]$rdpTcp.PortNumber } else { $null }
        winrm_enabled = ($svc['winrm'] -eq 'Running')
        ssh_present   = [bool]($svc.ContainsKey('sshd'))
    }

    # ---------------- web servers ----------------
    $iisSites = @()
    if ($svc.ContainsKey('w3svc')) {
        try {
            Import-Module WebAdministration -ErrorAction Stop
            $iisSites = @(Get-Website | ForEach-Object { [ordered]@{ name = "$($_.Name)"; state = "$($_.State)"; bindings = @($_.Bindings.Collection | ForEach-Object { "$($_.protocol) $($_.bindingInformation)" }) } })
        } catch {}
    }
    $web = [ordered]@{
        iis       = [bool]$svc.ContainsKey('w3svc')
        apache    = [bool](@($svc.Keys | Where-Object { $_ -like 'apache*' }).Count -or $procNames -contains 'httpd.exe')
        nginx     = [bool]($procNames -contains 'nginx.exe')
        iis_sites = $iisSites
    }

    # ---------------- containers ----------------
    $dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    $dockerSvc = if ($svc.ContainsKey('docker')) { $svc['docker'] } elseif ($svc.ContainsKey('com.docker.service')) { $svc['com.docker.service'] } else { '' }
    $containers = @(); $images = @()
    if ($dockerCmd) {
        # Only metadata from `docker ps` / `docker images`. No inspect, no env vars, no mounts, no secrets.
        $containers = @(& docker ps -a --no-trunc --format '{{json .}}' 2>$null | ForEach-Object {
            try { $c = $_ | ConvertFrom-Json } catch { return }
            [ordered]@{ id = "$($c.ID)".Substring(0, [Math]::Min(12, "$($c.ID)".Length)); name = "$($c.Names)"; image = "$($c.Image)"; ports = @("$($c.Ports)" -split ',\s*' | Where-Object { $_ }); status = "$($c.State)" }
        })
        $images = @(& docker images --format '{{.Repository}}:{{.Tag}}' 2>$null | Where-Object { $_ -and $_ -notmatch '<none>' })
    }
    $k8s = @()
    if (Get-Command kubectl -ErrorAction SilentlyContinue) { $k8s += 'kubectl_cli' }
    if ($svc.ContainsKey('kubelet') -or $procNames -contains 'kubelet.exe') { $k8s += 'kubelet' }
    if ($procNames -contains 'kube-proxy.exe') { $k8s += 'kube-proxy' }
    if ($procNames -contains 'containerd.exe' -or $svc.ContainsKey('containerd')) { $k8s += 'containerd_runtime' }
    if (Test-Path 'C:\k') { $k8s += 'windows_node_dir_c_k' }
    if (Test-Path (Join-Path $env:USERPROFILE '.kube\config')) { $k8s += 'kubeconfig_present' }  # existence only, never read

    [ordered]@{
        schema_version      = '1.0'
        collection_time     = (Get-Date).ToUniversalTime().ToString('o')
        collector           = [ordered]@{ name = 'sentinelforge-windows-discovery'; version = '1.0.0'; mode = 'agentless-powershell' }
        simulated           = $false
        host                = $hostInfo
        network             = [ordered]@{ interfaces = $interfaces; routes = $routes; listening_ports = $listening }
        services            = $services
        processes           = $processes
        users               = $users
        admin_group_members = $admins
        software            = $software
        scheduled_tasks     = $tasks
        security            = [ordered]@{ defender = $defender; firewall_profiles = $firewall; audit_policy = $audit; security_services = @($securityServices) }
        remote_access       = $remote
        web_servers         = $web
        containers          = [ordered]@{
            docker                = [bool]$dockerCmd
            docker_service_status = "$dockerSvc"
            containers            = $containers
            images                = $images
            kubernetes            = [bool](($k8s -contains 'kubelet') -or ($k8s -contains 'kube-proxy'))
            kubernetes_indicators = @($k8s)
        }
    } | ConvertTo-Json -Depth 8 -Compress
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
if ($ComputerName) {
    $json = Invoke-Command -ComputerName $ComputerName -ScriptBlock $collect -ArgumentList ([bool]$NoCommandLine) -ErrorAction Stop
} else {
    $json = & $collect ([bool]$NoCommandLine)
}
if ($OutFile) {
    [System.IO.File]::WriteAllText($OutFile, $json, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "Inventory written to $OutFile"
} else {
    $json
}
