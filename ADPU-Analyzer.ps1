#  ADPU-Analyzer
#  -----------
#  Reviews an Active Directory forest and works out which privileged accounts
#  can safely be placed into the Protected Users group - and which still have a
#  blocker (legacy auth, stale password, wrong account type, missing group).
#
#  Usage
#    .\ADPU-Analyzer.ps1                         run it; pick a domain when asked
#    . .\ADPU-Analyzer.ps1 ; Invoke-ADPUAnalyzer -Domain corp.example.net
#    . .\ADPU-Analyzer.ps1 ; Invoke-ADPUAnalyzer -HtmlPath .\report.html
#    . .\ADPU-Analyzer.ps1 ; Invoke-ADPUAnalyzer -Verify -Days 7
#                                                after enrolling: read the
#                                                Protected Users operational logs
#
#  Requirements
#    * Windows PowerShell 5.1+ or PowerShell 7+
#    * run on, or with line of sight to, a domain controller (elevated on a DC)
#    * WinRM reachable on the controllers
#    * Logon auditing (success + failure) switched on
#
#  Made by Carbon/Nobrac

#requires -Version 5

Set-StrictMode -Off

#  ==========================================================================
#  >> User-interface helpers (all screen output and prompts)
#  ==========================================================================

function Get-ADPUHostContext {
    # Snapshot of where we are running: are we elevated, and is this box a DC?
    $token = [Security.Principal.WindowsIdentity]::GetCurrent()
    $admin = [Security.Principal.WindowsPrincipal]::new($token)
    [pscustomobject]@{
        IsElevated         = $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        IsDomainController = [bool](Get-CimInstance -ClassName CIM_OperatingSystem |
                                    Where-Object { $_.ProductType -eq 2 })
    }
}

function Write-ADPULine {
    # Single styled output primitive. $Kind picks a word-tag and a colour; titles
    # and notes render as headings/indented notes instead of tagged lines. No
    # background colours are ever set, so it stays legible on any colour scheme.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateSet('note','warn','good','bad','snippet','tip','head','sub')]
        [string]$Kind,

        [Parameter(Mandatory, Position = 1)]
        $Text
    )

    if ($Kind -eq 'head') {
        $h = [string]$Text
        Write-Host ''
        Write-Host "  $h" -ForegroundColor White
        Write-Host ('  ' + ('=' * $h.Length)) -ForegroundColor DarkGray
        return
    }
    if ($Kind -eq 'sub') {
        Write-Host "    $Text" -ForegroundColor DarkGray
        return
    }

    $tag, $colour = switch ($Kind) {
        'note'    { 'Info',  'Cyan'   ; break }
        'warn'    { 'Warn',  'Yellow' ; break }
        'good'    { 'OK',    'Green'  ; break }
        'bad'     { 'Error', 'Red'    ; break }
        'snippet' { 'Code',  'Yellow' ; break }
        'tip'     { 'Tip',   'Magenta'; break }
    }
    $label = ('[{0}]' -f $tag).PadRight(8)
    Write-Host "$label $Text" -ForegroundColor $colour
}

function Clear-ADPUInput {
    # Drop keystrokes typed ahead of time (e.g. extra Enters held down during a
    # pause or spinner) so the next prompt waits for a deliberate answer instead
    # of racing through the queued newlines.
    try { $Host.UI.RawUI.FlushInputBuffer() } catch { }
}

function Wait-ADPUEnter {
    # A "press Enter to continue" pause that ignores any pre-typed input first.
    [CmdletBinding()]
    param([string]$Prompt = '   (Enter to continue)')
    Clear-ADPUInput
    Read-Host $Prompt | Out-Null
}

function Read-ADPUAnswer {
    # Free-form prompt. Returns the raw string the operator typed.
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0)] $Prompt)
    Clear-ADPUInput
    Write-Host ('[Ask]'.PadRight(8) + " $Prompt") -ForegroundColor Magenta
    Read-Host '   >'
}

function Read-ADPUYesNo {
    # Loops until the operator gives a clean yes/no. Returns [bool].
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0)] [string]$Question)
    do {
        $reply = ([string](Read-ADPUAnswer "$Question (y/n)")).Trim().ToLowerInvariant()
        Write-Host ''
    } until ($reply -in @('y', 'yes', 'n', 'no'))
    return ($reply -in @('y', 'yes'))
}

function Read-ADPUChoice {
    # Shows a numbered menu and loops until the operator picks a valid number.
    # Returns the chosen item's text.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)] [string]$Prompt,
        [Parameter(Mandatory, Position = 1)] [string[]]$Items
    )
    while ($true) {
        Write-Host ('[Ask]'.PadRight(8) + " $Prompt") -ForegroundColor Magenta
        for ($i = 0; $i -lt $Items.Count; $i++) {
            Write-Host ('        {0,2}) {1}' -f ($i + 1), $Items[$i]) -ForegroundColor Gray
        }
        Clear-ADPUInput
        $raw = ([string](Read-Host '   #')).Trim()
        $pick = 0
        if ([int]::TryParse($raw, [ref]$pick) -and $pick -ge 1 -and $pick -le $Items.Count) {
            Write-Host ''
            return $Items[$pick - 1]
        }
        Write-Host ('[Warn]'.PadRight(8) + " Enter a number from 1 to $($Items.Count).") -ForegroundColor Yellow
    }
}

function Read-ADPUMultiChoice {
    # Numbered menu that allows several picks at once: comma/space separated
    # numbers (e.g. "1,3"), or 'a' for all. Returns the chosen item texts.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)] [string]$Prompt,
        [Parameter(Mandatory, Position = 1)] [string[]]$Items
    )
    while ($true) {
        Write-Host ('[Ask]'.PadRight(8) + " $Prompt") -ForegroundColor Magenta
        for ($i = 0; $i -lt $Items.Count; $i++) {
            Write-Host ('        {0,2}) {1}' -f ($i + 1), $Items[$i]) -ForegroundColor Gray
        }
        Write-Host "        (e.g. 1,3  -  or  a  for all)" -ForegroundColor DarkGray
        Clear-ADPUInput
        $raw = ([string](Read-Host '   #')).Trim()
        if ($raw -match '^(a|all)$') { Write-Host ''; return $Items }
        $picked = [System.Collections.Generic.List[int]]::new()
        $bad = $false
        foreach ($tok in ($raw -split '[,\s]+' | Where-Object { $_ })) {
            $n = 0
            if ([int]::TryParse($tok, [ref]$n) -and $n -ge 1 -and $n -le $Items.Count) {
                if (-not $picked.Contains($n)) { [void]$picked.Add($n) }
            } else { $bad = $true; break }
        }
        if (-not $bad -and $picked.Count -gt 0) {
            Write-Host ''
            return @($picked | Sort-Object | ForEach-Object { $Items[$_ - 1] })
        }
        Write-Host ('[Warn]'.PadRight(8) + " Enter numbers 1-$($Items.Count) (e.g. 1,3) or 'a' for all.") -ForegroundColor Yellow
    }
}

function Start-ADPUActivity {
    # Runs $Work on a side runspace and spins a glyph on one redrawn line until it
    # finishes, so long network/log reads visibly show life. Output of $Work is
    # passed straight through. Falls back to a single line off real consoles.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)] [string]$Caption,
        [Parameter(Mandatory, Position = 1)] [scriptblock]$Work,
        [object[]]$With
    )

    $live = ($Host.Name -eq 'ConsoleHost')
    try { if ([System.Console]::IsOutputRedirected) { $live = $false } } catch { }

    if (-not $live) {
        Write-ADPULine note "$Caption..."
        return (& $Work @With)
    }

    $shell = $null
    try {
        $shell = [powershell]::Create()
        $null = $shell.AddScript($Work)
        foreach ($a in $With) { $null = $shell.AddArgument($a) }
        $async = $shell.BeginInvoke()
    } catch {
        if ($shell) { $shell.Dispose() }
        Write-ADPULine note "$Caption..."
        return (& $Work @With)
    }

    $spin = '|','/','-','\'
    $n = 0
    try {
        while (-not $async.IsCompleted) {
            Write-Host ("`r {0} {1}..." -f $spin[$n % $spin.Length], $Caption) -NoNewline -ForegroundColor Cyan
            Start-Sleep -Milliseconds 100
            $n++
        }
        $result = $shell.EndInvoke($async)
    } finally {
        $done = ('[Info]'.PadRight(8) + " $Caption... done.")
        Write-Host ("`r{0}" -f $done.PadRight($Caption.Length + 18)) -ForegroundColor Cyan
        $shell.Dispose()
    }
    $result
}

function Show-ADPUBanner {
    [CmdletBinding()]
    param([string]$Stamp)

    $rows = @(
        @('   _   ___  ___ _   _      _             _                 ', 'Red'),
        @('  /_\ |   \| _ \ | | |___ /_\  _ _  __ _| |_  _ ______ _ _ ', 'DarkYellow'),
        @(' / _ \| |) |  _/ |_| |___/ _ \| '' \/ _` | | || |_ / -_) ''_|', 'Yellow'),
        @('/_/ \_\___/|_|  \___/   /_/ \_\_||_\__,_|_|\_, /__\___|_|  ', 'Green'),
        @('                                           |__/            ', 'Cyan')
    )
    Write-Host ('{0,-59}' -f '')
    foreach ($r in $rows) {
        Write-Host ('{0,-59}' -f $r[0]) -BackgroundColor Black -ForegroundColor $r[1]
    }
    $line = if ([string]::IsNullOrWhiteSpace($Stamp)) { '' } else { "build $Stamp" }
    Write-Host ('{0,-59}' -f "    $line")            -BackgroundColor Black -ForegroundColor Magenta
    Write-Host ('{0,-59}' -f '    Made by Carbon/Nobrac')   -BackgroundColor Black -ForegroundColor Cyan
    Write-Host ('{0,-59}' -f '')                     -BackgroundColor Black
}

function Show-ADPUCredits {
    [CmdletBinding()]
    param()
    Wait-ADPUEnter '   Press Enter to finish'
    $mark = @'

                @@@@@@@@@@@@@
            @@@@@@@@@@@@@@@@@@@@@
         @@@@@@@@@@@@@@@@@@@@@@@@@@@
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
     @@@@@@@@@@@             @@@@@
    @@@@@@@@@@
   @@@@@@@@@@
   @@@@@@@@@
   @@@@@@@@@
   @@@@@@@@@
   @@@@@@@@@
   @@@@@@@@@@
    @@@@@@@@@@
     @@@@@@@@@@@             @@@@@
      @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
       @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
         @@@@@@@@@@@@@@@@@@@@@@@@@@@
            @@@@@@@@@@@@@@@@@@@@@
                @@@@@@@@@@@@@
'@
    Write-Host $mark -ForegroundColor Magenta
    Write-Host
    Write-Host '                 ADPU-Analyzer  -  Made by Carbon/Nobrac' -ForegroundColor Cyan
}

#  ==========================================================================
#  >> Active Directory helpers (SIDs, groups, controllers, events)
#  ==========================================================================

Add-Type -AssemblyName 'System.DirectoryServices.AccountManagement' -ErrorAction SilentlyContinue

function Get-ADPUDomainSid {
    <#
        Works out a domain's SID without needing RSAT: translate DOMAIN\krbtgt to a
        SID and lop off the trailing -502 RID. krbtgt always exists, so this is a
        reliable anchor.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $DomainName)

    $krbtgt = [Security.Principal.NTAccount]::new($DomainName, 'krbtgt').
                  Translate([Security.Principal.SecurityIdentifier]).Value
    [Security.Principal.SecurityIdentifier]::new($krbtgt.Substring(0, $krbtgt.Length - 4))
}

function Expand-ADPUGroup {
    <#
        Returns the recursive membership of a group, given the group's SID and the
        domain it lives in. Every returned principal is stamped with .HomeDomain so
        later stages know where it came from. Missing groups yield a warning, not a
        throw.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $GroupSid,
        [Parameter(Mandatory)] $Domain
    )

    $ctx   = [DirectoryServices.AccountManagement.PrincipalContext]::new('Domain', $Domain.Name)
    $group = [DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($ctx, [string]$GroupSid)

    if (-not $group) {
        Write-ADPULine warn "Group $GroupSid is absent in $($Domain.Name) - nothing to expand."
        return
    }

    try {
        foreach ($member in $group.GetMembers($true)) {
            $member | Add-Member -NotePropertyName HomeDomain -NotePropertyValue $Domain -Force -PassThru
        }
    } catch {
        Write-ADPULine warn "Could not read members of $GroupSid in $($Domain.Name)."
    }
}

function Get-ADPUPugTimestamp {
    <#
        Reads the whenCreated stamp of a domain's Protected Users group. Returns
        $null if the group is not present. Used to judge whether a password predates
        the group.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Domain,
        [Parameter(Mandatory)] $PugSid
    )

    $ctx   = [DirectoryServices.AccountManagement.PrincipalContext]::new('Domain', $Domain.Name)
    $group = [DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($ctx, [string]$PugSid)
    if ($group) { $group.GetUnderlyingObject().Properties['whenCreated'].Value }
}

function Test-ADPUPugPresent {
    <#
        True when the Protected Users group both exists and can be enumerated in the
        given domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Domain,
        [Parameter(Mandatory)] $PugSid
    )

    try {
        $ctx   = [DirectoryServices.AccountManagement.PrincipalContext]::new('Domain', $Domain.Name)
        $group = [DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($ctx, [string]$PugSid)
        if (-not $group) { return $false }
        $null = $group.GetMembers()
        $true
    } catch {
        $false
    }
}

function Test-ADPURemoting {
    # Is WSMan answering on this host? Wrapped in the spinner because an unreachable
    # box makes Test-WSMan sit on its timeout.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Controller)

    Start-ADPUActivity "Checking WinRM on $($Controller.Name)" -With $Controller -Work {
        param($box)
        $null = Test-WSMan -ComputerName $box -ErrorAction SilentlyContinue
        $?
    }
}

function Test-ADPUAuditReady {
    <#
        Confirms that Logon/Logoff > Logon auditing is set to Success+Failure on the
        controller. The whole check runs inside the remote session as a self-contained
        block (parses auditpol's CSV there and returns a single bool), so nothing has
        to be shipped to the remote runspace.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Controller)

    Start-ADPUActivity "Reading audit policy on $($Controller.Name)" -With $Controller -Work {
        param($box)
        Invoke-Command -ComputerName $box -ScriptBlock {
            $csv = New-TemporaryFile
            try {
                auditpol /get /category:"Logon/Logoff" /r | Out-File -FilePath $csv -Force
                $logon = Import-Csv -Path $csv |
                         Where-Object { $_.'Policy Target' -eq 'System' -and $_.Subcategory -eq 'Logon' }
                [bool]($logon -and $logon.'Inclusion Setting' -eq 'Success and Failure')
            } finally {
                Remove-Item $csv -ErrorAction SilentlyContinue
            }
        }
    }
}

function Get-ADPUSuspectLogons {
    <#
        Harvests the logon events that matter for Protected Users from a controller's
        Security log. -Flavor NTLM grabs 4624 logons that used NTLM; -Flavor WeakKerb
        grabs 4768 TGTs issued with DES/RC4 (i.e. anything that is not AES or the
        sentinel 0xFFFFFFFF). Each event carries a rendered .Detail string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Controller,
        [Parameter(Mandatory)][ValidateSet('NTLM', 'WeakKerb')] [string]$Flavor
    )

    $caption = if ($Flavor -eq 'NTLM') {
        "Sweeping $($Controller.Name) for NTLM logons"
    } else {
        "Sweeping $($Controller.Name) for DES/RC4 Kerberos"
    }

    Start-ADPUActivity $caption -With $Controller, $Flavor -Work {
        param($box, $flavor)
        Invoke-Command -ComputerName $box -ArgumentList $flavor -ScriptBlock {
            param($flavor)
            if ($flavor -eq 'NTLM') {
                $filter = @"
                    *[EventData[Data[@Name='AuthenticationPackageName'] and (Data='NTLM')]]
                    [System[(EventID=4624)]]
"@
            } else {
                $filter = @"
                    *[EventData
                        [Data[@Name='TicketEncryptionType']!='0x12']
                        [Data[@Name='TicketEncryptionType']!='0x11']
                        [Data[@Name='TicketEncryptionType']!='0xFFFFFFFF']]
                    [System[(EventID=4768)]]
"@
            }
            $q = [Diagnostics.Eventing.Reader.EventLogQuery]::new('Security', 'LogName', $filter)
            $r = [Diagnostics.Eventing.Reader.EventLogReader]::new($q)
            try {
                while ($null -ne ($e = $r.ReadEvent())) {
                    $e | Add-Member -NotePropertyName Detail -NotePropertyValue $e.FormatDescription() -Force -PassThru
                }
            } catch {
                # reading past the end / access trouble: stop quietly
            }
        }
    }
}

# The dedicated Protected Users channels. All three are OFF by default and have to
# be switched on before they record anything - the client one lives on the
# workstation, not on a controller.
$script:ADPUDcFailureLog = 'Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController'
$script:ADPUDcSuccessLog = 'Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController'
$script:ADPUClientLog    = 'Microsoft-Windows-Authentication/ProtectedUser-Client'

function Get-ADPUProtectedUserEvents {
    <#
        Reads one of the two DC-side Protected Users channels on a controller.
        -Flavor Failures picks up IDs 100/104 (an enrolled account was turned away
        because it tried NTLM or DES/RC4); -Flavor Successes picks up ID 303 (an
        enrolled account authenticated cleanly). Returns one object carrying the
        channel state (Present/Enabled) plus the events, so a disabled channel can
        be reported as "nothing recorded" instead of "nothing happened".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Controller,
        [Parameter(Mandatory)][ValidateSet('Failures', 'Successes')] [string]$Flavor,
        [int]$Days = 7
    )

    $log = if ($Flavor -eq 'Failures') { $script:ADPUDcFailureLog } else { $script:ADPUDcSuccessLog }
    $ids = if ($Flavor -eq 'Failures') { @(100, 104) } else { @(303) }

    # Built here and handed over as one string: a nested array would flatten into
    # the argument list and shift everything after it.
    $idPart = ($ids | ForEach-Object { "EventID=$_" }) -join ' or '

    Start-ADPUActivity "Reading protected-user $($Flavor.ToLowerInvariant()) on $($Controller.Name)" -With $Controller, $log, $idPart, $Days -Work {
        param($box, $log, $idPart, $days)
        Invoke-Command -ComputerName $box -ArgumentList $log, $idPart, $days -ScriptBlock {
            param($log, $idPart, $days)

            $out = [pscustomobject]@{ Log = $log; Present = $false; Enabled = $false; Events = @() }

            try {
                $cfg = [Diagnostics.Eventing.Reader.EventLogConfiguration]::new($log)
                $out.Present = $true
                $out.Enabled = [bool]$cfg.IsEnabled
            } catch {
                return $out          # channel not on this build
            }
            if (-not $out.Enabled) { return $out }

            $span   = [int64]$days * 86400000
            $filter = "*[System[($idPart) and TimeCreated[timediff(@SystemTime) <= $span]]]"

            try {
                $out.Events = @(
                    Get-WinEvent -LogName $log -FilterXPath $filter -ErrorAction Stop | ForEach-Object {
                        # The account field is not in a fixed slot across these
                        # channels, so pick the first Data element that looks like
                        # one and fall back to the first element.
                        $who = $null
                        try {
                            $data = @(([xml]$_.ToXml()).Event.EventData.Data)
                            $node = $data | Where-Object { $_.GetAttribute('Name') -match 'Account|User' } | Select-Object -First 1
                            if (-not $node) { $node = $data[0] }
                            if ($node) { $who = [string]$node.InnerText }
                        } catch { }
                        if ([string]::IsNullOrWhiteSpace($who)) { $who = '(account not named in event)' }

                        [pscustomobject]@{
                            Time    = $_.TimeCreated
                            Id      = $_.Id
                            Account = $who
                            Detail  = $_.FormatDescription()
                        }
                    }
                )
            } catch {
                # an empty channel throws rather than returning nothing - treat as none
            }
            $out
        }
    }
}

#  ==========================================================================
#  >> Environment sweep (build the annotated topology)
#  ==========================================================================

# Server builds new enough to honour Protected Users on a DC.
$script:ADPUModernServers = @(
    'Windows Server 2025 Standard',   'Windows Server 2025 Datacenter'
    'Windows Server 2022 Standard',   'Windows Server 2022 Datacenter'
    'Windows Server 2019 Standard',   'Windows Server 2019 Datacenter'
    'Windows Server 2016 Standard',   'Windows Server 2016 Datacenter'
    'Windows Server 2012 R2 Standard','Windows Server 2012 R2 Datacenter'
)

# Functional-level 6 == Server 2012 R2, the floor for the Protected Users group.
$script:ADPUFunctionalFloor = 6

function Get-ADPUTopology {
    <#
        .SYNOPSIS
            Discovers and annotates the whole environment in a single sweep.
        .DESCRIPTION
            Returns one object holding the forest, its reachable domains, their
            reachable controllers, the flattened privileged-account set, and the
            current Protected Users membership. Every domain/DC is tagged with the
            readiness facts the report consumes (functional level, group presence,
            audit state, harvested logon events, ...).
        .PARAMETER DomainName
            Optional list of domain names to limit the review to. When omitted,
            every reachable domain in the forest is surveyed (the default).
    #>
    [CmdletBinding()]
    param(
        [string[]]$DomainName
    )

    # -- forest -----------------------------------------------------------------
    Write-ADPULine note 'Mapping the forest...'
    $forest  = [DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $rootSid = Get-ADPUDomainSid -DomainName $forest.RootDomain.Name
    $forestAdminSids = @(518, 519) | ForEach-Object {
        [Security.Principal.SecurityIdentifier]::new("$rootSid-$_")
    }
    $forest | Add-Member -NotePropertyName ReadyFL   -NotePropertyValue ([bool]($forest.ForestModeLevel -ge $script:ADPUFunctionalFloor)) -Force
    $forest | Add-Member -NotePropertyName AdminSids -NotePropertyValue $forestAdminSids -Force
    $forest | Add-Member -NotePropertyName RootSid   -NotePropertyValue $rootSid -Force

    # -- domains ----------------------------------------------------------------
    Write-ADPULine note 'Walking the domains...'
    $candidateDomains = $forest.Domains
    if ($DomainName) {
        $pick = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]$DomainName, [System.StringComparer]::OrdinalIgnoreCase)
        $candidateDomains = @($forest.Domains | Where-Object { $pick.Contains($_.Name) })
        Write-ADPULine note ("Scope limited to: {0}" -f ($candidateDomains.Name -join ', '))
    }
    $domains = foreach ($d in $candidateDomains) {
        if (-not ($d.Forest -and $d.DomainControllers)) {
            Write-ADPULine warn "$($d.Name) is out of reach - leaving it out of the review."
            continue
        }
        $sid     = Get-ADPUDomainSid -DomainName $d.Name
        $pugSid  = [Security.Principal.SecurityIdentifier]::new("$sid-525")
        $present = Test-ADPUPugPresent -Domain $d -PugSid $pugSid
        $bornOn  = if ($present) { Get-ADPUPugTimestamp -Domain $d -PugSid $pugSid } else { $null }
        $adminSids = @(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')   # built-in Administrators
            [Security.Principal.SecurityIdentifier]::new("$sid-512")       # Domain Admins
        )

        $d | Add-Member -NotePropertyName Sid        -NotePropertyValue $sid       -Force
        $d | Add-Member -NotePropertyName ReadyFL    -NotePropertyValue ([bool]($d.DomainModeLevel -ge $script:ADPUFunctionalFloor)) -Force
        $d | Add-Member -NotePropertyName PugSid     -NotePropertyValue $pugSid    -Force
        $d | Add-Member -NotePropertyName PugPresent -NotePropertyValue $present   -Force
        $d | Add-Member -NotePropertyName PugBornOn  -NotePropertyValue $bornOn    -Force
        $d | Add-Member -NotePropertyName AdminSids  -NotePropertyValue $adminSids -Force
        $d
    }

    # -- controllers ------------------------------------------------------------
    Write-ADPULine note 'Reaching the controllers...'
    $controllers = foreach ($d in $domains) {
        $ctx = [DirectoryServices.ActiveDirectory.DirectoryContext]::new(0, $d.Name)
        foreach ($dc in [DirectoryServices.ActiveDirectory.DomainController]::FindAll($ctx)) {
            if (-not ($dc.Forest -and $dc.Domain)) {
                Write-ADPULine warn "$($dc.Name) is out of reach - leaving it out of the review."
                continue
            }

            $dc | Add-Member -NotePropertyName OSOk    -NotePropertyValue ([bool]($script:ADPUModernServers -contains [string]$dc.OSVersion)) -Force
            $dc | Add-Member -NotePropertyName WinRMUp -NotePropertyValue (Test-ADPURemoting -Controller $dc) -Force

            if (-not $dc.WinRMUp) {
                $dc | Add-Member -NotePropertyName AuditOk -NotePropertyValue $false -Force
                Write-ADPULine warn "WinRM is closed on $($dc.Name) - cannot inspect its logs."
            } else {
                $auditOk = $false
                try { $auditOk = [bool](Test-ADPUAuditReady -Controller $dc) } catch { $auditOk = $false }
                $dc | Add-Member -NotePropertyName AuditOk -NotePropertyValue $auditOk -Force

                if ($auditOk) {
                    $dc | Add-Member -NotePropertyName NtlmHits     -NotePropertyValue (Get-ADPUSuspectLogons -Controller $dc -Flavor NTLM)     -Force
                    $dc | Add-Member -NotePropertyName WeakKerbHits -NotePropertyValue (Get-ADPUSuspectLogons -Controller $dc -Flavor WeakKerb) -Force
                } else {
                    Write-ADPULine warn "Logon auditing is off on $($dc.Name) - its weak-auth data is unavailable."
                }
            }
            $dc
        }
    }

    # -- people -----------------------------------------------------------------
    Write-ADPULine note 'Flattening the Protected Users roster...'
    $pugMembers = foreach ($d in $domains) { Expand-ADPUGroup -GroupSid $d.PugSid -Domain $d }

    Write-ADPULine note 'Collecting privileged accounts...'
    # Enterprise/Schema Admins live in the forest root domain. Only expand them
    # when the root is in scope; otherwise this is a focused per-domain review.
    $rootInScope = (-not $DomainName) -or ($DomainName -contains $forest.RootDomain.Name)
    if ($rootInScope) {
        # Use the enriched copy of the root domain so forest admins carry PugBornOn etc.
        $rootEnriched = $domains | Where-Object { $_.Name -eq $forest.RootDomain.Name } | Select-Object -First 1
        if (-not $rootEnriched) { $rootEnriched = $forest.RootDomain }
        $forestAdmins = foreach ($s in $forest.AdminSids) { Expand-ADPUGroup -GroupSid $s -Domain $rootEnriched }
        $forestAdmins = @($forestAdmins | Sort-Object -Property DistinguishedName -Unique)
    } else {
        Write-ADPULine note 'Root domain is out of scope - skipping forest-wide Enterprise/Schema Admins.'
        $forestAdmins = @()
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@($forestAdmins.DistinguishedName | Where-Object { $_ })
    )
    $domainAdmins = foreach ($d in $domains) {
        foreach ($s in $d.AdminSids) {
            Expand-ADPUGroup -GroupSid $s -Domain $d | Where-Object {
                $_.DistinguishedName -and $seen.Add([string]$_.DistinguishedName)
            }
        }
    }

    [pscustomobject]@{
        Forest      = $forest
        Domains     = @($domains)
        Controllers = @($controllers)
        PugMembers  = @($pugMembers)
        Admins      = @(@($forestAdmins) + @($domainAdmins))
    }
}

#  ==========================================================================
#  >> Scoring (decide each accounts verdict)
#  ==========================================================================

function Set-ADPUReadiness {
    <#
        .SYNOPSIS
            Annotates every privileged account with its Protected Users readiness.
        .DESCRIPTION
            For each account adds: Enrolled (already a member), PwdStale (>1 year),
            PwdPreGroup (set before the group existed), DidNtlm / DidWeakKerb (seen
            using legacy auth on an audited DC), DesOnly / NoAesEtype (the account's
            own cipher configuration rules AES out), IsGmsa, Person (a real user
            account, not a computer/service account) and ClearNow (safe to enrol
            immediately).
            Mutates and returns the accounts.
        .PARAMETER Topology
            The object from Get-ADPUTopology.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Topology)

    # Fast lookup of who is already in a Protected Users group.
    $enrolledDns = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@($Topology.PugMembers.DistinguishedName | Where-Object { $_ })
    )

    # Only controllers we could actually read contribute legacy-auth evidence.
    $audited  = $Topology.Controllers | Where-Object { $_.AuditOk }
    $ntlmBlob = [string]::Join("`n", @($audited.NtlmHits.Detail     | Where-Object { $_ }))
    $weakBlob = [string]::Join("`n", @($audited.WeakKerbHits.Detail | Where-Object { $_ }))

    $oneYearAgo = (Get-Date).AddDays(-365)

    foreach ($acct in $Topology.Admins) {
        $sidText = [string]$acct.Sid
        $pwdSet  = $acct.LastPasswordSet
        $bornOn  = $acct.HomeDomain.PugBornOn

        $enrolled    = $enrolledDns.Contains([string]$acct.DistinguishedName)
        $pwdStale    = ($pwdSet -is [datetime]) -and ($pwdSet -lt $oneYearAgo)
        $pwdPreGroup = ($pwdSet -is [datetime]) -and ($bornOn -is [datetime]) -and ($pwdSet -lt $bornOn)
        $didNtlm     = (-not $enrolled) -and $sidText -and $ntlmBlob.Contains($sidText)
        $didWeak     = (-not $enrolled) -and $sidText -and $weakBlob.Contains($sidText)
        $person      = ([string]$acct.StructuralObjectClass) -match 'user|iNetOrgPerson'

        # Informational hardening signals - read straight from AD. These never
        # change the enrol verdict; they are surfaced as separate hints only.
        $adminCount = $false; $noPreAuth = $false; $pwdNeverExp = $false
        $delegation = $false; $disabled = $false

        # Deterministic cipher blockers - these come straight from AD, so unlike the
        # log-based checks they are reliable even when auditing was off.
        $desOnly = $false; $noAesEtype = $false; $etypes = $null
        $isGmsa  = ([string]$acct.StructuralObjectClass) -eq 'msDS-GroupManagedServiceAccount'
        try { $pwdNeverExp = [bool]$acct.PasswordNeverExpires } catch { }
        try { if ($null -ne $acct.Enabled) { $disabled = -not [bool]$acct.Enabled } } catch { }
        try {
            $de  = $acct.GetUnderlyingObject()
            try { $adminCount = ([int]($de.Properties['adminCount'].Value)) -eq 1 } catch { }
            try {
                $uac = [int]($de.Properties['userAccountControl'].Value)
                $noPreAuth  = (($uac -band 0x400000) -ne 0)   # DONT_REQ_PREAUTH
                $delegation = (($uac -band 0x80000)  -ne 0)   # TRUSTED_FOR_DELEGATION (unconstrained)
                $desOnly    = (($uac -band 0x200000) -ne 0)   # USE_DES_KEY_ONLY
            } catch { }
            try {
                # msDS-SupportedEncryptionTypes bits: 0x1 DES-CRC, 0x2 DES-MD5,
                # 0x4 RC4, 0x8 AES128, 0x10 AES256. Absent or 0 means "use the
                # default", which is AES - only an explicitly set value without any
                # AES bit locks the account out of the group.
                $raw = $de.Properties['msDS-SupportedEncryptionTypes'].Value
                if ($null -ne $raw) { $etypes = [int]$raw }
                $noAesEtype = ($null -ne $etypes) -and ($etypes -ne 0) -and (($etypes -band 0x18) -eq 0)
            } catch { }
        } catch { }

        $clearNow = $person -and -not $enrolled -and -not $pwdPreGroup -and -not $didNtlm -and -not $didWeak -and
                    -not $desOnly -and -not $noAesEtype

        $acct | Add-Member -NotePropertyName DesOnly     -NotePropertyValue $desOnly     -Force
        $acct | Add-Member -NotePropertyName NoAesEtype  -NotePropertyValue $noAesEtype  -Force
        $acct | Add-Member -NotePropertyName EncTypes    -NotePropertyValue $etypes      -Force
        $acct | Add-Member -NotePropertyName IsGmsa      -NotePropertyValue $isGmsa      -Force
        $acct | Add-Member -NotePropertyName Enrolled    -NotePropertyValue $enrolled    -Force
        $acct | Add-Member -NotePropertyName PwdStale    -NotePropertyValue $pwdStale    -Force
        $acct | Add-Member -NotePropertyName PwdPreGroup -NotePropertyValue $pwdPreGroup -Force
        $acct | Add-Member -NotePropertyName DidNtlm     -NotePropertyValue $didNtlm     -Force
        $acct | Add-Member -NotePropertyName DidWeakKerb -NotePropertyValue $didWeak     -Force
        $acct | Add-Member -NotePropertyName Person      -NotePropertyValue $person      -Force
        $acct | Add-Member -NotePropertyName ClearNow    -NotePropertyValue $clearNow    -Force
        $acct | Add-Member -NotePropertyName AdminCount  -NotePropertyValue $adminCount  -Force
        $acct | Add-Member -NotePropertyName PwdNeverExp -NotePropertyValue $pwdNeverExp -Force
        $acct | Add-Member -NotePropertyName NoPreAuth   -NotePropertyValue $noPreAuth   -Force
        $acct | Add-Member -NotePropertyName Delegation  -NotePropertyValue $delegation  -Force
        $acct | Add-Member -NotePropertyName Disabled    -NotePropertyValue $disabled    -Force
        $acct
    }
}

#  ==========================================================================
#  >> Walkthrough (present the findings)
#  ==========================================================================

$script:ADPULevelNames = @{
    0 = 'Server 2000'; 1 = 'Server 2003 (interim)'; 2 = 'Server 2003'
    3 = 'Server 2008'; 4 = 'Server 2008 R2';        5 = 'Server 2012'
    6 = 'Server 2012 R2'; 7 = 'Server 2016';        10 = 'Server 2025'
}

function Show-ADPUReadinessReport {
    <#
        .SYNOPSIS
            Renders the guided Protected Users readiness walkthrough.
        .DESCRIPTION
            Outcome-first layout: a summary, then the accounts that are clear to
            enrol now, then the blocked accounts (grouped per account), then those
            already enrolled, and lastly the environment prerequisites grouped by
            domain. Display order only - the underlying scoring is unchanged.
        .PARAMETER Topology
            The annotated object from Get-ADPUTopology / Set-ADPUReadiness.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Topology)

    $wait  = { Wait-ADPUEnter }
    $named = { param($a) '{0}\{1}' -f $a.HomeDomain.Name, $a.SamAccountName }
    $level = { param($n) if ($script:ADPULevelNames.ContainsKey([int]$n)) { $script:ADPULevelNames[[int]$n] } else { "level $n" } }

    $forest = $Topology.Forest

    $admins   = $Topology.Admins | Sort-Object @{ e = { $_.HomeDomain.Name } }, SamAccountName -Unique
    $enrolled = @($admins | Where-Object Enrolled)
    $pending  = @($admins | Where-Object { -not $_.Enrolled })
    $clear    = @($pending | Where-Object ClearNow)
    $blocked  = @($pending | Where-Object { -not $_.ClearNow })
    $auditGap = @($Topology.Controllers | Where-Object { -not $_.AuditOk })

    # ===== 1. Bottom line ====================================================
    Write-ADPULine head 'Summary'
    Write-ADPULine sub  'Privileged = inside Administrators, Domain Admins, Enterprise Admins or Schema Admins.'
    Write-ADPULine sub  'Real user accounts belong in Protected Users; computer and service accounts do not.'
    Write-ADPULine sub  'Clear = a user account with AES-capable keys and no NTLM or DES/RC4 seen in the logs that could be read. Each verdict is itemised below.'
    Write-ADPULine note ("{0} privileged accounts in total." -f @($admins).Count)
    Write-ADPULine note ("{0} already enrolled, {1} still outside the group." -f $enrolled.Count, $pending.Count)
    Write-ADPULine note ("{0} of the {1} pending accounts are clear to enrol right now." -f $clear.Count, $pending.Count)
    if ($auditGap) {
        Write-ADPULine warn ("{0} controller(s) had Logon auditing off - NTLM/Kerberos findings there are incomplete (details at the end)." -f $auditGap.Count)
    }
    & $wait

    # ===== 2. Action list first ==============================================
    Write-ADPULine head 'Clear to enrol now'
    if (-not $pending) {
        Write-ADPULine good 'Nothing pending - every privileged account is already enrolled.'
    } elseif ($clear) {
        Write-ADPULine sub 'Each account lists the evidence its verdict rests on.'
        foreach ($a in $clear) {
            Write-ADPULine good (& $named $a)
            foreach ($r in (Get-ADPUClearReasons -Account $a -Topology $Topology)) {
                if ($r.Kind -eq 'warn') { Write-ADPULine warn ('   ' + $r.Text) }
                else                    { Write-ADPULine sub  ('  - ' + $r.Text) }
            }
        }
        Write-Host ''
        $clear | ForEach-Object {
            Write-ADPULine snippet ("Add-ADGroupMember -Identity 'Protected Users' -Members '{0}' -Server '{1}'" -f ($_.SamAccountName -replace "'", "''"), ($_.HomeDomain.Name -replace "'", "''"))
        }
        Write-Host ''
        Write-ADPULine tip 'Use an account allowed to change the group. New to this? Enrol one, prove it still works end to end, then do the rest.'
    } else {
        Write-ADPULine note 'Nothing is clear to enrol yet - work through the blockers below first.'
    }
    & $wait

    # ===== 3. Blocked accounts, per account ==================================
    if ($blocked) {
        Write-ADPULine head 'Still blocked - per account'
        Write-ADPULine sub  'Each account lists only what is holding it back.'
        foreach ($a in $blocked) {
            Write-ADPULine note (& $named $a)
            if ($a.IsGmsa) {
                Write-ADPULine bad  '   group managed service account - cannot join Protected Users (nor be marked sensitive); use an authentication policy silo instead, and reconsider its admin rights'
            } elseif (-not $a.Person) {
                Write-ADPULine bad  '   not a user account (computer/service) - cannot be enrolled; reconsider its admin rights'
            }
            if ($a.DesOnly) {
                Write-ADPULine bad  '   "use DES encryption types only" is set (userAccountControl 0x200000) - clear the flag and reset the password'
            }
            if ($a.NoAesEtype) {
                Write-ADPULine bad  ('   msDS-SupportedEncryptionTypes = 0x{0:X} permits no AES - add AES128/AES256 or clear the attribute' -f [int]$a.EncTypes)
            }
            if ($a.PwdPreGroup) {
                Write-ADPULine bad  '   password predates the group - must be reset before enrolling'
            } elseif ($a.PwdStale) {
                Write-ADPULine warn '   password is over a year old - rotate it soon'
            }
            if ($a.DidNtlm) {
                Write-ADPULine bad  '   recently authenticated with NTLM - track down the dependency first'
            }
            if ($a.DidWeakKerb) {
                Write-ADPULine bad  '   recently used DES/RC4 Kerberos - fix the cipher usage first'
            }
        }
        & $wait
    }

    # ===== 4. Already enrolled ===============================================
    Write-ADPULine head 'Already enrolled'
    if ($enrolled) { $enrolled | ForEach-Object { Write-ADPULine good (& $named $_) } }
    else           { Write-ADPULine note 'None yet.' }
    & $wait

    # ===== 4b. Hardening hints (informational only) ==========================
    $hinted = @($admins | Where-Object { ($_.AdminCount -and -not $_.Enrolled) -or $_.PwdNeverExp -or $_.NoPreAuth -or $_.Delegation -or $_.Disabled })
    Write-ADPULine head 'Hardening hints (informational)'
    Write-ADPULine sub  'Side observations, unrelated to the enrol decision - worth a look, but they block nothing.'
    if (-not $hinted) {
        Write-ADPULine good 'Nothing flagged.'
    } else {
        foreach ($a in $hinted) {
            Write-ADPULine note (& $named $a)
            if ($a.AdminCount -and -not $a.Enrolled) {
                Write-ADPULine warn '   adminCount=1 but not in Protected Users - a protected admin left outside the group'
            }
            if ($a.PwdNeverExp) {
                Write-ADPULine warn '   password is set to never expire'
            }
            if ($a.NoPreAuth) {
                Write-ADPULine warn '   Kerberos pre-auth not required (AS-REP roastable)'
            }
            if ($a.Delegation) {
                Write-ADPULine warn '   trusted for unconstrained delegation - high-value target'
            }
            if ($a.Disabled) {
                Write-ADPULine warn '   account is disabled but still sits in an admin group - consider removing it'
            }
        }
    }
    & $wait

    # ===== 5. Environment prerequisites, grouped by domain ===================
    Write-ADPULine head 'Environment - foundation (per domain)'
    Write-ADPULine sub  'These are the conditions that decide whether the group exists and whether this review could see everything.'
    if ($forest.ReadyFL) {
        Write-ADPULine good ("Forest {0} at {1} - the group is available forest-wide." -f $forest.Name, (& $level $forest.ForestModeLevel))
    } else {
        Write-ADPULine warn ("Forest {0} at {1} - group availability is decided per domain (below)." -f $forest.Name, (& $level $forest.ForestModeLevel))
    }
    Write-Host ''

    foreach ($d in $Topology.Domains) {
        $lvl = (& $level $d.DomainModeLevel)

        # domain line: presence of the group at this level
        if ($d.PugPresent -and $d.ReadyFL) {
            Write-ADPULine good "Domain $($d.Name) ($lvl): group present; full client- and DC-side cover inside the domain."
        } elseif ($d.PugPresent) {
            Write-ADPULine warn "Domain $($d.Name) ($lvl): group present, level too low for DC-side cover (client-side only)."
        } else {
            Write-ADPULine bad  "Domain $($d.Name) ($lvl): no Protected Users group - move the PDC emulator onto a 2012 R2+ controller to create it."
        }

        # its controllers: OS + audit together, indented under the domain
        $dcs = @($Topology.Controllers | Where-Object { $_.Domain -eq $d.Name })
        if (-not $dcs) { $dcs = @($Topology.Controllers) }   # fallback if .Domain does not line up
        foreach ($dc in $dcs) {
            $osText    = if ($dc.OSOk)    { "OS $($dc.OSVersion) ok" }            else { "OS $($dc.OSVersion) too old" }
            $auditText = if ($dc.AuditOk) { 'auditing on' }                        else { 'auditing off' }
            if ($dc.OSOk -and $dc.AuditOk) {
                Write-ADPULine good "   $($dc.Name): $osText, $auditText."
            } elseif ($dc.AuditOk) {
                Write-ADPULine warn "   $($dc.Name): $osText, $auditText."
            } else {
                Write-ADPULine bad  "   $($dc.Name): $osText, $auditText."
                if (Read-ADPUYesNo "   Show the command to turn Logon auditing on for $($dc.Name)?") {
                    Write-ADPULine snippet "Invoke-Command -ComputerName $($dc.Name) -ScriptBlock { auditpol /set /subcategory:Logon /success:enable /failure:enable }"
                    Write-ADPULine tip     'Run it with rights over that controller.'
                }
            }
        }
        Write-Host ''
    }
    & $wait
}

#  ==========================================================================
#  >> Entry point
#  ==========================================================================

#  ==========================================================================
#  >> HTML report (same findings, as a standalone web page)
#  ==========================================================================

function Export-ADPUHtmlReport {
    <#
        .SYNOPSIS
            Writes the readiness findings to a self-contained HTML file.
        .DESCRIPTION
            Renders the same data the console walkthrough shows (summary, clear-to-
            enrol list with commands, blocked accounts with their blockers, enrolled
            accounts, and the per-domain environment) into one HTML file with inline
            CSS, so it opens in any browser with no dependencies.
        .PARAMETER Topology
            The annotated object from Get-ADPUTopology / Set-ADPUReadiness.
        .PARAMETER Path
            Destination .html file. Parent folders are created if needed.
        .OUTPUTS
            The full path of the written file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)] $Topology,
        [Parameter(Mandatory, Position = 1)] [string]$Path
    )

    # tiny HTML escaper so account/domain text cannot break the markup
    function enc([object]$s) {
        $x = [string]$s
        $x = $x.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
        $x
    }
    $lvl = { param($n) if ($script:ADPULevelNames.ContainsKey([int]$n)) { $script:ADPULevelNames[[int]$n] } else { "level $n" } }

    $forest    = $Topology.Forest
    $admins    = $Topology.Admins | Sort-Object @{ e = { $_.HomeDomain.Name } }, SamAccountName -Unique
    $enrolled  = @($admins | Where-Object Enrolled)
    $pending   = @($admins | Where-Object { -not $_.Enrolled })
    $clear     = @($pending | Where-Object ClearNow)
    $blocked   = @($pending | Where-Object { -not $_.ClearNow })
    $auditGap  = @($Topology.Controllers | Where-Object { -not $_.AuditOk })
    $generated = Get-Date

    $css = @'
:root{color-scheme:light}
*{box-sizing:border-box}
body{font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#f4f5f7;color:#1f2430;line-height:1.45}
header{background:#2b2f3a;color:#fff;padding:24px 28px}
header h1{margin:0;font-size:22px;letter-spacing:.5px}
.muted{color:#6b7280}
header .muted{color:#c8ccd4}
main,section{padding:0 28px}
h2{margin:28px 0 8px;font-size:17px;border-bottom:2px solid #e3e6ea;padding-bottom:6px}
h3{margin:18px 0 4px;font-size:14px}
.cards{display:flex;flex-wrap:wrap;gap:14px;padding:20px 28px 0}
.card{flex:1 1 150px;background:#fff;border:1px solid #e3e6ea;border-radius:10px;padding:14px 16px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
.card .num{font-size:26px;font-weight:700}
.card .lbl{font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:.4px}
.card.good .num{color:#15803d}.card.warn .num{color:#b45309}.card.ok .num{color:#1d4ed8}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e3e6ea;border-radius:8px;overflow:hidden;margin:6px 0 4px}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid #eef0f3;font-size:13px}
th{background:#f0f2f5;font-weight:600}
tr:last-child td{border-bottom:none}
td.ok{color:#15803d}td.bad{color:#b91c1c}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;margin:1px 2px;white-space:nowrap}
.badge.bad{background:#fde2e1;color:#b91c1c}.badge.warn{background:#fdeecd;color:#92590a}
p.good{color:#15803d}p.warn{color:#b45309}p.bad{color:#b91c1c}
ul.why{margin:0;padding-left:16px}
ul.why li{font-size:12px;color:#4b5563;margin:1px 0}
ul.why li.warn{color:#b45309}
.banner{padding:10px 14px;border-radius:8px;margin:14px 0}
.banner.warn{background:#fdeecd;color:#7c4a02;border:1px solid #f3d28a}
pre{background:#1f2430;color:#e7e9ee;border-radius:8px;padding:12px 14px;overflow:auto;font-size:12.5px}
code{font-family:Consolas,Monaco,monospace}
footer{padding:20px 28px 32px;color:#9aa1ad;font-size:12px}
'@

    $sb  = [System.Text.StringBuilder]::new()
    $add = { param([string]$x) [void]$sb.AppendLine($x) }

    & $add '<!DOCTYPE html>'
    & $add '<html lang="en"><head><meta charset="utf-8">'
    & $add '<meta name="viewport" content="width=device-width, initial-scale=1">'
    & $add ('<title>ADPU-Analyzer - {0}</title>' -f (enc $forest.Name))
    & $add ('<style>{0}</style>' -f $css)
    & $add '</head><body>'

    & $add '<header><h1>ADPU-Analyzer</h1>'
    & $add ('<p class="muted">Forest <strong>{0}</strong> &middot; generated {1:yyyy-MM-dd HH:mm} &middot; Made by Carbon/Nobrac</p>' -f (enc $forest.Name), $generated)
    & $add '</header><main>'

    & $add '<section class="cards">'
    & $add ('<div class="card"><div class="num">{0}</div><div class="lbl">privileged accounts</div></div>' -f @($admins).Count)
    & $add ('<div class="card good"><div class="num">{0}</div><div class="lbl">already enrolled</div></div>' -f $enrolled.Count)
    & $add ('<div class="card warn"><div class="num">{0}</div><div class="lbl">still pending</div></div>' -f $pending.Count)
    & $add ('<div class="card ok"><div class="num">{0}</div><div class="lbl">clear to enrol now</div></div>' -f $clear.Count)
    & $add '</section>'

    if ($auditGap.Count) {
        & $add ('<section><p class="banner warn">{0} controller(s) had Logon auditing off - NTLM/Kerberos findings there are incomplete.</p></section>' -f $auditGap.Count)
    }

    & $add '<section><h2>Clear to enrol now</h2>'
    if ($clear.Count) {
        & $add '<table><thead><tr><th>Domain</th><th>Account</th><th>Why it is clear</th></tr></thead><tbody>'
        foreach ($a in $clear) {
            $why = [System.Collections.Generic.List[string]]::new()
            foreach ($r in (Get-ADPUClearReasons -Account $a -Topology $Topology)) {
                $cls = if ($r.Kind -eq 'warn') { ' class="warn"' } else { '' }
                [void]$why.Add(('<li{0}>{1}</li>' -f $cls, (enc $r.Text)))
            }
            & $add ('<tr><td>{0}</td><td>{1}</td><td><ul class="why">{2}</ul></td></tr>' -f (enc $a.HomeDomain.Name), (enc $a.SamAccountName), ($why -join ''))
        }
        & $add '</tbody></table>'
        & $add '<h3>Enrolment commands</h3><pre><code>'
        foreach ($a in $clear) { & $add (enc ("Add-ADGroupMember -Identity 'Protected Users' -Members '{0}' -Server '{1}'" -f ($a.SamAccountName -replace "'", "''"), ($a.HomeDomain.Name -replace "'", "''"))) }
        & $add '</code></pre>'
    } elseif (-not $pending.Count) {
        & $add '<p class="good">Every privileged account is already enrolled.</p>'
    } else {
        & $add '<p class="muted">Nothing is clear yet - resolve the blockers below first.</p>'
    }
    & $add '</section>'

    if ($blocked.Count) {
        & $add '<section><h2>Still blocked</h2>'
        & $add '<table><thead><tr><th>Domain</th><th>Account</th><th>Blockers</th></tr></thead><tbody>'
        foreach ($a in $blocked) {
            $badges = [System.Collections.Generic.List[string]]::new()
            if ($a.IsGmsa) { [void]$badges.Add('<span class="badge bad">gMSA - not eligible</span>') }
            elseif (-not $a.Person) { [void]$badges.Add('<span class="badge bad">not a user account</span>') }
            if ($a.DesOnly) { [void]$badges.Add('<span class="badge bad">DES only (UAC 0x200000)</span>') }
            if ($a.NoAesEtype) { [void]$badges.Add(('<span class="badge bad">no AES in msDS-SupportedEncryptionTypes (0x{0:X})</span>' -f [int]$a.EncTypes)) }
            if ($a.PwdPreGroup) { [void]$badges.Add('<span class="badge bad">password predates group</span>') }
            elseif ($a.PwdStale) { [void]$badges.Add('<span class="badge warn">password &gt; 1 year</span>') }
            if ($a.DidNtlm) { [void]$badges.Add('<span class="badge bad">recent NTLM</span>') }
            if ($a.DidWeakKerb) { [void]$badges.Add('<span class="badge bad">recent DES/RC4</span>') }
            & $add ('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (enc $a.HomeDomain.Name), (enc $a.SamAccountName), ($badges -join ' '))
        }
        & $add '</tbody></table></section>'
    }

    & $add '<section><h2>Already enrolled</h2>'
    if ($enrolled.Count) {
        & $add '<table><thead><tr><th>Domain</th><th>Account</th></tr></thead><tbody>'
        foreach ($a in $enrolled) { & $add ('<tr><td>{0}</td><td>{1}</td></tr>' -f (enc $a.HomeDomain.Name), (enc $a.SamAccountName)) }
        & $add '</tbody></table>'
    } else {
        & $add '<p class="muted">None yet.</p>'
    }
    & $add '</section>'

    & $add '<section><h2>Hardening hints <span class="muted">(informational)</span></h2>'
    $hinted = @($admins | Where-Object { ($_.AdminCount -and -not $_.Enrolled) -or $_.PwdNeverExp -or $_.NoPreAuth -or $_.Delegation -or $_.Disabled })
    if ($hinted.Count) {
        & $add '<table><thead><tr><th>Domain</th><th>Account</th><th>Hints</th></tr></thead><tbody>'
        foreach ($a in $hinted) {
            $hb = [System.Collections.Generic.List[string]]::new()
            if ($a.AdminCount -and -not $a.Enrolled) { [void]$hb.Add('<span class="badge warn">adminCount=1, not in Protected Users</span>') }
            if ($a.PwdNeverExp) { [void]$hb.Add('<span class="badge warn">password never expires</span>') }
            if ($a.NoPreAuth)   { [void]$hb.Add('<span class="badge warn">no Kerberos pre-auth</span>') }
            if ($a.Delegation)  { [void]$hb.Add('<span class="badge bad">unconstrained delegation</span>') }
            if ($a.Disabled)    { [void]$hb.Add('<span class="badge warn">disabled, still in admin group</span>') }
            & $add ('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (enc $a.HomeDomain.Name), (enc $a.SamAccountName), ($hb -join ' '))
        }
        & $add '</tbody></table>'
    } else {
        & $add '<p class="good">Nothing flagged.</p>'
    }
    & $add '</section>'

    & $add '<section><h2>Environment</h2>'
    if ($forest.ReadyFL) {
        & $add ('<p class="good">Forest {0} at {1} - the group is available forest-wide.</p>' -f (enc $forest.Name), (enc (& $lvl $forest.ForestModeLevel)))
    } else {
        & $add ('<p class="warn">Forest {0} at {1} - group availability decided per domain.</p>' -f (enc $forest.Name), (enc (& $lvl $forest.ForestModeLevel)))
    }
    foreach ($d in $Topology.Domains) {
        $dl = enc (& $lvl $d.DomainModeLevel)
        if ($d.PugPresent -and $d.ReadyFL) { $cls = 'good'; $msg = 'group present; full client- and DC-side cover inside the domain' }
        elseif ($d.PugPresent) { $cls = 'warn'; $msg = 'group present, level too low for DC-side cover (client-side only)' }
        else { $cls = 'bad'; $msg = 'no Protected Users group - move the PDC emulator onto a 2012 R2+ controller to create it' }
        & $add ('<h3>{0} <span class="muted">({1})</span></h3>' -f (enc $d.Name), $dl)
        & $add ('<p class="{0}">{1}</p>' -f $cls, $msg)

        $dcs = @($Topology.Controllers | Where-Object { $_.Domain -eq $d.Name })
        if (-not $dcs.Count) { $dcs = @($Topology.Controllers) }
        & $add '<table><thead><tr><th>Controller</th><th>OS</th><th>Auditing</th></tr></thead><tbody>'
        foreach ($dc in $dcs) {
            $osCls = if ($dc.OSOk) { 'ok' } else { 'bad' }
            $auCls = if ($dc.AuditOk) { 'ok' } else { 'bad' }
            $auTxt = if ($dc.AuditOk) { 'on' } else { 'off' }
            & $add ('<tr><td>{0}</td><td class="{1}">{2}</td><td class="{3}">{4}</td></tr>' -f (enc $dc.Name), $osCls, (enc $dc.OSVersion), $auCls, $auTxt)
        }
        & $add '</tbody></table>'
    }
    & $add '</section></main>'

    & $add ('<footer>ADPU-Analyzer &middot; generated {0:yyyy-MM-dd HH:mm:ss}</footer>' -f $generated)
    & $add '</body></html>'

    $html = $sb.ToString()
    $dir  = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $html | Out-File -LiteralPath $Path -Encoding UTF8
    (Resolve-Path -LiteralPath $Path).Path
}

function Get-ADPUClearReasons {
    <#
        .SYNOPSIS
            Spells out why an account came back as "clear to enrol".
        .DESCRIPTION
            The blocked list already says what is holding an account back; this is
            the mirror image, so a green verdict can be checked rather than taken on
            faith. Each line is a fact the verdict rests on, tagged 'sub' for
            evidence and 'warn' where the evidence is thin - notably when no
            controller could be audited, in which case the legacy-auth checks found
            nothing simply because they could not look.
        .OUTPUTS
            Objects with .Kind ('sub'/'warn') and .Text.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Account,
        [Parameter(Mandatory)] $Topology
    )

    $out = [System.Collections.Generic.List[object]]::new()
    $say = { param($kind, $text) [void]$out.Add([pscustomobject]@{ Kind = $kind; Text = $text }) }

    # -- what kind of object it is ---------------------------------------------
    & $say 'sub' ('account type "{0}" - a real user account, which is what the group is for' -f [string]$Account.StructuralObjectClass)

    # -- password / AES keys ----------------------------------------------------
    $pwd  = $Account.LastPasswordSet
    $born = $Account.HomeDomain.PugBornOn
    if (($pwd -is [datetime]) -and ($born -is [datetime])) {
        & $say 'sub' ('password set {0:yyyy-MM-dd}, after the group appeared on {1:yyyy-MM-dd} - so AES keys were generated for it' -f $pwd, $born)
    } elseif ($pwd -is [datetime]) {
        & $say 'warn' ('password set {0:yyyy-MM-dd}, but the group age is unknown here - AES keys are assumed, not proven' -f $pwd)
    } else {
        & $say 'warn' 'password age unknown - AES keys are assumed, not proven'
    }
    if ($Account.PwdStale) {
        & $say 'warn' 'that password is over a year old - worth rotating, though it does not block enrolment'
    }

    # -- cipher configuration on the account itself -----------------------------
    if ($null -eq $Account.EncTypes) {
        & $say 'sub' 'msDS-SupportedEncryptionTypes is not set, so the account follows the domain default (AES)'
    } else {
        & $say 'sub' ('msDS-SupportedEncryptionTypes = 0x{0:X}, which includes AES' -f [int]$Account.EncTypes)
    }
    & $say 'sub' 'the "use DES encryption types only" flag is not set'

    # -- what the logs did (or did not) show ------------------------------------
    $audited = @($Topology.Controllers | Where-Object { $_.AuditOk })
    $blind   = @($Topology.Controllers | Where-Object { -not $_.AuditOk })
    if (-not $audited.Count) {
        & $say 'warn' 'no controller could be audited - the NTLM and DES/RC4 checks came back empty because they could not look, not because nothing was found'
    } else {
        $names = @($audited.Name | Sort-Object)
        $where = if ($names.Count -le 3) { $names -join ', ' } else { ($names[0..2] -join ', ') + (' and {0} more' -f ($names.Count - 3)) }
        & $say 'sub' ('no NTLM logon (4624) carrying this SID in the Security log of {0} audited controller(s): {1}' -f $audited.Count, $where)
        & $say 'sub' 'no DES/RC4 Kerberos ticket (4768) carrying this SID there either'
        if ($blind.Count) {
            & $say 'warn' ('{0} further controller(s) could not be read - anything that happened only there is invisible to this verdict' -f $blind.Count)
        }
    }

    $out
}

#  ==========================================================================
#  >> Post-enrolment verification (did enrolling actually break anything?)
#  ==========================================================================

function Invoke-ADPUVerification {
    <#
        .SYNOPSIS
            Checks the Protected Users operational logs after accounts were enrolled.
        .DESCRIPTION
            The readiness review is backward-looking; this is the other half. Once
            accounts are in the group, the dedicated channels record every time the
            group turned an account away (failures) or let it through (successes).
            Walks every reachable controller in scope, reports which accounts are
            still hitting a wall, and prints the command to switch a channel on when
            it is off - which it is by default.
        .PARAMETER Domain
            Optional list of domains. Omit for every reachable domain in the forest.
        .PARAMETER Days
            How far back to look. Default 7.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Domain,
        [int]$Days = 7
    )

    Write-ADPULine head 'Post-enrolment verification'
    Write-ADPULine sub  "Reads the Protected Users channels on each controller, covering the last $Days day(s)."
    Write-ADPULine sub  'Failures = an enrolled account still tried NTLM or DES/RC4. Successes = the group is working.'

    $forest  = [DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $domains = if ($Domain) { @($forest.Domains | Where-Object { $Domain -contains $_.Name }) } else { @($forest.Domains) }
    if (-not $domains) {
        Write-ADPULine bad 'No domain in scope is reachable.'
        return
    }

    $sawFailure = $false
    $sawSuccess = $false
    $blindSpots = 0

    foreach ($d in $domains) {
        Write-ADPULine note "Domain $($d.Name)"

        $ctx = [DirectoryServices.ActiveDirectory.DirectoryContext]::new(0, $d.Name)
        foreach ($dc in [DirectoryServices.ActiveDirectory.DomainController]::FindAll($ctx)) {

            if (-not (Test-ADPURemoting -Controller $dc)) {
                Write-ADPULine warn "   $($dc.Name): WinRM closed - skipped."
                $blindSpots++
                continue
            }

            foreach ($flavor in 'Failures', 'Successes') {
                $res = $null
                try { $res = Get-ADPUProtectedUserEvents -Controller $dc -Flavor $flavor -Days $Days } catch { }

                if (-not $res) {
                    Write-ADPULine warn "   $($dc.Name): could not read the $flavor channel."
                    $blindSpots++
                    continue
                }
                if (-not $res.Present) {
                    Write-ADPULine warn "   $($dc.Name): the $flavor channel does not exist on this build."
                    $blindSpots++
                    continue
                }
                if (-not $res.Enabled) {
                    Write-ADPULine warn "   $($dc.Name): the $flavor channel is switched off - nothing was recorded."
                    Write-ADPULine snippet ("Invoke-Command -ComputerName '{0}' -ScriptBlock {{ wevtutil sl '{1}' /e:true }}" -f $dc.Name, $res.Log)
                    $blindSpots++
                    continue
                }

                $events = @($res.Events)
                if (-not $events.Count) {
                    if ($flavor -eq 'Failures') {
                        Write-ADPULine good "   $($dc.Name): no protected-user failures in the last $Days day(s)."
                    } else {
                        Write-ADPULine note "   $($dc.Name): no protected-user logons recorded - either nobody signed in here, or nobody is enrolled yet."
                    }
                    continue
                }

                if ($flavor -eq 'Successes') {
                    $sawSuccess = $true
                    $people = @($events.Account | Sort-Object -Unique).Count
                    Write-ADPULine good ("   {0}: {1} clean protected-user logon(s) from {2} account(s)." -f $dc.Name, $events.Count, $people)
                    continue
                }

                $sawFailure = $true
                Write-ADPULine bad ("   {0}: {1} protected-user failure(s)." -f $dc.Name, $events.Count)
                foreach ($g in ($events | Group-Object Account | Sort-Object Count -Descending)) {
                    $last  = @($g.Group.Time | Sort-Object -Descending)[0]
                    $first = ((([string]$g.Group[0].Detail) -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 1)
                    Write-ADPULine bad ("      {0} - {1}x, last {2:yyyy-MM-dd HH:mm} (event {3})" -f $g.Name, $g.Count, $last, $g.Group[0].Id)
                    if ($first) { Write-ADPULine sub ("      {0}" -f $first.Trim()) }
                }
            }
        }
        Write-Host ''
    }

    Write-ADPULine head 'Verification - bottom line'
    if ($sawFailure) {
        Write-ADPULine bad  'Enrolled accounts are still being turned away. Fix the dependency, or pull the account back out of the group while you do.'
    } elseif ($sawSuccess) {
        Write-ADPULine good 'No failures recorded, and protected logons are coming through - the enrolment is holding.'
    } else {
        Write-ADPULine warn 'No evidence either way. Give it a full working day of real sign-ins before reading anything into this.'
    }
    if ($blindSpots) {
        Write-ADPULine warn ("{0} channel(s)/controller(s) could not be read - this verdict is only as good as the coverage above." -f $blindSpots)
    }
    Write-ADPULine tip ("Client side is separate: enable '{0}' on the workstation and look for IDs 104/304 there. This run only covers controllers." -f $script:ADPUClientLog)
    Write-ADPULine tip 'Protected Users only bites on a fresh logon - sign out and back in before trusting a quiet result.'
    Wait-ADPUEnter
}

function Invoke-ADPUAnalyzer {
    <#
        .SYNOPSIS
            Runs the full, guided Protected Users readiness review for the forest.
        .DESCRIPTION
            End-to-end entry point: prerequisite checks, environment survey,
            per-account scoring, and the interactive report. On a domain controller
            it insists on an elevated session, since reading the local Security log
            requires it.
        .EXAMPLE
            Invoke-ADPUAnalyzer
        .EXAMPLE
            Invoke-ADPUAnalyzer -Domain child.example.com
            Skips the prompt and reviews only that domain.
        .EXAMPLE
            Invoke-ADPUAnalyzer -Domain corp.example.net -HtmlPath C:\reports\pu.html
            Reviews one domain and writes the HTML report without prompting.
        .EXAMPLE
            Invoke-ADPUAnalyzer -Verify -Days 3
            Skips the readiness review and reports what the Protected Users channels
            recorded for already-enrolled accounts over the last three days.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Domain,
        [string]$HtmlPath,
        [switch]$Verify,
        [int]$Days = 7
    )

    Show-ADPUBanner -Stamp (Get-Date -Format 'yyyy.MM.dd')

    $here = Get-ADPUHostContext
    if ($here.IsDomainController -and -not $here.IsElevated) {
        $relaunch = if ($Host.Name -eq 'Windows PowerShell ISE Host') {
            'powershell_ise.exe'
        } elseif ($Host.Version.Major -gt 6) {
            'pwsh.exe'
        } else {
            'powershell.exe'
        }
        throw "On a domain controller, ADPU-Analyzer needs administrator rights to read the local Security log. Close this window, relaunch $relaunch via right-click -> 'Run as Administrator', and run it again."
    }

    # Decide the scope. If -Domain was supplied, honour it. Otherwise discover the
    # forest's domains and, when there is more than one, let the operator pick one
    # or choose "all".
    $scope = $Domain
    if (-not $scope) {
        $forest      = [DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $domainNames = @($forest.Domains | ForEach-Object { $_.Name } | Sort-Object)
        if ($domainNames.Count -gt 1) {
            $picked = Read-ADPUMultiChoice 'Which domain(s) should I review?' $domainNames
            # Picking every domain is treated as "all" (keeps forest-wide admins in scope).
            if (@($picked).Count -lt $domainNames.Count) { $scope = @($picked) }
        }
    }

    # -Verify is the after-the-fact pass: no readiness sweep, just the operational
    # logs for accounts that are already in the group.
    if ($Verify) {
        Invoke-ADPUVerification -Domain $scope -Days $Days
        Show-ADPUCredits
        return
    }

    $topology = Get-ADPUTopology -DomainName $scope
    $null     = Set-ADPUReadiness -Topology $topology

    Write-ADPULine note 'Survey complete - rendering the report.'
    Wait-ADPUEnter '   Press Enter to view the findings'
    Write-Host

    Show-ADPUReadinessReport -Topology $topology

    # Optional HTML report: -HtmlPath writes silently; otherwise offer to save one.
    $reportPath = $HtmlPath
    if (-not $reportPath) {
        if (Read-ADPUYesNo 'Save an HTML report of these findings?') {
            $suggest    = Join-Path (Get-Location).Path ('ADPU-Analyzer-{0:yyyyMMdd-HHmmss}.html' -f (Get-Date))
            $typed      = Read-ADPUAnswer "Path for the HTML file [$suggest]"
            $reportPath = if ([string]::IsNullOrWhiteSpace($typed)) { $suggest } else { $typed }
        }
    }
    if ($reportPath) {
        try {
            $written = Export-ADPUHtmlReport -Topology $topology -Path $reportPath
            Write-ADPULine good "HTML report saved: $written"
        } catch {
            Write-ADPULine bad "Could not write the HTML report: $($_.Exception.Message)"
        }
    }

    Show-ADPUCredits
}

#  ----------------------------------------------------------------------------
#  Kick off automatically, unless the file was dot-sourced (then it only loads).
#  ----------------------------------------------------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-ADPUAnalyzer
}
