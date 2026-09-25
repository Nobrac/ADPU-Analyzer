#  ADPU-Analyzer
#  -------------
#  Reviews an Active Directory forest and works out which privileged accounts
#  can safely be placed into the Protected Users group - and which still have a
#  blocker (legacy auth, missing AES keys, delegation, wrong account type, ...).
#
#  Read-only: the script never writes to the directory. It prints the commands
#  for you to run yourself.
#
#  Usage
#    .\ADPU-Analyzer.ps1                              run it; pick a domain when asked
#    .\ADPU-Analyzer.ps1 -Domain corp.example.net
#    .\ADPU-Analyzer.ps1 -Domain corp.example.net -Credential (Get-Credential)
#    .\ADPU-Analyzer.ps1 -HtmlPath .\report.html -JsonPath .\report.json
#    .\ADPU-Analyzer.ps1 -Scope Extended               widen the privileged set
#    .\ADPU-Analyzer.ps1 -Days 30                      widen the log window
#    .\ADPU-Analyzer.ps1 -BreakGlass 'CORP\emergency'   keep an emergency admin out
#    .\ADPU-Analyzer.ps1 -Identity alice, 'CORP\bob'     check just these accounts
#    .\ADPU-Analyzer.ps1 -Verify -Days 7               after enrolling: read the
#                                                      Protected Users channels
#    .\ADPU-Analyzer.ps1 -NonInteractive -JsonPath .\r.json    for scheduled runs
#
#  Exit codes (only when run as a script, not when dot-sourced)
#    0  nothing blocked and the evidence was complete
#    1  at least one account is blocked
#    2  no blockers, but the evidence has gaps (auditing off, DC unreachable)
#    3  the run could not be completed
#
#  Requirements
#    * Windows PowerShell 5.1+ or PowerShell 7+
#    * run on, or with line of sight to, a domain controller (elevated on a DC)
#    * WinRM reachable on the controllers
#    * Logon, Kerberos Authentication Service and Credential Validation auditing
#
#  Made by Carbon/Nobrac

#requires -Version 5

[CmdletBinding()]
param(
    # One or more domains to review. Omit to choose interactively.
    [string[]]$Domain,

    # Which groups count as privileged. Core = Administrators, Domain Admins,
    # Enterprise Admins, Schema Admins. Extended adds the operator groups,
    # Group Policy Creator Owners, the Key Admins groups and DnsAdmins.
    [ValidateSet('Core', 'Extended')]
    [string]$Scope = 'Core',

    # Extra groups to fold in, by SID or by name (resolved per domain).
    [string[]]$IncludeGroup,

    # Drop privileged members whose own domain is not in scope. By default they
    # are listed - a foreign admin in your domain is worth knowing about - but
    # this leaves them out entirely.
    [switch]$StrictScope,

    # Emergency admin accounts to keep outside Protected Users on purpose, by
    # SID, sAMAccountName or DOMAIN\name. The built-in Administrator (RID 500)
    # is always treated this way.
    [string[]]$BreakGlass,

    # Review exactly these accounts instead of the privileged group set - by
    # SID, sAMAccountName, DOMAIN\name or UPN. A group name reviews its members.
    [string[]]$Identity,

    # How far back the log harvest reaches.
    [ValidateRange(1, 365)]
    [int]$Days = 7,

    # Credentials for the remote log reads. Omit to use the current session.
    [pscredential]$Credential,

    [string]$HtmlPath,
    [string]$JsonPath,

    # Skip the readiness review; read the Protected Users channels instead.
    [switch]$Verify,

    # Emit the scored result object to the pipeline.
    [switch]$PassThru,

    # Never prompt and never pause - for scheduled runs.
    [switch]$NonInteractive
)

Set-StrictMode -Off

#  ==========================================================================
#  >> User-interface helpers (all screen output and prompts)
#  ==========================================================================

# Set by Invoke-ADPUAnalyzer. When true every prompt and pause is skipped, so
# the script can run unattended without blocking on a Read-Host.
$script:ADPUNonInteractive = $false

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
    if ($script:ADPUNonInteractive) { return }
    Clear-ADPUInput
    Read-Host $Prompt | Out-Null
}

function Read-ADPUAnswer {
    # Free-form prompt. Returns the raw string the operator typed.
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0)] $Prompt)
    if ($script:ADPUNonInteractive) { return '' }
    Clear-ADPUInput
    Write-Host ('[Ask]'.PadRight(8) + " $Prompt") -ForegroundColor Magenta
    Read-Host '   >'
}

function Read-ADPUYesNo {
    # Loops until the operator gives a clean yes/no. Returns [bool].
    # A bare Enter takes the default (no, unless told otherwise) - re-asking on an
    # empty line just repeated the question for every Enter still in the buffer.
    # Unattended runs answer "no" - the caller must never depend on a yes.
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0)] [string]$Question, [bool]$Default = $false)
    if ($script:ADPUNonInteractive) { return $false }
    $hint = if ($Default) { '(Y/n)' } else { '(y/N)' }
    do {
        $reply = ([string](Read-ADPUAnswer "$Question $hint")).Trim().ToLowerInvariant()
        Write-Host ''
        if (-not $reply) { return $Default }
    } until ($reply -in @('y', 'yes', 'j', 'ja', 'n', 'no', 'nein'))
    return ($reply -in @('y', 'yes', 'j', 'ja'))
}

function Read-ADPUMultiChoice {
    # Numbered menu that allows several picks at once: comma/space separated
    # numbers (e.g. "1,3"), or 'a' for all. Returns the chosen item texts.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)] [string]$Prompt,
        [Parameter(Mandatory, Position = 1)] [string[]]$Items
    )
    if ($script:ADPUNonInteractive) { return $Items }
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

    $live = ($Host.Name -eq 'ConsoleHost') -and -not $script:ADPUNonInteractive
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
    $result = $null
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
        # Errors raised inside the side runspace are invisible otherwise - they do
        # not reach the caller's error stream. Surface them under -Verbose so a
        # silent empty result can be told apart from a genuine "nothing found".
        try {
            foreach ($err in $shell.Streams.Error) {
                Write-Verbose ("{0}: {1}" -f $Caption, $err.Exception.Message)
            }
        } catch { }
        $shell.Dispose()
    }

    # EndInvoke hands back a PSDataCollection, so a single returned value would
    # arrive as a one-element collection and every caller would have to unwrap it.
    if ($null -eq $result) { return }
    if ($result.Count -eq 1) { $result[0] } else { $result }
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
    if ($script:ADPUNonInteractive) { return }
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
#  >> Remote collector (everything we need from one controller, in one call)
#  ==========================================================================

# The three audit subcategories this tool depends on. Addressed by GUID, never by
# name: the names are localised, the GUIDs are not.
$script:ADPUAuditGuid = [ordered]@{
    # Logon/Logoff  > Logon                            -> 4624 (NTLM logon at the DC)
    Logon   = '{0CCE9215-69AE-11D9-BED3-505054503030}'
    # Account Logon > Kerberos Authentication Service   -> 4768 (etypes, account keys)
    KerbAS  = '{0CCE9242-69AE-11D9-BED3-505054503030}'
    # Account Logon > Credential Validation             -> 4776 (NTLM anywhere in the domain)
    CredVal = '{0CCE923F-69AE-11D9-BED3-505054503030}'
}

# Held as source text rather than as a scriptblock: a scriptblock is bound to the
# runspace that created it, and this one has to survive being handed to the
# spinner's side runspace before it is sent to the controllers.
$script:ADPUCollectorSource = @'
param($Days, $Guids, $TargetSids, $TargetNames)

$span  = [int64]$Days * 86400000
$notes = [System.Collections.Generic.List[string]]::new()

# ---------------------------------------------------------------- audit policy
# Three states, not two. "Off" and "could not be determined" used to collapse
# into the same answer, which meant a failed read looked exactly like a
# deliberately disabled subcategory - and the report then told you auditing was
# off when in truth it had no idea.
#
# `auditpol /backup` is the only variant that carries the numeric setting
# (0 none, 1 success, 2 failure, 3 both); the "Inclusion Setting" text is
# localised and the column layout is NOT stable - the backup CSV has seven
# columns, other builds and `/get /r` emit five, without Machine Name and
# Exclusion Setting. Parsing by position therefore reads the setting out of the
# wrong column on some hosts and silently yields "off" everywhere. So: find the
# GUID column by its own shape, and take the setting as the last bare 0-3 field
# after it. Nothing depends on the header, the language or the column count.

function Split-CsvLine {
    param([string]$Line)
    $out  = [System.Collections.Generic.List[string]]::new()
    $buf  = [System.Text.StringBuilder]::new()
    $inQ  = $false
    for ($i = 0; $i -lt $Line.Length; $i++) {
        $c = $Line[$i]
        if ($inQ) {
            if ($c -eq '"') {
                if (($i + 1) -lt $Line.Length -and $Line[$i + 1] -eq '"') { [void]$buf.Append('"'); $i++ }
                else { $inQ = $false }
            } else { [void]$buf.Append($c) }
        } else {
            if     ($c -eq '"') { $inQ = $true }
            elseif ($c -eq ',') { $out.Add($buf.ToString().Trim()); [void]$buf.Clear() }
            else   { [void]$buf.Append($c) }
        }
    }
    $out.Add($buf.ToString().Trim())
    ,$out
}

function ConvertFrom-AuditCsv {
    # bare lowercase GUID -> @{ Value = <int or $null>; Text = <inclusion setting> }
    param([string[]]$Lines)
    $map = @{}
    foreach ($line in @($Lines)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        # No @() here: Split-CsvLine hands back a List so the fields survive the
        # return, and wrapping it would collapse the whole line into one element.
        $f = Split-CsvLine $line

        $guid = $null
        $gi   = -1
        for ($i = 0; $i -lt $f.Count; $i++) {
            if ($f[$i] -match '^\{?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}?$') {
                $guid = $Matches[1].ToLowerInvariant()
                $gi   = $i
                break
            }
        }
        if (-not $guid) { continue }      # header row, blank line, section marker

        $val = $null
        for ($i = $f.Count - 1; $i -gt $gi; $i--) {
            if ($f[$i] -match '^[0-3]$') { $val = [int]$f[$i]; break }
        }
        $text = if (($gi + 1) -lt $f.Count) { $f[$gi + 1] } else { '' }
        $map[$guid] = @{ Value = $val; Text = $text }
    }
    $map
}

function Resolve-AuditText {
    # Only reached when no numeric column existed. The inclusion setting is
    # localised, so this covers the handful of languages worth covering and
    # returns $null - "unknown" - for everything else rather than guessing "off".
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $t = $Text.Trim()
    # "no auditing" spellings first: several of them contain a success word.
    if ($t -match '^(No Auditing|Keine Überwachung|Nicht überwacht|Aucun audit|Sin auditoría|Nessun controllo|Geen controle)$') { return 0 }
    if ($t -match '(Success|Erfolg|Réussite|Succès|Correcto|Éxito|Riuscito|Successo|Geslaagd)') { return 1 }
    if ($t -match '(Failure|Fehler|Échec|Error|Errore|Mislukt)') { return 2 }
    $null
}

$auditMethod = 'none'
$backupRows  = @{}

# C:\Windows\Temp rather than the profile temp: a user profile path can contain
# a space, and auditpol does not survive the quoting that produces.
$tmpDir = Join-Path $env:SystemRoot 'Temp'
if (-not (Test-Path -LiteralPath $tmpDir)) { $tmpDir = $env:TEMP }
$tmp = Join-Path $tmpDir ("adpu-audit-{0}.csv" -f [guid]::NewGuid())
try {
    $null = auditpol /backup /file:$tmp
    if (Test-Path -LiteralPath $tmp) {
        $backupRows = ConvertFrom-AuditCsv -Lines (Get-Content -LiteralPath $tmp)
        if ($backupRows.Count) { $auditMethod = 'auditpol /backup' }
    }
} catch {
    $notes.Add("auditpol /backup failed: $($_.Exception.Message)")
} finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
}

# Fallback: query each subcategory on its own. Same parser, because /get /r is
# the same shape minus a column or two.
if (-not $backupRows.Count) {
    $notes.Add('auditpol /backup produced nothing - falling back to per-subcategory queries')
    foreach ($k in @($Guids.Keys)) {
        try {
            $lines = @(auditpol /get /subcategory:"$($Guids[$k])" /r 2>$null)
            foreach ($kv in (ConvertFrom-AuditCsv -Lines $lines).GetEnumerator()) { $backupRows[$kv.Key] = $kv.Value }
            if ($backupRows.Count) { $auditMethod = 'auditpol /get /r' }
        } catch { }
    }
}

$aud = @{}
foreach ($k in @($Guids.Keys)) {
    $bare = ([string]$Guids[$k]).Trim('{','}').ToLowerInvariant()
    $row  = if ($backupRows.ContainsKey($bare)) { $backupRows[$bare] } else { $null }

    $value = $null
    $text  = $null
    if ($row) {
        $text  = [string]$row.Text
        $value = $row.Value
        if ($null -eq $value) { $value = Resolve-AuditText $text }
    }

    # On   = successes are recorded (4624/4768/4776 are success events, so
    #        failure-only auditing is not enough)
    # Off  = read successfully, and it is not recording successes
    # Unknown = the subcategory was not found, or its setting could not be read
    $state = if ($null -eq $value) { 'Unknown' } elseif ((([int]$value) -band 1) -eq 1) { 'On' } else { 'Off' }

    $aud[$k] = @{
        State = $state
        Value = $value
        Text  = $(if ($text) { $text } elseif ($state -eq 'Unknown') { '(not reported)' } else { $text })
    }
}

if (-not (@($aud.Values | Where-Object { $_.State -ne 'Unknown' }).Count)) {
    $notes.Add('the audit policy could not be read at all - check that the account has rights to run auditpol on this controller. "Unknown" is reported, not "off".')
}

# Only a confirmed "On" licenses a harvest. Unknown is treated like off for the
# purpose of collecting evidence, but it is reported as unknown.
$onLogon   = ($aud.Logon.State   -eq 'On')
$onKerb    = ($aud.KerbAS.State  -eq 'On')
$onCredVal = ($aud.CredVal.State -eq 'On')

# ------------------------------------------------------------- event log reader
# One XML parse per (EventID, Version) instead of one per event: the Data elements
# always arrive in the same order for a given schema version, so the name->index
# map is built once and every later event is read positionally. On a busy
# controller that is the difference between minutes and seconds.
$fieldMaps = @{}

function Get-FieldMap {
    # $Cache is passed in rather than reached for: which scope $script: resolves
    # to inside a remote runspace is not worth betting the harvest on.
    param($Record, [hashtable]$Spec, [hashtable]$Cache)
    # The property count is part of the key: the January 2025 update added
    # fields to 4768 without it being safe to assume the schema version moved,
    # and a map built for the short layout would read the long one wrongly.
    $count = 0
    try { $count = @($Record.Properties).Count } catch { }
    $key = '{0}/{1}/{2}' -f $Record.Id, $Record.Version, $count
    if ($Cache.ContainsKey($key)) { return $Cache[$key] }

    $names = @()
    try {
        $xml = [xml]$Record.ToXml()
        foreach ($d in @($xml.Event.EventData.Data)) { $names += [string]$d.GetAttribute('Name') }
    } catch { }
    # A record that could not be parsed must not poison the cache for every
    # later event of the same shape - hand back an empty map, uncached.
    if (-not $names.Count) { return @{} }

    # Resolve each logical field to the FIRST matching element. Order matters:
    # 4768 repeats MSDS-SupportedEncryptionTypes and Available Keys for the
    # account, the service and the controller, and the account comes first.
    $map = @{}
    foreach ($logical in $Spec.Keys) {
        for ($i = 0; $i -lt $names.Count; $i++) {
            if ($names[$i] -and $names[$i] -match $Spec[$logical]) { $map[$logical] = $i; break }
        }
    }
    $Cache[$key] = $map
    $map
}

function Get-EventRows {
    param(
        [string]$Log,
        [string]$Xpath,
        [hashtable]$Spec,
        [hashtable]$Cache,
        [int]$Max = 500000,
        # Filled in for the caller: Truncated when the $Max cap was hit, ReadError
        # when the reader failed part-way. Either one means the rows are
        # incomplete, and the caller must not treat the source as fully read.
        [hashtable]$Status = @{}
    )
    $Status.Truncated = $false
    $Status.ReadError = $null
    $out = [System.Collections.Generic.List[hashtable]]::new()
    $reader = $null
    try {
        $q = [Diagnostics.Eventing.Reader.EventLogQuery]::new($Log, 'LogName', $Xpath)
        $q.TolerateQueryErrors = $true
        $reader = [Diagnostics.Eventing.Reader.EventLogReader]::new($q)
    } catch {
        throw ("cannot query {0}: {1}" -f $Log, $_.Exception.Message)
    }

    try {
        $seen = 0
        while ($null -ne ($e = $reader.ReadEvent())) {
            try {
                $map = Get-FieldMap -Record $e -Spec $Spec -Cache $Cache
                # Mapped lists the logical fields this event's schema actually
                # carries - "absent from the schema" and "present but empty" are
                # different answers, and the 4768 logic depends on telling them apart.
                $row = @{ Time = $e.TimeCreated; Id = [int]$e.Id; Version = [int]$e.Version; Mapped = @($map.Keys) }
                foreach ($logical in $Spec.Keys) {
                    $row[$logical] = if ($map.ContainsKey($logical)) {
                        [string]$e.Properties[$map[$logical]].Value
                    } else { $null }
                }
                $out.Add($row)
            } catch { }
            $e.Dispose()
            $seen++
            if ($seen -ge $Max) {
                # Only truncated if there really was more to read.
                $next = $null
                try { $next = $reader.ReadEvent() } catch { }
                if ($null -ne $next) { $Status.Truncated = $true; $next.Dispose() }
                break
            }
        }
    } catch {
        # Keep what we already have, but say that it is not everything: a silent
        # stop here used to look exactly like a complete, clean harvest.
        $Status.ReadError = $_.Exception.Message
    } finally {
        try { $reader.Dispose() } catch { }
    }
    ,$out
}

# ------------------------------------------------------------------- XPath bits
function Split-Chunk {
    # A list of string[] rather than an array of arrays: PowerShell unrolls one
    # level on output, so returning nested arrays would flatten every chunk back
    # into one long list and the XPath filters would be built wrong.
    param([string[]]$Items, [int]$Size = 20)
    $list = [System.Collections.Generic.List[object]]::new()
    $all  = @($Items | Where-Object { $_ })
    for ($i = 0; $i -lt $all.Count; $i += $Size) {
        $end = [Math]::Min($i + $Size - 1, $all.Count - 1)
        $list.Add([string[]]@($all[$i..$end]))
    }
    ,$list
}

function New-OrClause {
    param([string]$Field, [string[]]$Values)
    (($Values | ForEach-Object { "Data[@Name='{0}']='{1}'" -f $Field, $_ }) -join ' or ')
}

# XPath string literals are delimited by single quotes and the Event XPath subset
# has no escape for one, so a name carrying an apostrophe cannot be filtered on.
# Drop it from the filter rather than build a broken query, and say so.
$safeNames = @($TargetNames | Where-Object { $_ -and ($_ -notmatch "'") })
$dropped   = @($TargetNames | Where-Object { $_ -and ($_ -match "'") })
if ($dropped.Count) {
    $notes.Add("$($dropped.Count) account name(s) contain an apostrophe and were left out of the 4776 filter")
}

# 4776 records the name the way the client sent it. Whether the Event XPath
# equality test ignores case is not something to bet coverage on, so the filter
# carries the stored spelling plus its lower- and upper-case forms. That covers
# "admin" / "ADMIN" / "Admin"; the results are folded to lower case afterwards.
$nameSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
foreach ($n in $safeNames) {
    [void]$nameSet.Add($n)
    [void]$nameSet.Add($n.ToLowerInvariant())
    [void]$nameSet.Add($n.ToUpperInvariant())
}
$filterNames = @($nameSet)

# Which sources were only partly read. A harvest that hit the row cap or lost
# its reader half-way has findings, but its "nothing found" is not trustworthy.
$partial = @{ Logon = $false; KerbAS = $false; CredVal = $false }

function Test-HarvestComplete {
    param([hashtable]$Status, [string]$What, [string]$Key, [hashtable]$Partial, $Notes)
    if ($Status.Truncated) {
        $Partial[$Key] = $true
        $Notes.Add("$What stopped at the row cap - the harvest is incomplete; narrow -Days or check the log volume")
    }
    if ($Status.ReadError) {
        $Partial[$Key] = $true
        $Notes.Add("$What stopped early ($($Status.ReadError)) - the harvest is incomplete")
    }
}

# ------------------------------------------------------------------- 4624: NTLM
# NTLM logon recorded *at this controller*. Compare the named field directly: the
# looser two-clause form could match a different field holding the same text.
$ntlm4624 = @{}
if ($onLogon) {
    $spec = @{ Sid = '^TargetUserSid$'; Name = '^TargetUserName$' }
    try {
        foreach ($chunk in (Split-Chunk $TargetSids)) {
            $x = "*[EventData[Data[@Name='AuthenticationPackageName']='NTLM'][{0}]]" -f (New-OrClause 'TargetUserSid' $chunk) +
                 "[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $span]]]"
            $st = @{}
            foreach ($r in (Get-EventRows -Log 'Security' -Xpath $x -Spec $spec -Cache $fieldMaps -Status $st)) {
                $sid = [string]$r.Sid
                if (-not $sid -or $sid -eq 'S-1-0-0') { continue }
                if ($ntlm4624.ContainsKey($sid)) {
                    $ntlm4624[$sid].Count++
                    if ($r.Time -gt $ntlm4624[$sid].Last) { $ntlm4624[$sid].Last = $r.Time }
                } else {
                    $ntlm4624[$sid] = @{ Sid = $sid; Account = [string]$r.Name; Count = 1; Last = $r.Time }
                }
            }
            Test-HarvestComplete -Status $st -What '4624 harvest' -Key 'Logon' -Partial $partial -Notes $notes
        }
    } catch {
        $onLogon = $false
        $aud.Logon.State = 'Unknown'
        $aud.Logon.Text  = "harvest failed: $($_.Exception.Message)"
        $notes.Add("4624 harvest failed: $($_.Exception.Message)")
    }
}

# ------------------------------------------------ 4624/4625: service and batch logons
# An account that logs on as a service (logon type 5) or a scheduled task
# (logon type 4) is a service account in practice, whatever its name. Protected
# Users gives it a 4-hour TGT that cannot be renewed, no delegation and no
# "do not store password" (S4U) tasks - Microsoft's guidance is to keep service
# accounts out of the group altogether.
#
# Only logons on the controllers themselves are visible here; a task on a member
# server logs its 4624 on that server. Successes need Logon success auditing;
# the failures (4625) need Logon *failure* auditing, which many domains have on
# even when success auditing is off - and a service or task that keeps failing
# is exactly the "old password still saved somewhere" case.
#
# 4625 usually carries the NULL SID for the target, so failures are matched by
# account name, like 4776.
$svcLogons = @{}
$logonFailOn = $false
if ($aud.Logon.State -ne 'Unknown') {
    $lv = $aud.Logon.Value
    $logonFailOn = ($null -ne $lv -and ((([int]$lv) -band 2) -eq 2))
    if ($null -eq $lv -and ([string]$aud.Logon.Text) -match '(Failure|Fehler|Échec|Errore|Mislukt)') { $logonFailOn = $true }
}
$svcTypes = "(Data[@Name='LogonType']='4' or Data[@Name='LogonType']='5')"

function Add-SvcLogon {
    param([hashtable]$Map, [string]$Key, [string]$Account, [string]$Sid, [int]$Type, [bool]$Ok, $Time, [string]$Process, [string]$Status)
    if (-not $Map.ContainsKey($Key)) {
        $Map[$Key] = @{
            Key = $Key; Account = $Account; Sid = $Sid
            Batch = 0; Service = 0; BatchFailed = 0; ServiceFailed = 0
            Processes = @(); FailedStatus = @{}; Last = $Time
        }
    }
    $h = $Map[$Key]
    if ($Sid -and -not $h.Sid) { $h.Sid = $Sid }
    if ($Type -eq 4) { if ($Ok) { $h.Batch++ } else { $h.BatchFailed++ } }
    else             { if ($Ok) { $h.Service++ } else { $h.ServiceFailed++ } }
    if ($Time -gt $h.Last) { $h.Last = $Time }
    if ($Process -and $Process -ne '-' -and $h.Processes -notcontains $Process -and $h.Processes.Count -lt 5) { $h.Processes += $Process }
    if (-not $Ok) {
        $code = ([string]$Status).Trim()
        if ($code -match '^0x([0-9a-fA-F]+)$') { $code = '0x' + $Matches[1].ToUpperInvariant() }
        if (-not $code) { $code = 'unknown' }
        if ($h.FailedStatus.ContainsKey($code)) { $h.FailedStatus[$code]++ } else { $h.FailedStatus[$code] = 1 }
    }
}

if ($onLogon) {
    $spec = @{ Sid = '^TargetUserSid$'; Name = '^TargetUserName$'; Type = '^LogonType$'; Process = '^ProcessName$' }
    try {
        foreach ($chunk in (Split-Chunk $TargetSids)) {
            $x = "*[EventData[$svcTypes][{0}]]" -f (New-OrClause 'TargetUserSid' $chunk) +
                 "[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $span]]]"
            $st = @{}
            foreach ($r in (Get-EventRows -Log 'Security' -Xpath $x -Spec $spec -Cache $fieldMaps -Status $st)) {
                $nm = [string]$r.Name
                if (-not $nm) { continue }
                Add-SvcLogon -Map $svcLogons -Key $nm.ToLowerInvariant() -Account $nm -Sid ([string]$r.Sid) `
                             -Type ([int]$r.Type) -Ok $true -Time $r.Time -Process ([string]$r.Process)
            }
            Test-HarvestComplete -Status $st -What '4624 service/batch harvest' -Key 'Logon' -Partial $partial -Notes $notes
        }
    } catch {
        $notes.Add("4624 service/batch harvest failed: $($_.Exception.Message)")
    }
}
if ($logonFailOn) {
    $spec = @{ Name = '^TargetUserName$'; Type = '^LogonType$'; Process = '^ProcessName$'; Status = '^Status$'; Sub = '^SubStatus$' }
    try {
        foreach ($chunk in (Split-Chunk $filterNames)) {
            $x = "*[EventData[$svcTypes][{0}]]" -f (New-OrClause 'TargetUserName' $chunk) +
                 "[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= $span]]]"
            $st = @{}
            foreach ($r in (Get-EventRows -Log 'Security' -Xpath $x -Spec $spec -Cache $fieldMaps -Status $st)) {
                $nm = [string]$r.Name
                if (-not $nm) { continue }
                # The sub-status carries the specific reason (wrong password,
                # locked out, ...); the status is often just "logon failure".
                $why = if ([string]$r.Sub -match '^0x0*[1-9a-fA-F]') { [string]$r.Sub } else { [string]$r.Status }
                Add-SvcLogon -Map $svcLogons -Key $nm.ToLowerInvariant() -Account $nm -Sid $null `
                             -Type ([int]$r.Type) -Ok $false -Time $r.Time -Process ([string]$r.Process) -Status $why
            }
            Test-HarvestComplete -Status $st -What '4625 service/batch harvest' -Key 'Logon' -Partial $partial -Notes $notes
        }
    } catch {
        $notes.Add("4625 service/batch harvest failed: $($_.Exception.Message)")
    }
}

# ------------------------------------------------------------------- 4776: NTLM
# The one that matters most. 4624 only sees NTLM aimed at the controller itself;
# NTLM against a member server or workstation reaches the controller as 4776
# instead. 4776 carries no SID, only the bare account name - which is unique
# inside a domain, so the caller matches it per domain.
#
# Successes and failures are counted apart, and failures keep their status code.
# A success proves a working NTLM dependency. Failures from the same machines
# over and over usually mean something is still configured to sign this account
# in over NTLM with an old password - the day someone fixes that password, it
# needs NTLM and breaks under Protected Users. The scorer blocks on both; only a
# failure for a name that does not exist on this controller is let through.
$ntlm4776 = @{}
if ($onCredVal) {
    $spec = @{ Name = '^TargetUserName$'; Status = '^Status$'; Workstation = '^Workstation$' }
    try {
        foreach ($chunk in (Split-Chunk $filterNames)) {
            $x = "*[EventData[{0}]]" -f (New-OrClause 'TargetUserName' $chunk) +
                 "[System[(EventID=4776) and TimeCreated[timediff(@SystemTime) <= $span]]]"
            $st = @{}
            foreach ($r in (Get-EventRows -Log 'Security' -Xpath $x -Spec $spec -Cache $fieldMaps -Status $st)) {
                $nm = ([string]$r.Name)
                if (-not $nm) { continue }
                $key = $nm.ToLowerInvariant()
                $ok  = (([string]$r.Status) -match '^0x0+$')
                $w   = [string]$r.Workstation
                if (-not $ntlm4776.ContainsKey($key)) {
                    $ntlm4776[$key] = @{
                        Account       = $nm
                        Count         = 0
                        Succeeded     = 0
                        Failed        = 0
                        Last          = $r.Time
                        Sources       = @()
                        FailedSources = @()
                        # NTSTATUS -> count, for the failures only. Tells a stale
                        # saved password (wrong password, locked out) apart from a
                        # name that simply does not exist here (no such user).
                        FailedStatus  = @{}
                    }
                }
                $h = $ntlm4776[$key]
                $h.Count++
                if ($r.Time -gt $h.Last) { $h.Last = $r.Time }
                if ($ok) {
                    $h.Succeeded++
                    if ($w -and $h.Sources -notcontains $w -and $h.Sources.Count -lt 8) { $h.Sources += $w }
                } else {
                    $h.Failed++
                    if ($w -and $h.FailedSources -notcontains $w -and $h.FailedSources.Count -lt 8) { $h.FailedSources += $w }
                    $code = ([string]$r.Status).Trim()
                    if ($code -match '^0x([0-9a-fA-F]+)$') { $code = '0x' + $Matches[1].ToUpperInvariant() }
                    if (-not $code) { $code = 'unknown' }
                    if ($h.FailedStatus.ContainsKey($code)) { $h.FailedStatus[$code]++ } else { $h.FailedStatus[$code] = 1 }
                }
            }
            Test-HarvestComplete -Status $st -What '4776 harvest' -Key 'CredVal' -Partial $partial -Notes $notes
        }
    } catch {
        $onCredVal = $false
        $aud.CredVal.State = 'Unknown'
        $aud.CredVal.Text  = "harvest failed: $($_.Exception.Message)"
        $notes.Add("4776 harvest failed: $($_.Exception.Message)")
    }
}

# ---------------------------------------------------- 4768: etypes and AES keys
# Which fields mean what:
#   * TicketEncryptionType is the encryption of the TGT itself. The KDC picks it
#     from the *krbtgt* account's keys, so it says nothing about the account that
#     asked - on any build.
#   * SessionKeyEncryptionType (and the pre-auth type, where the build reports
#     one) is what the client and the KDC actually negotiated. That is the value
#     that tells us whether this account still uses DES/RC4.
#   * AccountAvailableKeys lists the long-term keys AD holds for the account -
#     direct proof that AES keys exist, rather than the password-age guess.
#   * ClientAdvertizedEncryptionTypes is what the requesting client offered.
# The newer fields exist on Server 2019+, or Server 2016 with the January 2025
# cumulative update. Whether an event has them is decided per event, from the
# fields its schema actually carries - not from a version number.
function Test-WeakEtype {
    # $null = no usable value, $false = AES, $true = anything weaker.
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim()
    if ($v -match '^-$' -or $v -match '^0x[fF]+$') { return $null }       # sentinel on failures
    if ($v -match '^0x0*1[12]$' -or $v -match '^(17|18)$') { return $false } # AES128 / AES256
    if ($v -match 'AES') { return $false }
    $true
}

function Test-AesMask {
    # Reads a key list or an etype list: hex mask or text. $null when empty.
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim()
    if ($v -match '^-?$') { return $null }
    if ($v -match '^0x[0-9a-fA-F]+$') { return ((([Convert]::ToInt64($v, 16)) -band 0x18) -ne 0) }
    ($v -match 'AES')
}

# The schema, straight from the provider manifest: this answers "does this
# controller report the new fields" even when none of our accounts happened to
# request a TGT during the window.
$schemaNew = $null
try {
    $meta = [Diagnostics.Eventing.Reader.ProviderMetadata]::new('Microsoft-Windows-Security-Auditing')
    $tpl  = @($meta.Events | Where-Object { $_.Id -eq 4768 } | ForEach-Object { [string]$_.Template })
    if ($tpl.Count) { $schemaNew = [bool](@($tpl | Where-Object { $_ -match 'AccountAvailableKeys|SessionKeyEncryptionType' }).Count) }
} catch { }

$kerb        = @{}
$maxVer      = -1
$observedNew = $false
if ($onKerb) {
    $spec = @{
        Sid        = '^TargetSid$'
        Name       = '^TargetUserName$'
        Ticket     = '^TicketEncryptionType$'
        Session    = '^SessionKeyEncryptionType$'
        PreAuth    = '^PreAuthEncryptionType$'
        Keys       = '^AccountAvailableKeys$'
        Etypes     = '^AccountSupportedEncryptionTypes$'
        Advertized = '^ClientAdvertizedEncryptionTypes$'
        Client     = '^IpAddress$'
        Status     = '^Status$'
    }
    try {
        foreach ($chunk in (Split-Chunk $TargetSids)) {
            $x = "*[EventData[{0}]]" -f (New-OrClause 'TargetSid' $chunk) +
                 "[System[(EventID=4768) and TimeCreated[timediff(@SystemTime) <= $span]]]"
            $st = @{}
            foreach ($r in (Get-EventRows -Log 'Security' -Xpath $x -Spec $spec -Cache $fieldMaps -Status $st)) {
                $sid = [string]$r.Sid
                if (-not $sid -or $sid -eq 'S-1-0-0') { continue }
                if ([int]$r.Version -gt $maxVer) { $maxVer = [int]$r.Version }

                $mapped = @($r.Mapped)
                $isNew  = ($mapped -contains 'Session') -or ($mapped -contains 'Keys')
                if ($isNew) { $observedNew = $true }

                # A failed AS-REQ carries no usable etype - it says nothing about
                # what the account can do, so it is not evidence either way.
                $failed = (([string]$r.Status) -and ([string]$r.Status) -notmatch '^0x0+$')

                $weakNew    = $false
                $weakLegacy = $false
                if (-not $failed) {
                    if ($isNew) {
                        foreach ($v in @([string]$r.Session, [string]$r.PreAuth)) {
                            if ((Test-WeakEtype $v) -eq $true) { $weakNew = $true }
                        }
                    } else {
                        # Legacy layout: the ticket type is all there is. It is the
                        # krbtgt's choice, so the scorer discards it whenever krbtgt
                        # is known to permit no AES.
                        if ((Test-WeakEtype ([string]$r.Ticket)) -eq $true) { $weakLegacy = $true }
                    }
                }

                $keys   = if ($isNew) { [string]$r.Keys } else { $null }
                $hasAes = Test-AesMask $keys
                $adv    = if ($isNew -and -not $failed) { Test-AesMask ([string]$r.Advertized) } else { $null }
                $client = ([string]$r.Client) -replace '^::ffff:', ''

                if (-not $kerb.ContainsKey($sid)) {
                    $kerb[$sid] = @{
                        Sid          = $sid
                        Account      = [string]$r.Name
                        Count        = 0
                        NewEvents    = 0
                        Weak         = 0
                        WeakNew      = 0
                        WeakLegacy   = 0
                        HasAes       = $false
                        KeysSeen     = $false
                        Keys         = $null
                        Etypes       = [string]$r.Etypes
                        NoAesAdv     = 0
                        AdvSources   = @()
                        Last         = $r.Time
                    }
                }
                $k = $kerb[$sid]
                $k.Count++
                if ($isNew)      { $k.NewEvents++ }
                if ($weakNew)    { $k.WeakNew++;    $k.Weak++ }
                if ($weakLegacy) { $k.WeakLegacy++; $k.Weak++ }
                if ($null -ne $hasAes) { $k.HasAes = ($k.HasAes -or $hasAes); $k.KeysSeen = $true }
                if ($keys) { $k.Keys = $keys }
                if ($adv -eq $false) {
                    $k.NoAesAdv++
                    if ($client -and $client -ne '-' -and $k.AdvSources -notcontains $client -and $k.AdvSources.Count -lt 8) { $k.AdvSources += $client }
                }
                if ($r.Time -gt $k.Last) { $k.Last = $r.Time }
            }
            Test-HarvestComplete -Status $st -What '4768 harvest' -Key 'KerbAS' -Partial $partial -Notes $notes
        }
    } catch {
        $onKerb = $false
        $aud.KerbAS.State = 'Unknown'
        $aud.KerbAS.Text  = "harvest failed: $($_.Exception.Message)"
        $notes.Add("4768 harvest failed: $($_.Exception.Message)")
    }
}

# ------------------------------------------------- KDC RC4 deprecation warnings
# Free evidence: no audit subcategory has to be on for these. The KDC writes them
# to the System log when a request could only have been served with RC4.
$kdcRc4 = @{}
try {
    $ids = 201..209 | ForEach-Object { "EventID=$_" }
    $x = "*[System[Provider[@Name='Microsoft-Windows-Kerberos-Key-Distribution-Center']" +
         " and ({0}) and TimeCreated[timediff(@SystemTime) <= $span]]]" -f ($ids -join ' or ')
    foreach ($r in (Get-EventRows -Log 'System' -Xpath $x -Spec @{} -Cache $fieldMaps -Max 20000)) {
        $k = [string]$r.Id
        if ($kdcRc4.ContainsKey($k)) {
            $kdcRc4[$k].Count++
            if ($r.Time -gt $kdcRc4[$k].Last) { $kdcRc4[$k].Last = $r.Time }
        } else {
            $kdcRc4[$k] = @{ Id = [int]$r.Id; Count = 1; Last = $r.Time }
        }
    }
} catch {
    # channel or provider absent on older builds - not an error worth reporting
}

[pscustomobject]@{
    Computer      = $env:COMPUTERNAME
    AuditLogon    = $onLogon
    AuditLogonFail = $logonFailOn
    AuditKerb     = $onKerb
    AuditCredVal  = $onCredVal
    AuditMethod   = $auditMethod
    AuditState    = @{
        Logon   = $aud.Logon.State
        KerbAS  = $aud.KerbAS.State
        CredVal = $aud.CredVal.State
    }
    AuditRaw      = @{
        Logon   = $aud.Logon.Text
        KerbAS  = $aud.KerbAS.Text
        CredVal = $aud.CredVal.Text
    }
    AuditPartial  = $partial
    Ntlm4624      = @($ntlm4624.Values)
    SvcLogons     = @($svcLogons.Values)
    Ntlm4776      = @($ntlm4776.Values)
    KerbSeen      = @($kerb.Values)
    Kerb4768Ver   = $maxVer
    Kerb4768New   = [bool](($schemaNew -eq $true) -or $observedNew)
    KdcRc4        = @($kdcRc4.Values)
    Notes         = @($notes)
}
'@

function Get-ADPUControllerFacts {
    <#
        .SYNOPSIS
            Collects audit state and every log finding from all controllers in one
            fan-out call.
        .DESCRIPTION
            The old shape was four sequential round trips per controller (WinRM
            probe, audit policy, NTLM sweep, Kerberos sweep), each re-authenticating.
            This is a single Invoke-Command against the whole list, which WinRM
            runs in parallel, with an open timeout so one wedged controller cannot
            stall the review. Controllers that never answered come back in .Failed.
        .OUTPUTS
            A hashtable of controller name -> facts, plus a .Failed hashtable of
            controller name -> error text, wrapped in one object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string[]]$Computer,
        [int]$Days = 7,
        [pscredential]$Credential,
        [string[]]$TargetSid,
        [string[]]$TargetName,
        [int]$ThrottleLimit = 16
    )

    # A plain hashtable survives remoting serialisation more predictably than an
    # ordered dictionary does.
    $guids = @{}
    foreach ($k in $script:ADPUAuditGuid.Keys) { $guids[$k] = $script:ADPUAuditGuid[$k] }

    # The operation timeout grows with the window: a year of Security log on a
    # busy controller can take far longer than a week, and a timeout would show
    # up as "unreachable" rather than "slow". 15 minutes floor, one hour ceiling.
    $opTimeout = [int][Math]::Min(3600000, 900000 + ([int64]$Days * 10000))
    $option = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout $opTimeout -CancelTimeout 5000

    $work = {
        param($names, $src, $days, $guids, $sids, $accounts, $cred, $option, $throttle)

        $splat = @{
            ComputerName  = $names
            ScriptBlock   = [scriptblock]::Create($src)
            ArgumentList  = @($days, $guids, $sids, $accounts)
            ThrottleLimit = $throttle
            SessionOption = $option
            ErrorAction   = 'SilentlyContinue'
        }
        if ($cred) { $splat.Credential = $cred }

        $problems = $null
        $results  = Invoke-Command @splat -ErrorVariable problems

        [pscustomobject]@{
            Results = @($results)
            Errors  = @($problems | ForEach-Object {
                $who = [string]$_.TargetObject
                if (-not $who -and $_.OriginInfo) { $who = [string]$_.OriginInfo.PSComputerName }
                [pscustomobject]@{ Computer = $who; Message = $_.Exception.Message }
            })
        }
    }

    $caption = "Reading audit policy and logs on $(@($Computer).Count) controller(s)"
    $raw = Start-ADPUActivity $caption -Work $work -With @(
        [string[]]$Computer, $script:ADPUCollectorSource, [int]$Days, $guids,
        [string[]]$TargetSid, [string[]]$TargetName, $Credential, $option, [int]$ThrottleLimit
    )

    $byName = @{}
    $failed = @{}
    foreach ($r in @($raw.Results)) {
        $name = [string]$r.PSComputerName
        if (-not $name) { $name = [string]$r.Computer }
        if ($name) { $byName[$name] = $r }
    }
    foreach ($e in @($raw.Errors)) {
        if ($e.Computer -and -not $byName.ContainsKey($e.Computer)) { $failed[$e.Computer] = $e.Message }
    }
    # Anything we asked for and never heard back from is a blind spot too, even if
    # WinRM did not raise a matching error record.
    foreach ($c in $Computer) {
        if (-not $byName.ContainsKey($c) -and -not $failed.ContainsKey($c)) {
            $failed[$c] = 'no response'
        }
    }

    [pscustomobject]@{ Facts = $byName; Failed = $failed }
}

#  ==========================================================================
#  >> Active Directory helpers (SIDs, groups, controllers)
#  ==========================================================================

Add-Type -AssemblyName 'System.DirectoryServices.AccountManagement' -ErrorAction SilentlyContinue

# Which groups count as privileged. RID entries are resolved against the domain
# (or the forest root, for Level = Forest); Sid entries are the fixed builtin
# domain-local groups; Name entries are looked up by name because they have no
# well-known RID.
$script:ADPUGroupCatalog = @(
    [pscustomobject]@{ Label = 'Administrators';              Sid = 'S-1-5-32-544'; Rid = $null; Name = $null;        Tier = 'Core';     Level = 'Domain' }
    [pscustomobject]@{ Label = 'Domain Admins';               Sid = $null;          Rid = 512;   Name = $null;        Tier = 'Core';     Level = 'Domain' }
    [pscustomobject]@{ Label = 'Enterprise Admins';           Sid = $null;          Rid = 519;   Name = $null;        Tier = 'Core';     Level = 'Forest' }
    [pscustomobject]@{ Label = 'Schema Admins';               Sid = $null;          Rid = 518;   Name = $null;        Tier = 'Core';     Level = 'Forest' }
    [pscustomobject]@{ Label = 'Account Operators';           Sid = 'S-1-5-32-548'; Rid = $null; Name = $null;        Tier = 'Extended'; Level = 'Domain' }
    [pscustomobject]@{ Label = 'Server Operators';            Sid = 'S-1-5-32-549'; Rid = $null; Name = $null;        Tier = 'Extended'; Level = 'Domain' }
    [pscustomobject]@{ Label = 'Print Operators';             Sid = 'S-1-5-32-550'; Rid = $null; Name = $null;        Tier = 'Extended'; Level = 'Domain' }
    [pscustomobject]@{ Label = 'Backup Operators';            Sid = 'S-1-5-32-551'; Rid = $null; Name = $null;        Tier = 'Extended'; Level = 'Domain' }
    [pscustomobject]@{ Label = 'Group Policy Creator Owners'; Sid = $null;          Rid = 520;   Name = $null;        Tier = 'Extended'; Level = 'Domain' }
    [pscustomobject]@{ Label = 'Key Admins';                  Sid = $null;          Rid = 526;   Name = $null;        Tier = 'Extended'; Level = 'Domain' }
    [pscustomobject]@{ Label = 'Enterprise Key Admins';       Sid = $null;          Rid = 527;   Name = $null;        Tier = 'Extended'; Level = 'Forest' }
    [pscustomobject]@{ Label = 'DnsAdmins';                   Sid = $null;          Rid = $null; Name = 'DnsAdmins';  Tier = 'Extended'; Level = 'Domain' }
)

function Get-ADPUDirectoryContext {
    <#
        A DirectoryContext that carries -Credential when one was given. Every
        System.DirectoryServices.ActiveDirectory call (forest, domain, controller
        discovery) goes through here, so a run from a machine outside the domain
        uses the supplied account throughout rather than only for some of it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [DirectoryServices.ActiveDirectory.DirectoryContextType]$Type,
        [string]$Name,
        [pscredential]$Credential
    )
    if ($Credential) {
        $user = $Credential.UserName
        $pass = $Credential.GetNetworkCredential().Password
        if ($Name) { [DirectoryServices.ActiveDirectory.DirectoryContext]::new($Type, $Name, $user, $pass) }
        else       { [DirectoryServices.ActiveDirectory.DirectoryContext]::new($Type, $user, $pass) }
    } else {
        if ($Name) { [DirectoryServices.ActiveDirectory.DirectoryContext]::new($Type, $Name) }
        else       { [DirectoryServices.ActiveDirectory.DirectoryContext]::new($Type) }
    }
}

function Get-ADPUForest {
    <#
        Finds the forest to review. Without credentials that is simply the current
        forest. With credentials, it is reached through a named domain when one is
        known (works from a machine that is not joined at all), and otherwise
        through the machine's own forest, but bound with the supplied account.
    #>
    [CmdletBinding()]
    param([string[]]$DomainName, [pscredential]$Credential)

    if (-not $Credential) { return [DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest() }
    $first = @($DomainName | Where-Object { $_ }) | Select-Object -First 1
    if ($first) {
        $ctx = Get-ADPUDirectoryContext -Type Domain -Name $first -Credential $Credential
        return ([DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)).Forest
    }
    $ctx = Get-ADPUDirectoryContext -Type Forest -Credential $Credential
    [DirectoryServices.ActiveDirectory.Forest]::GetForest($ctx)
}

# One PrincipalContext per domain (and credential), reused for the whole run and
# disposed at the end. Building a fresh one for every lookup opened a new LDAP
# bind each time and never released any of them.
$script:ADPUContextCache = @{}

function Get-ADPUPrincipalContext {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$DomainName, [pscredential]$Credential)

    $key = '{0}|{1}' -f $DomainName.ToLowerInvariant(), $(if ($Credential) { $Credential.UserName } else { '' })
    if ($script:ADPUContextCache.ContainsKey($key)) { return $script:ADPUContextCache[$key] }

    $ctx = if ($Credential) {
        [DirectoryServices.AccountManagement.PrincipalContext]::new(
            'Domain', $DomainName, $Credential.UserName, $Credential.GetNetworkCredential().Password)
    } else {
        [DirectoryServices.AccountManagement.PrincipalContext]::new('Domain', $DomainName)
    }
    $script:ADPUContextCache[$key] = $ctx
    $ctx
}

function Clear-ADPUContextCache {
    # Called once the run is over - principals read through a context stay usable
    # only while it is open, so this must not happen any earlier.
    foreach ($ctx in @($script:ADPUContextCache.Values)) { try { $ctx.Dispose() } catch { } }
    $script:ADPUContextCache = @{}
}

function Get-ADPUDomainSid {
    <#
        Works out a domain's SID without needing RSAT: look up the domain's krbtgt
        account and take its account-domain SID. krbtgt always exists, so this is
        a reliable anchor. Goes through the (credentialled) principal context
        first; the NTAccount translation is only a fallback, because it always
        runs as the current user.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $DomainName, [pscredential]$Credential)

    try {
        $ctx  = Get-ADPUPrincipalContext -DomainName ([string]$DomainName) -Credential $Credential
        $user = [DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($ctx, 'krbtgt')
        if ($user -and $user.Sid -and $user.Sid.AccountDomainSid) { return $user.Sid.AccountDomainSid }
    } catch {
        if ($Credential) { throw }
    }

    $krbtgt = [Security.Principal.NTAccount]::new($DomainName, 'krbtgt').
                  Translate([Security.Principal.SecurityIdentifier]).Value
    [Security.Principal.SecurityIdentifier]::new($krbtgt.Substring(0, $krbtgt.Length - 4))
}

function Resolve-ADPUGroupIdentity {
    <#
        Turns a catalog entry into the identity to search for in a given domain.
        Returns $null when the entry does not apply here (a forest-level group in
        a child domain, say).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Entry,
        [Parameter(Mandatory)] $DomainSid,
        [Parameter(Mandatory)] [bool]$IsForestRoot
    )

    if ($Entry.Level -eq 'Forest' -and -not $IsForestRoot) { return $null }
    if ($Entry.Sid)  { return $Entry.Sid }
    if ($Entry.Rid)  { return ('{0}-{1}' -f $DomainSid, $Entry.Rid) }
    if ($Entry.Name) { return $Entry.Name }
    $null
}

function Expand-ADPUGroup {
    <#
        Returns the recursive membership of a group. $Identity is a SID string or a
        group name. Missing or unreachable groups yield a warning, not a throw, and
        the caller carries on with the groups it could read.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Identity,
        [Parameter(Mandatory)] [string]$DomainName,
        [pscredential]$Credential
    )

    try {
        $ctx   = Get-ADPUPrincipalContext -DomainName $DomainName -Credential $Credential
        $group = [DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($ctx, $Identity)
    } catch {
        # FindByIdentity contacts a controller - an unreachable domain throws here.
        Write-ADPULine warn "Could not look up group $Identity in $DomainName."
        return
    }

    if (-not $group) { return }   # absent group is normal (DnsAdmins, Key Admins on old domains)

    try {
        $group.GetMembers($true)
    } catch {
        Write-ADPULine warn "Could not read all members of $Identity in $DomainName - the list may be incomplete."
    }
}

function Get-ADPUPugTimestamp {
    <#
        Reads the whenCreated stamp of a domain's Protected Users group. Returns
        $null if the group is not present.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$DomainName,
        [Parameter(Mandatory)] $PugSid,
        [pscredential]$Credential
    )

    try {
        $ctx   = Get-ADPUPrincipalContext -DomainName $DomainName -Credential $Credential
        $group = [DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($ctx, [string]$PugSid)
        if ($group) { $group.GetUnderlyingObject().Properties['whenCreated'].Value }
    } catch { $null }
}

function Test-ADPUPugPresent {
    # True when the Protected Users group both exists and can be enumerated.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$DomainName,
        [Parameter(Mandatory)] $PugSid,
        [pscredential]$Credential
    )

    try {
        $ctx   = Get-ADPUPrincipalContext -DomainName $DomainName -Credential $Credential
        $group = [DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($ctx, [string]$PugSid)
        if (-not $group) { return $false }
        $null = $group.GetMembers()
        $true
    } catch {
        $false
    }
}

function Get-ADPUKrbtgtHealth {
    <#
        .SYNOPSIS
            Checks whether the domain's krbtgt account has AES keys.
        .DESCRIPTION
            Worth one lookup per domain, because it changes how the DES/RC4 findings
            must be read. The Ticket Encryption Type in event 4768 is the encryption
            of the TGT itself, which the KDC picks from the krbtgt account's keys -
            so a krbtgt without AES makes *every* account in the domain look like an
            RC4 user wherever that field is all there is. That is a domain problem
            to fix once, not a blocker on each individual account.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$DomainName,
        [Parameter(Mandatory)] $DomainSid,
        [pscredential]$Credential
    )

    $out = [pscustomobject]@{
        Readable   = $false
        EncTypes   = $null
        Explicit   = $false
        HasAes     = $null
        PwdLastSet = $null
    }
    try {
        $ctx  = Get-ADPUPrincipalContext -DomainName $DomainName -Credential $Credential
        $user = [DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($ctx, ('{0}-502' -f $DomainSid))
        if (-not $user) { return $out }
        $out.Readable   = $true
        $out.PwdLastSet = $user.LastPasswordSet
        $de  = $user.GetUnderlyingObject()
        $raw = $de.Properties['msDS-SupportedEncryptionTypes'].Value

        # 0 and "absent" mean the same thing: nothing is configured, so the KDC
        # default applies - and that has included AES since the domain functional
        # level reached 2008. A healthy krbtgt almost never has this attribute
        # set, so treating 0 as "no AES keys" fired a false alarm in practically
        # every environment. Only an explicit, non-zero mask without an AES bit
        # is evidence of a problem.
        if ($null -ne $raw) { $out.EncTypes = [int]$raw }
        if ($null -ne $raw -and [int]$raw -ne 0) {
            $out.Explicit = $true
            $out.HasAes   = (([int]$raw -band 0x18) -ne 0)
        } else {
            $out.HasAes = $null      # unknown, not bad
        }
    } catch { }
    $out
}

#  ==========================================================================
#  >> Environment sweep (build the annotated topology)
#  ==========================================================================

# Server builds new enough to honour Protected Users on a DC: 2012 R2 and up.
# A fixed list of SKU strings misses Core installs, Evaluation editions and names
# like "Windows Server 2022 Datacenter: Azure Edition", so match on the release
# instead. "Windows Server 2012 Standard" (no R2) is deliberately not matched.
$script:ADPUModernServerPattern = '^Windows Server (2012 R2|201[6-9]|20[2-9]\d)\b'

# Functional-level 6 == Server 2012 R2, the floor for the Protected Users group.
$script:ADPUFunctionalFloor = 6

# Below this many days of logs no account is rated "Proven", however clean: a
# weekly batch job or a monthly VPN sign-in can hide inside a shorter window.
$script:ADPUProvenMinDays = 14

function ConvertTo-ADPUAccount {
    <#
        .SYNOPSIS
            Flattens an AccountManagement principal into a plain fact object.
        .DESCRIPTION
            Everything downstream - scoring, the console report, the HTML and the
            JSON - works on these plain objects, so none of it has to touch a live
            directory binding and all of it can be exercised with synthetic data.

            The home domain is derived from the principal's own SID, not from the
            group that was being expanded. Builtin\Administrators is domain-local
            and can hold users from other domains in the forest; stamping those
            with the expanded domain used to point PugBornOn, NoPugHere and the
            -Server argument of the printed enrolment command at the wrong domain.
        .PARAMETER DomainMap
            Domain SID string -> domain object, used to place the account.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Principal,
        [Parameter(Mandatory)] [hashtable]$DomainMap,
        [string]$ViaGroup,
        [string]$ViaDomain
    )

    $sid    = $null
    $sidTxt = $null
    try { $sid = $Principal.Sid; $sidTxt = [string]$sid } catch { }

    $domSidTxt = $null
    try { if ($sid -and $sid.AccountDomainSid) { $domSidTxt = [string]$sid.AccountDomainSid } } catch { }

    $homeDom = if ($domSidTxt -and $DomainMap.ContainsKey($domSidTxt)) { $DomainMap[$domSidTxt] } else { $null }
    $foreign = ($null -eq $homeDom)

    # For a member that lives outside the reviewed scope, name the domain it
    # really comes from. Falling back to the domain whose group we happened to be
    # expanding was actively wrong: three same-named admins from three domains all
    # rendered as one domain's account, and - worse - each then matched that one
    # domain's name-keyed 4776 evidence.
    $domainName = if ($homeDom) {
        $homeDom.Name
    } else {
        $realm = $null
        # AccountManagement resolves a cross-domain member against its own home
        # context, so this is usually already correct.
        try { if ($Principal.Context -and $Principal.Context.Name) { $realm = [string]$Principal.Context.Name } } catch { }
        if (-not $realm) {
            try { $realm = (([string]$sid.Translate([Security.Principal.NTAccount]).Value) -split '\\')[0] } catch { }
        }
        if ($realm) { $realm } elseif ($domSidTxt) { "(unresolved domain $domSidTxt)" } else { '(unresolved domain)' }
    }

    $acct = [pscustomobject]@{
        Sid           = $sidTxt
        Sam           = [string]$Principal.SamAccountName
        Display       = [string]$Principal.Name
        Dn            = [string]$Principal.DistinguishedName
        Class         = [string]$Principal.StructuralObjectClass
        Domain        = $domainName
        DomainSid     = $domSidTxt
        Foreign       = $foreign
        FoundVia      = $ViaDomain
        PugBornOn     = if ($homeDom) { $homeDom.PugBornOn } else { $null }
        PugPresent    = if ($homeDom) { [bool]$homeDom.PugPresent } else { $false }
        ViaGroups     = @()
        PwdLastSet    = $null
        Enabled       = $null
        PwdNeverExp   = $false
        AdminCount    = $false
        Uac           = $null
        EncTypes      = $null
        Spns          = @()
        DelegateTo    = @()
        IsGmsa        = ([string]$Principal.StructuralObjectClass) -eq 'msDS-GroupManagedServiceAccount'
    }
    if ($ViaGroup) { $acct.ViaGroups = @($ViaGroup) }

    try { $acct.PwdLastSet  = $Principal.LastPasswordSet } catch { }
    try { $acct.Enabled     = $Principal.Enabled } catch { }
    try { $acct.PwdNeverExp = [bool]$Principal.PasswordNeverExpires } catch { }

    try {
        $de = $Principal.GetUnderlyingObject()
        # Constructed and rarely-cached attributes are not always in the property
        # cache after a FindByIdentity, so ask for them explicitly.
        try {
            $de.RefreshCache(@('adminCount','userAccountControl','msDS-SupportedEncryptionTypes',
                               'servicePrincipalName','msDS-AllowedToDelegateTo'))
        } catch { }

        try { $acct.AdminCount = ([int]($de.Properties['adminCount'].Value)) -eq 1 } catch { }
        try { $acct.Uac        = [int]($de.Properties['userAccountControl'].Value) } catch { }
        try {
            $raw = $de.Properties['msDS-SupportedEncryptionTypes'].Value
            if ($null -ne $raw) { $acct.EncTypes = [int]$raw }
        } catch { }
        try { $acct.Spns       = @($de.Properties['servicePrincipalName']       | Where-Object { $_ }) } catch { }
        try { $acct.DelegateTo = @($de.Properties['msDS-AllowedToDelegateTo']   | Where-Object { $_ }) } catch { }
    } catch { }

    $acct
}

function Find-ADPUIdentity {
    <#
        Resolves one -Identity value to directory principals in the reviewed
        domains. Accepts a SID, DOMAIN\name (NetBIOS or DNS domain), a UPN, or a
        bare sAMAccountName. A bare name that exists in several domains returns
        every match - they are different accounts, and each is reviewed. A group
        is expanded to its members, recursively.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Identity,
        [Parameter(Mandatory)] $Domains,
        [pscredential]$Credential
    )

    $sidTxt = $null
    if ($Identity -match '^S-1-5-21-') {
        $sidTxt = $Identity
    } elseif ($Identity -match '\\') {
        # NTAccount understands the NetBIOS form natively; only a fallback below
        # is needed when that translation is not possible from this machine.
        try { $sidTxt = ([Security.Principal.NTAccount]::new($Identity)).Translate([Security.Principal.SecurityIdentifier]).Value } catch { }
    }

    $found = [System.Collections.Generic.List[object]]::new()
    if ($sidTxt) {
        $sid = [Security.Principal.SecurityIdentifier]::new($sidTxt)
        $dom = @($Domains | Where-Object { $_.Sid -eq [string]$sid.AccountDomainSid }) | Select-Object -First 1
        if ($dom) {
            try {
                $ctx = Get-ADPUPrincipalContext -DomainName $dom.Name -Credential $Credential
                $p = [DirectoryServices.AccountManagement.Principal]::FindByIdentity(
                         $ctx, [DirectoryServices.AccountManagement.IdentityType]::Sid, $sidTxt)
                if ($p) { $found.Add($p) }
            } catch { }
        }
    } else {
        $prefix = $null
        $name   = $Identity
        if ($Identity -match '\\') { $prefix, $name = $Identity -split '\\', 2 }
        foreach ($d in @($Domains)) {
            if ($prefix -and -not ($d.Name -ieq $prefix -or ($d.Name -split '\.')[0] -ieq $prefix)) { continue }
            try {
                $ctx = Get-ADPUPrincipalContext -DomainName $d.Name -Credential $Credential
                $p = [DirectoryServices.AccountManagement.Principal]::FindByIdentity($ctx, $name)
                if ($p) { $found.Add($p) }
            } catch { }
        }
    }

    foreach ($p in $found) {
        if ($p -is [DirectoryServices.AccountManagement.GroupPrincipal]) {
            try { $p.GetMembers($true) } catch { Write-ADPULine warn "Could not read all members of $Identity - the list may be incomplete." }
        } else {
            $p
        }
    }
}

function Get-ADPUTopology {
    <#
        .SYNOPSIS
            Discovers and annotates the whole environment in a single sweep.
        .DESCRIPTION
            Returns one object holding the forest, its reachable domains, their
            controllers (with everything the log harvest found), the flattened
            privileged-account set and the current Protected Users membership.
        .PARAMETER DomainName
            Optional list of domain names to limit the review to.
        .PARAMETER Days
            How far back the log harvest reaches.
        .PARAMETER Scope
            Core or Extended - which groups count as privileged.
        .PARAMETER IncludeGroup
            Extra group SIDs or names to fold in, on top of the scope.
    #>
    [CmdletBinding()]
    param(
        [string[]]$DomainName,
        [int]$Days = 7,
        [ValidateSet('Core','Extended')] [string]$Scope = 'Core',
        [string[]]$IncludeGroup,
        [switch]$StrictScope,
        [pscredential]$Credential,
        # Review exactly these accounts (or group members) instead of the
        # privileged group set. They do not have to be admins.
        [string[]]$Identity
    )

    # -- forest -----------------------------------------------------------------
    Write-ADPULine note 'Mapping the forest...'
    $forest   = Get-ADPUForest -DomainName $DomainName -Credential $Credential
    $rootName = [string]$forest.RootDomain.Name

    # -- domains ----------------------------------------------------------------
    Write-ADPULine note 'Walking the domains...'
    $candidates = @($forest.Domains)
    if ($DomainName) {
        $known = @($candidates | ForEach-Object { [string]$_.Name })
        $unknown = @($DomainName | Where-Object { $n = $_; -not ($known | Where-Object { $_ -ieq $n }) })
        if ($unknown.Count) {
            throw ("Not a domain of forest {0}: {1}. Known domains: {2}" -f
                   $forest.Name, ($unknown -join ', '), ($known -join ', '))
        }
        $pick = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]$DomainName, [System.StringComparer]::OrdinalIgnoreCase)
        $candidates = @($candidates | Where-Object { $pick.Contains([string]$_.Name) })
        Write-ADPULine note ("Scope limited to: {0}" -f (($candidates | ForEach-Object { $_.Name }) -join ', '))
    }

    $domains = foreach ($d in $candidates) {
        # An unreachable domain does not return $null here - the property getter
        # throws, which used to abort the whole run instead of skipping the domain.
        try {
            $null = $d.Forest
            $sid  = Get-ADPUDomainSid -DomainName $d.Name -Credential $Credential
        } catch {
            Write-ADPULine warn "$($d.Name) is out of reach - leaving it out of the review."
            continue
        }

        $pugSid  = [Security.Principal.SecurityIdentifier]::new("$sid-525")
        $present = Test-ADPUPugPresent -DomainName $d.Name -PugSid $pugSid -Credential $Credential
        $bornOn  = if ($present) { Get-ADPUPugTimestamp -DomainName $d.Name -PugSid $pugSid -Credential $Credential } else { $null }

        [pscustomobject]@{
            Name       = [string]$d.Name
            Sid        = [string]$sid
            ModeLevel  = [int]$d.DomainModeLevel
            ReadyFL    = [bool]([int]$d.DomainModeLevel -ge $script:ADPUFunctionalFloor)
            IsRoot     = ([string]$d.Name -ieq $rootName)
            PugSid     = [string]$pugSid
            PugPresent = [bool]$present
            PugBornOn  = $bornOn
            Krbtgt     = (Get-ADPUKrbtgtHealth -DomainName $d.Name -DomainSid $sid -Credential $Credential)
        }
    }
    $domains = @($domains)
    if (-not $domains.Count) { throw 'No domain in scope could be reached.' }

    $domainMap = @{}
    foreach ($d in $domains) { $domainMap[$d.Sid] = $d }

    if (-not ($domains | Where-Object { $_.IsRoot })) {
        Write-ADPULine note 'Forest root is out of scope - Enterprise/Schema Admins are not reviewed.'
    }

    # -- privileged accounts ----------------------------------------------------
    $byKey = [ordered]@{}
    $wanted = @()
    $groupDomains = $domains
    $requested = @($Identity | Where-Object { $_ })
    if ($requested.Count) {
        # -Identity replaces the group sweep: the named accounts are reviewed
        # whether or not they are privileged.
        Write-ADPULine note ("Looking up {0} account(s) given with -Identity..." -f $requested.Count)
        $groupDomains = @()
        foreach ($id in $requested) {
            $hits = @(Find-ADPUIdentity -Identity $id -Domains $domains -Credential $Credential)
            if (-not $hits.Count) {
                Write-ADPULine warn "'$id' was not found in the domain(s) under review - skipped."
                continue
            }
            $homes = @($hits | ForEach-Object { try { [string]$_.Context.Name } catch { '' } } | Where-Object { $_ } | Select-Object -Unique)
            if ($homes.Count -gt 1) {
                Write-ADPULine note "'$id' exists in several domains ($($homes -join ', ')) - each one is reviewed."
            }
            foreach ($member in $hits) {
                $acct = ConvertTo-ADPUAccount -Principal $member -DomainMap $domainMap -ViaGroup '-Identity'
                $acct.FoundVia = $acct.Domain
                $key = if ($acct.Sid) { $acct.Sid } else { "$($acct.Domain)\$($acct.Sam)" }
                if (-not $byKey.Contains($key)) { $byKey[$key] = $acct }
            }
        }
        if (-not $byKey.Count) { throw 'None of the accounts given with -Identity were found in the domain(s) under review.' }
    } else {
        Write-ADPULine note "Collecting privileged accounts ($Scope scope)..."
        $wanted = @($script:ADPUGroupCatalog | Where-Object { $_.Tier -eq 'Core' -or $Scope -eq 'Extended' })
    }

    foreach ($d in $groupDomains) {
        $entries = foreach ($e in $wanted) {
            $id = Resolve-ADPUGroupIdentity -Entry $e -DomainSid $d.Sid -IsForestRoot $d.IsRoot
            if ($id) { [pscustomobject]@{ Label = $e.Label; Identity = $id } }
        }
        foreach ($extra in @($IncludeGroup | Where-Object { $_ })) {
            $entries = @($entries) + [pscustomobject]@{ Label = $extra; Identity = $extra }
        }

        foreach ($g in @($entries)) {
            foreach ($member in (Expand-ADPUGroup -Identity $g.Identity -DomainName $d.Name -Credential $Credential)) {
                $acct = ConvertTo-ADPUAccount -Principal $member -DomainMap $domainMap -ViaGroup $g.Label -ViaDomain $d.Name
                # Key on the SID: distinguished names differ in case and foreign
                # security principals carry a DN that is not the account's own.
                $key = if ($acct.Sid) { $acct.Sid } else { "$($acct.Domain)\$($acct.Sam)" }
                if ($byKey.Contains($key)) {
                    $seen = $byKey[$key]
                    if ($seen.ViaGroups -notcontains $g.Label) { $seen.ViaGroups = @($seen.ViaGroups) + $g.Label }
                } else {
                    $byKey[$key] = $acct
                }
            }
        }
    }
    $accounts = @($byKey.Values)

    # -StrictScope removes them here rather than at render time, so they also
    # stay out of the log filters, the counts, the JSON and the exit code.
    $excludedForeign = 0
    if ($StrictScope) {
        $excludedForeign = @($accounts | Where-Object { $_.Foreign }).Count
        $accounts = @($accounts | Where-Object { -not $_.Foreign })
    }

    Write-ADPULine note ("{0} distinct privileged account(s) found." -f $accounts.Count)
    if ($excludedForeign) {
        Write-ADPULine note ("{0} member(s) homed in an unreviewed domain left out (-StrictScope)." -f $excludedForeign)
    }

    # -- Protected Users roster -------------------------------------------------
    Write-ADPULine note 'Flattening the Protected Users roster...'
    $pugSids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($d in $domains) {
        if (-not $d.PugPresent) { continue }
        foreach ($m in (Expand-ADPUGroup -Identity $d.PugSid -DomainName $d.Name -Credential $Credential)) {
            try { if ($m.Sid) { [void]$pugSids.Add([string]$m.Sid) } } catch { }
        }
    }

    # -- controllers ------------------------------------------------------------
    Write-ADPULine note 'Reaching the controllers...'
    $controllers = foreach ($d in $domains) {
        try {
            $ctx    = Get-ADPUDirectoryContext -Type Domain -Name $d.Name -Credential $Credential
            $dcList = @([DirectoryServices.ActiveDirectory.DomainController]::FindAll($ctx))
        } catch {
            Write-ADPULine warn "Could not enumerate the controllers of $($d.Name) - skipping them."
            continue
        }

        foreach ($dc in $dcList) {
            $os = ''
            try { $os = [string]$dc.OSVersion } catch { }
            [pscustomobject]@{
                Name           = [string]$dc.Name
                DomainName     = [string]$d.Name
                OSVersion      = $os
                OSOk           = [bool]($os -match $script:ADPUModernServerPattern)
                Reachable      = $false
                Error          = $null
                AuditLogonOk   = $false
                AuditLogonFailOk = $false
                AuditKerbOk    = $false
                AuditCredValOk = $false
                AuditState     = @{ Logon = 'Unknown'; KerbAS = 'Unknown'; CredVal = 'Unknown' }
                AuditRaw       = @{ Logon = $null; KerbAS = $null; CredVal = $null }
                AuditMethod    = 'not read'
                NewKerbFields  = $false
                AuditPartial   = @{ Logon = $false; KerbAS = $false; CredVal = $false }
                Ntlm4624       = @()
                SvcLogons      = @()
                Ntlm4776       = @()
                KerbSeen       = @()
                KdcRc4         = @()
                Notes          = @()
            }
        }
    }
    $controllers = @($controllers)

    if ($controllers.Count) {
        $facts = Get-ADPUControllerFacts -Computer @($controllers.Name) -Days $Days -Credential $Credential `
                     -TargetSid @($accounts.Sid | Where-Object { $_ }) `
                     -TargetName @($accounts.Sam | Where-Object { $_ })

        foreach ($dc in $controllers) {
            if ($facts.Facts.ContainsKey($dc.Name)) {
                $f = $facts.Facts[$dc.Name]
                $dc.Reachable      = $true
                $dc.AuditLogonOk   = [bool]$f.AuditLogon
                $dc.AuditLogonFailOk = [bool]$f.AuditLogonFail
                $dc.AuditKerbOk    = [bool]$f.AuditKerb
                $dc.AuditCredValOk = [bool]$f.AuditCredVal
                $dc.AuditState     = $f.AuditState
                $dc.AuditRaw       = $f.AuditRaw
                $dc.AuditMethod    = [string]$f.AuditMethod
                # Whether 4768 carries "Available Keys" and the session-key type
                # is read from the controller's own event manifest (and from the
                # events themselves), not inferred from a version number.
                $dc.NewKerbFields  = [bool]$f.Kerb4768New
                if ($f.AuditPartial) {
                    $dc.AuditPartial = @{
                        Logon   = [bool]$f.AuditPartial.Logon
                        KerbAS  = [bool]$f.AuditPartial.KerbAS
                        CredVal = [bool]$f.AuditPartial.CredVal
                    }
                }
                $dc.Ntlm4624       = @($f.Ntlm4624)
                $dc.SvcLogons      = @($f.SvcLogons)
                $dc.Ntlm4776       = @($f.Ntlm4776)
                $dc.KerbSeen       = @($f.KerbSeen)
                $dc.KdcRc4         = @($f.KdcRc4)
                $dc.Notes          = @($f.Notes)
            } else {
                $dc.Error = if ($facts.Failed.ContainsKey($dc.Name)) { $facts.Failed[$dc.Name] } else { 'no response' }
                Write-ADPULine warn "$($dc.Name) could not be read ($($dc.Error)) - it contributes no evidence."
            }
        }
    }

    [pscustomobject]@{
        Forest       = [pscustomobject]@{
            Name      = [string]$forest.Name
            ModeLevel = [int]$forest.ForestModeLevel
            ReadyFL   = [bool]([int]$forest.ForestModeLevel -ge $script:ADPUFunctionalFloor)
            RootName  = $rootName
        }
        Domains      = $domains
        Controllers  = $controllers
        Accounts     = $accounts
        EnrolledSids = $pugSids
        LookbackDays = $Days
        Scope        = $Scope
        Identity     = @($requested)
        StrictScope  = [bool]$StrictScope
        ExcludedForeign = $excludedForeign
        Generated    = (Get-Date)
    }
}

#  ==========================================================================
#  >> Scoring (decide each account's verdict)
#  ==========================================================================

# What joining the group changes, beyond NTLM and DES/RC4. None of this can be
# read out of the directory, so it is stated plainly in the report instead of
# being silently assumed away.
$script:ADPUSideEffects = @(
    'The TGT is fixed at 4 hours and cannot be renewed - long-running scheduled tasks and batch jobs that rely on renewal will stop.'
    'Members cannot be delegated, constrained or unconstrained. Anything that impersonates the account downstream breaks.'
    'Credentials are not cached, so there is no offline sign-in. An admin on a laptop away from a controller cannot log in.'
    'CredSSP and WDigest no longer store the credential in plaintext - tooling that depends on credential delegation breaks.'
    'Protections apply from the next fresh logon. An existing session or ticket can hide the problem for hours.'
)

function Get-ADPUField {
    # Reads a field that an older collector may not have sent. Hashtables and
    # objects both come back from remoting, and under strict mode a missing key or
    # property is an error rather than $null - so look before reaching.
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { $p.Value } else { $null }
}

# The NTSTATUS codes event 4776 reports for a failed validation, in words. Only
# the ones that tell the reader something; anything else is shown as its code.
$script:ADPUNtStatus = @{
    '0xC000006A' = 'wrong password'
    '0xC0000064' = 'no such user'
    '0xC0000234' = 'locked out'
    '0xC0000072' = 'account disabled'
    '0xC0000071' = 'password expired'
    '0xC0000193' = 'account expired'
    '0xC0000224' = 'must change password'
    '0xC000006F' = 'outside logon hours'
    '0xC0000070' = 'workstation not allowed'
    '0xC000015B' = 'logon type not granted'
    '0xC0000133' = 'clock skew'
    '0xC0000371' = 'local account store'
}

function Format-ADPUStatusCounts {
    # "wrong password 1200, locked out 188" - largest first.
    param($Counts)
    if (-not $Counts) { return '' }
    $parts = foreach ($code in @($Counts.Keys | Sort-Object { [int]$Counts[$_] } -Descending)) {
        $label = if ($script:ADPUNtStatus.ContainsKey([string]$code)) { $script:ADPUNtStatus[[string]$code] } else { [string]$code }
        '{0} {1}' -f $label, [int]$Counts[$code]
    }
    ($parts -join ', ')
}

function New-ADPUFinding {
    param([string]$Code, [ValidateSet('bad','warn')] [string]$Severity, [string]$Text)
    [pscustomobject]@{ Code = $Code; Severity = $Severity; Text = $Text }
}

function Set-ADPUReadiness {
    <#
        .SYNOPSIS
            Annotates every privileged account with its Protected Users readiness.
        .DESCRIPTION
            Pure function over the topology object: it reads facts and evidence and
            writes verdicts, without touching the directory. That is what makes it
            testable with synthetic input.

            Two things changed against the earlier scoring. First, evidence is now
            scoped to the account's own domain - a controller in another domain
            never sees this account authenticate, so counting it as coverage
            overstated the case. Second, the verdict carries a confidence:

              Proven    - AES keys observed in the logs, the account really did
                          authenticate during the window, and every controller in
                          its domain was fully audited and on a build that reports
                          the new Kerberos fields.
              Plausible - no blocker found, but nothing positively confirmed
                          either; typically a quiet account.
              Unknown   - the checks could not look. Absence of findings here means
                          nothing at all.

            Mutates and returns the accounts.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Topology)

    $enrolled = $Topology.EnrolledSids
    if ($enrolled -isnot [System.Collections.Generic.HashSet[string]]) {
        $enrolled = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]@($enrolled | Where-Object { $_ }), [System.StringComparer]::OrdinalIgnoreCase)
    }

    $window = if ($Topology.LookbackDays) { [int]$Topology.LookbackDays } else { 7 }
    $oneYearAgo = (Get-Date).AddDays(-365)

    # ---- build per-domain evidence indexes once -------------------------------
    $index = @{}
    foreach ($d in @($Topology.Domains)) {
        $dcs = @($Topology.Controllers | Where-Object { $_.DomainName -ieq $d.Name })

        $ntlmSid = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $svcSid  = @{}
        $svcName = @{}
        $credNm  = @{}
        $kerb    = @{}

        foreach ($dc in ($dcs | Where-Object { $_.AuditLogonOk })) {
            foreach ($h in @($dc.Ntlm4624)) { if ($h.Sid) { [void]$ntlmSid.Add([string]$h.Sid) } }
        }
        # Service and batch logons on the controllers: successes carry a SID,
        # failures (4625) only a name. Both are folded per domain.
        foreach ($dc in ($dcs | Where-Object { $_.AuditLogonOk -or (Get-ADPUField $_ 'AuditLogonFailOk') })) {
            foreach ($h in @(Get-ADPUField $dc 'SvcLogons')) {
                if (-not $h) { continue }
                $sidKey  = [string](Get-ADPUField $h 'Sid')
                $nameKey = ([string](Get-ADPUField $h 'Account')).ToLowerInvariant()
                $target  = if ($sidKey) { $svcSid } else { $svcName }
                $k       = if ($sidKey) { $sidKey } else { $nameKey }
                if (-not $k) { continue }
                if (-not $target.ContainsKey($k)) {
                    $target[$k] = [pscustomobject]@{
                        Batch = 0; Service = 0; BatchFailed = 0; ServiceFailed = 0
                        Processes = @(); FailedStatus = @{}; Dcs = @(); Last = $null
                    }
                }
                $c = $target[$k]
                $c.Batch         += [int](Get-ADPUField $h 'Batch')
                $c.Service       += [int](Get-ADPUField $h 'Service')
                $c.BatchFailed   += [int](Get-ADPUField $h 'BatchFailed')
                $c.ServiceFailed += [int](Get-ADPUField $h 'ServiceFailed')
                $c.Processes = @(@($c.Processes) + @(Get-ADPUField $h 'Processes') | Where-Object { $_ } | Select-Object -Unique)
                if ($c.Dcs -notcontains $dc.Name) { $c.Dcs = @($c.Dcs) + $dc.Name }
                $fs = Get-ADPUField $h 'FailedStatus'
                if ($fs) {
                    foreach ($code in @($fs.Keys)) {
                        if ($c.FailedStatus.ContainsKey($code)) { $c.FailedStatus[$code] += [int]$fs[$code] } else { $c.FailedStatus[$code] = [int]$fs[$code] }
                    }
                }
                $last = Get-ADPUField $h 'Last'
                if ($null -eq $c.Last -or $last -gt $c.Last) { $c.Last = $last }
            }
        }
        foreach ($dc in ($dcs | Where-Object { $_.AuditCredValOk })) {
            foreach ($h in @($dc.Ntlm4776)) {
                if (-not $h.Account) { continue }
                $k = ([string]$h.Account).ToLowerInvariant()
                # Older collectors only reported Count/Succeeded; everything that
                # did not succeed is a failure.
                $hOk   = Get-ADPUField $h 'Succeeded'
                $hBad  = Get-ADPUField $h 'Failed'
                $ok  = if ($null -ne $hOk)  { [int]$hOk }  else { [int]$h.Count }
                $bad = if ($null -ne $hBad) { [int]$hBad } else { [int]$h.Count - $ok }
                if (-not $credNm.ContainsKey($k)) {
                    $credNm[$k] = [pscustomobject]@{
                        Count = 0; Succeeded = 0; Failed = 0; Last = $h.Last; Sources = @(); FailedSources = @()
                        FailedStatus = @{}
                    }
                }
                $c = $credNm[$k]
                $c.Count     += [int]$h.Count
                $c.Succeeded += $ok
                $c.Failed    += $bad
                if ($h.Last -gt $c.Last) { $c.Last = $h.Last }
                $c.Sources       = @(@($c.Sources) + @($h.Sources) | Where-Object { $_ } | Select-Object -Unique)
                $c.FailedSources = @(@($c.FailedSources) + @(Get-ADPUField $h 'FailedSources') | Where-Object { $_ } | Select-Object -Unique)
                $fs = Get-ADPUField $h 'FailedStatus'
                if ($fs) {
                    foreach ($code in @($fs.Keys)) {
                        $n = [int]$fs[$code]
                        if ($c.FailedStatus.ContainsKey($code)) { $c.FailedStatus[$code] += $n } else { $c.FailedStatus[$code] = $n }
                    }
                }
            }
        }
        foreach ($dc in ($dcs | Where-Object { $_.AuditKerbOk })) {
            foreach ($h in @($dc.KerbSeen)) {
                if (-not $h.Sid) { continue }
                $k = [string]$h.Sid
                if (-not $kerb.ContainsKey($k)) {
                    $kerb[$k] = [pscustomobject]@{
                        Count = 0; NewEvents = 0; Weak = 0; WeakNew = 0; WeakLegacy = 0
                        KeysSeen = $false; HasAes = $false; Keys = $null
                        NoAesAdv = 0; AdvSources = @(); Last = $null
                    }
                }
                $kerb[$k].Count     += [int]$h.Count
                $kerb[$k].NewEvents += [int](Get-ADPUField $h 'NewEvents')
                $kerb[$k].Weak      += [int]$h.Weak
                # A record without the split is from the old collector: treat all
                # of its weak findings as legacy (ticket-field) evidence.
                $wNew = Get-ADPUField $h 'WeakNew'
                $wOld = Get-ADPUField $h 'WeakLegacy'
                if ($null -ne $wNew -or $null -ne $wOld) {
                    $kerb[$k].WeakNew    += [int]$wNew
                    $kerb[$k].WeakLegacy += [int]$wOld
                } else {
                    $kerb[$k].WeakLegacy += [int]$h.Weak
                }
                $kerb[$k].NoAesAdv  += [int](Get-ADPUField $h 'NoAesAdv')
                $adv = @(Get-ADPUField $h 'AdvSources' | Where-Object { $_ })
                if ($adv.Count) {
                    $kerb[$k].AdvSources = @(@($kerb[$k].AdvSources) + $adv | Select-Object -Unique)
                }
                if ($h.KeysSeen) { $kerb[$k].KeysSeen = $true; $kerb[$k].HasAes = ($kerb[$k].HasAes -or [bool]$h.HasAes) }
                if ($h.Keys) { $kerb[$k].Keys = [string]$h.Keys }
                if ($null -eq $kerb[$k].Last -or $h.Last -gt $kerb[$k].Last) { $kerb[$k].Last = $h.Last }
            }
        }

        $reachable = @($dcs | Where-Object { $_.Reachable })
        # A krbtgt without AES makes the legacy (ticket-field) DES/RC4 reading
        # unusable: that field is the TGT's own encryption, chosen from krbtgt's
        # keys. The session-key reading from newer controllers is unaffected, so
        # this is decided per finding, not for the whole domain.
        $krbtgtBad = [bool]($d.Krbtgt -and $d.Krbtgt.Readable -and $d.Krbtgt.HasAes -eq $false)
        $isPartial = { param($dc, [string]$key) [bool]($dc.AuditPartial -and $dc.AuditPartial[$key]) }

        $index[$d.Name.ToLowerInvariant()] = [pscustomobject]@{
            Domain       = $d
            Dcs          = $dcs
            Reachable    = $reachable
            Unreachable  = @($dcs | Where-Object { -not $_.Reachable })
            LogonDcs     = @($reachable | Where-Object { $_.AuditLogonOk })
            KerbDcs      = @($reachable | Where-Object { $_.AuditKerbOk })
            CredValDcs   = @($reachable | Where-Object { $_.AuditCredValOk })
            NewFieldDcs  = @($reachable | Where-Object { $_.NewKerbFields })
            PartialDcs   = @($reachable | Where-Object {
                               (& $isPartial $_ 'Logon') -or (& $isPartial $_ 'KerbAS') -or (& $isPartial $_ 'CredVal') })
            NtlmSids     = $ntlmSid
            SvcSids      = $svcSid
            SvcNames     = $svcName
            LogonFailDcs = @($reachable | Where-Object { Get-ADPUField $_ 'AuditLogonFailOk' })
            CredNames    = $credNm
            Kerb         = $kerb
            KrbtgtBad    = $krbtgtBad
        }
    }

    $shorten = {
        param($list)
        $names = @($list | ForEach-Object { $_.Name } | Sort-Object)
        if ($names.Count -le 3) { $names -join ', ' } else { ($names[0..2] -join ', ') + (' and {0} more' -f ($names.Count - 3)) }
    }

    # Break-glass accounts: kept out of the group on purpose, so that a Protected
    # Users side effect nobody foresaw cannot lock out every administrator at
    # once. The built-in Administrator (RID 500) always counts; -BreakGlass adds
    # more by SID, sAMAccountName or DOMAIN\name.
    $breakGlass = @()
    $bgProp = $Topology.PSObject.Properties['BreakGlass']
    if ($bgProp -and $bgProp.Value) { $breakGlass = @($bgProp.Value | Where-Object { $_ } | ForEach-Object { [string]$_ }) }

    $minProven = [int]$script:ADPUProvenMinDays

    foreach ($a in @($Topology.Accounts)) {
        # An out-of-scope account is deliberately given no evidence index. Its
        # domain's controllers were never read, and borrowing another domain's
        # findings - the 4776 match is by account name, which repeats across
        # domains - would invent blockers out of thin air.
        $key = if ($a.Domain) { $a.Domain.ToLowerInvariant() } else { '' }
        $ix  = if (-not $a.Foreign -and $index.ContainsKey($key)) { $index[$key] } else { $null }

        $blockers = [System.Collections.Generic.List[object]]::new()
        $hints    = [System.Collections.Generic.List[object]]::new()
        $evidence = [System.Collections.Generic.List[object]]::new()

        $isEnrolled = [bool]($a.Sid -and $enrolled.Contains([string]$a.Sid))
        # Determined up front because the confidence computation reads it.
        $outOfScope = [bool]$a.Foreign
        $person     = ([string]$a.Class) -match '^(user|iNetOrgPerson)$'
        $uac        = if ($null -ne $a.Uac) { [int]$a.Uac } else { 0 }

        $desOnly     = (($uac -band 0x200000) -ne 0)   # USE_DES_KEY_ONLY
        $unconstr    = (($uac -band 0x80000)  -ne 0)   # TRUSTED_FOR_DELEGATION
        $trustedAuth = (($uac -band 0x1000000) -ne 0)  # TRUSTED_TO_AUTH_FOR_DELEGATION
        $noPreAuth   = (($uac -band 0x400000) -ne 0)   # DONT_REQ_PREAUTH
        $disabled    = ($null -ne $a.Enabled) -and (-not $a.Enabled)
        $hasSpn      = @($a.Spns).Count -gt 0
        $delegates   = @($a.DelegateTo).Count -gt 0
        $noAesEtype  = ($null -ne $a.EncTypes) -and ([int]$a.EncTypes -ne 0) -and ((([int]$a.EncTypes) -band 0x18) -eq 0)

        $isRid500   = [bool]($a.Sid -and ([string]$a.Sid) -match '-500$')
        $samName    = [string]$a.Sam
        $qualified  = '{0}\{1}' -f $a.Domain, $a.Sam
        $listed     = [bool](@($breakGlass | Where-Object {
                          $_ -ieq [string]$a.Sid -or $_ -ieq $samName -or $_ -ieq $qualified
                      }).Count)
        $breakGlassAcct = ($isRid500 -or $listed) -and -not $outOfScope

        # -- log evidence, scoped to the account's own domain --------------------
        $kerbRec   = if ($ix -and $a.Sid -and $ix.Kerb.ContainsKey([string]$a.Sid)) { $ix.Kerb[[string]$a.Sid] } else { $null }
        $credRec   = if ($ix -and $a.Sam -and $ix.CredNames.ContainsKey(([string]$a.Sam).ToLowerInvariant())) { $ix.CredNames[([string]$a.Sam).ToLowerInvariant()] } else { $null }
        $didNtlm   = [bool]($ix -and $a.Sid -and $ix.NtlmSids.Contains([string]$a.Sid))
        $svcOk   = if ($ix -and $a.Sid -and $ix.SvcSids.ContainsKey([string]$a.Sid)) { $ix.SvcSids[[string]$a.Sid] } else { $null }
        $svcFail = if ($ix -and $a.Sam -and $ix.SvcNames.ContainsKey(([string]$a.Sam).ToLowerInvariant())) { $ix.SvcNames[([string]$a.Sam).ToLowerInvariant()] } else { $null }
        # A successful NTLM validation proves a dependency. Failures block too:
        # repeated failures from the same machines are almost always a saved
        # credential that was never updated, and the day it is, that machine needs
        # NTLM. The one exception is "no such user" - the name did not resolve to
        # this account at all, so it says nothing about it.
        $credStatus  = if ($credRec) { Get-ADPUField $credRec 'FailedStatus' } else { $null }
        $noSuchUser  = if ($credStatus -and $credStatus.ContainsKey('0xC0000064')) { [int]$credStatus['0xC0000064'] } else { 0 }
        $failRelevant = if ($credRec) { [int]$credRec.Failed - $noSuchUser } else { 0 }
        $didCred   = [bool]($credRec -and [int]$credRec.Succeeded -gt 0)
        $failCred  = [bool]($credRec -and [int]$credRec.Succeeded -eq 0 -and $failRelevant -gt 0)
        $unknownOnly = [bool]($credRec -and [int]$credRec.Succeeded -eq 0 -and $failRelevant -le 0 -and $noSuchUser -gt 0)
        $weakNew    = [bool]($kerbRec -and [int]$kerbRec.WeakNew -gt 0)
        $weakLegacy = [bool]($kerbRec -and [int]$kerbRec.WeakLegacy -gt 0)
        $krbtgtBad  = [bool]($ix -and $ix.KrbtgtBad)
        $didWeak   = $weakNew -or ($weakLegacy -and -not $krbtgtBad)
        $aesProven = [bool]($kerbRec -and $kerbRec.KeysSeen -and $kerbRec.HasAes)
        $aesDenied = [bool]($kerbRec -and $kerbRec.KeysSeen -and -not $kerbRec.HasAes)

        # The password-age proxy only has to stand in when nothing better is known.
        # Observed key material beats it in both directions.
        $pwdPreGroup = ($a.PwdLastSet -is [datetime]) -and ($a.PugBornOn -is [datetime]) -and ($a.PwdLastSet -lt $a.PugBornOn)
        $pwdStale    = ($a.PwdLastSet -is [datetime]) -and ($a.PwdLastSet -lt $oneYearAgo)

        # ---- blockers ----------------------------------------------------------
        if ($a.IsGmsa) {
            $blockers.Add((New-ADPUFinding 'Gmsa' 'bad' 'group managed service account - cannot join Protected Users (nor be marked sensitive); use an authentication policy silo instead, and reconsider its admin rights'))
        } elseif (-not $person) {
            $blockers.Add((New-ADPUFinding 'NotAUser' 'bad' ('not a user account (objectClass "{0}") - cannot be enrolled; reconsider its admin rights' -f $a.Class)))
        }
        if (-not $a.PugPresent -and -not $a.Foreign) {
            $blockers.Add((New-ADPUFinding 'NoGroup' 'bad' 'its home domain has no Protected Users group - create it there first (PDC emulator on 2012 R2+)'))
        }
        if ($disabled) {
            # Enrolling a disabled admin achieves nothing; the fix is to take its
            # privileges away. It used to land in "clear to enrol" with a command.
            $blockers.Add((New-ADPUFinding 'Disabled' 'bad' 'account is disabled but still sits in an admin group - remove it from the group rather than enrolling it'))
        }
        if ($desOnly) {
            $blockers.Add((New-ADPUFinding 'DesOnly' 'bad' '"use DES encryption types only" is set (userAccountControl 0x200000) - clear the flag and reset the password'))
        }
        if ($noAesEtype) {
            $blockers.Add((New-ADPUFinding 'NoAesEtype' 'bad' ('msDS-SupportedEncryptionTypes = 0x{0:X} permits no AES - add AES128/AES256 or clear the attribute' -f [int]$a.EncTypes)))
        }
        if ($aesDenied) {
            $blockers.Add((New-ADPUFinding 'NoAesKeys' 'bad' ('the KDC reports no AES key for this account (Available Keys: {0}) - reset the password to generate one' -f $kerbRec.Keys)))
        } elseif ($pwdPreGroup -and -not $aesProven) {
            $blockers.Add((New-ADPUFinding 'PwdPreGroup' 'bad' ('password was last set {0:yyyy-MM-dd}, before the group appeared on {1:yyyy-MM-dd} - it may have no AES keys; reset it before enrolling' -f $a.PwdLastSet, $a.PugBornOn)))
        }
        if ($delegates) {
            $blockers.Add((New-ADPUFinding 'DelegatesOut' 'bad' ('constrained delegation is configured on this account (msDS-AllowedToDelegateTo: {0}) - members of the group cannot delegate at all' -f (@($a.DelegateTo) -join ', '))))
        }
        if ($trustedAuth) {
            $blockers.Add((New-ADPUFinding 'TrustedToAuth' 'bad' 'trusted to authenticate for delegation (protocol transition) - members of the group cannot delegate at all'))
        }
        if ($unconstr) {
            $blockers.Add((New-ADPUFinding 'Unconstrained' 'bad' 'trusted for unconstrained delegation - members of the group cannot delegate, and this is a high-value target in its own right'))
        }
        if ($svcOk -and ([int]$svcOk.Service + [int]$svcOk.Batch) -gt 0) {
            $what = @(
                if ([int]$svcOk.Service) { '{0} service logon(s)' -f [int]$svcOk.Service }
                if ([int]$svcOk.Batch)   { '{0} scheduled-task (batch) logon(s)' -f [int]$svcOk.Batch }
            ) -join ' and '
            $proc = if (@($svcOk.Processes).Count) { ' via ' + ((@($svcOk.Processes) | Select-Object -First 3) -join ', ') } else { '' }
            $blockers.Add((New-ADPUFinding 'ServiceLogon' 'bad' ('{0} on {1}{2} in the last {3} day(s) (event 4624) - the account runs a service or task. Protected Users gives it a 4-hour TGT that cannot be renewed, no delegation and no "do not store password" tasks; move that workload to a gMSA or a dedicated service account first' -f $what, ((@($svcOk.Dcs) | Select-Object -First 3) -join ', '), $proc, $window)))
        }
        if ($svcFail -and ([int]$svcFail.ServiceFailed + [int]$svcFail.BatchFailed) -gt 0) {
            $what = @(
                if ([int]$svcFail.ServiceFailed) { '{0} failed service logon(s)' -f [int]$svcFail.ServiceFailed }
                if ([int]$svcFail.BatchFailed)   { '{0} failed scheduled-task (batch) logon(s)' -f [int]$svcFail.BatchFailed }
            ) -join ' and '
            $why  = Format-ADPUStatusCounts $svcFail.FailedStatus
            $why  = if ($why) { " ($why)" } else { '' }
            $proc = if (@($svcFail.Processes).Count) { ' via ' + ((@($svcFail.Processes) | Select-Object -First 3) -join ', ') } else { '' }
            $blockers.Add((New-ADPUFinding 'ServiceLogonFailed' 'bad' ('{0} on {1}{2}{3} in the last {4} day(s) (event 4625) - a service or scheduled task is still configured with this account, most likely with an old password. Find it and move it to a gMSA or a dedicated service account before enrolling' -f $what, ((@($svcFail.Dcs) | Select-Object -First 3) -join ', '), $proc, $why, $window)))
        }
        if ($didNtlm) {
            $blockers.Add((New-ADPUFinding 'Ntlm4624' 'bad' ('authenticated with NTLM at a domain controller (event 4624) inside the last {0} day(s) - track down the dependency first' -f $window)))
        }
        if ($didCred) {
            $src = if (@($credRec.Sources).Count) { ' from ' + ((@($credRec.Sources) | Select-Object -First 4) -join ', ') } else { '' }
            $blockers.Add((New-ADPUFinding 'Ntlm4776' 'bad' ('successful NTLM credential validation (event 4776) {0}x in the last {1} day(s){2} - something in the estate still authenticates this account over NTLM' -f $credRec.Succeeded, $window, $src)))
        }
        if ($failCred) {
            $srcList = @($credRec.FailedSources)
            $src  = if ($srcList.Count) { ' from ' + (($srcList | Select-Object -First 4) -join ', ') + $(if ($srcList.Count -gt 4) { ' and more' } else { '' }) } else { '' }
            $why  = Format-ADPUStatusCounts $credStatus
            $why  = if ($why) { " ($why)" } else { '' }
            # Few sources, many attempts: a configured consumer. Many sources: it
            # may be an attack. Either way it has to be understood first.
            $read = if ($srcList.Count -and $srcList.Count -le 3) {
                'something on those machines is still set up to sign this account in over NTLM, most likely with an old saved password - once that password is corrected it needs NTLM and breaks under Protected Users. Find it and move it to Kerberos or another account first'
            } else {
                'either something is still set up to use this account over NTLM with an old password, or someone is trying the account - find out which before enrolling'
            }
            $blockers.Add((New-ADPUFinding 'Ntlm4776Failed' 'bad' ('{0} failed NTLM validation(s) (event 4776) in the last {1} day(s){2}{3}, none successful - {4}' -f $failRelevant, $window, $src, $why, $read)))
        }
        if ($weakNew) {
            $blockers.Add((New-ADPUFinding 'WeakKerb' 'bad' ('negotiated a DES/RC4 session key {0}x in the last {1} day(s) (event 4768, session-key field) - fix the cipher usage first' -f $kerbRec.WeakNew, $window)))
        }
        if ($weakLegacy) {
            if ($krbtgtBad) {
                # The legacy ticket field is the krbtgt's choice. With a krbtgt
                # that permits no AES, every account looks like an RC4 user.
                $hints.Add((New-ADPUFinding 'WeakKerbUnreliable' 'warn' 'a non-AES ticket was reported by a controller without the newer 4768 fields, but this domain''s krbtgt permits no AES - the finding is a domain-wide artefact, not evidence about this account'))
            } else {
                $blockers.Add((New-ADPUFinding 'WeakKerbLegacy' 'bad' ('a non-AES Kerberos ticket was reported {0}x in the last {1} day(s) by controller(s) without the newer 4768 fields - weaker evidence (the legacy field is the ticket''s encryption, not the negotiated session key), but not safe to ignore' -f $kerbRec.WeakLegacy, $window)))
            }
        }

        # ---- hints (never change the verdict) ----------------------------------
        if ($unknownOnly) {
            $hints.Add((New-ADPUFinding 'Ntlm4776UnknownUser' 'warn' ('{0} NTLM attempt(s) for this name failed as "no such user" (event 4776) - the name did not resolve to this account, so this is not evidence about it; possibly a same-named account elsewhere or a mistyped domain' -f $noSuchUser)))
        }
        # Enrolled members can no longer use NTLM at all, so any NTLM for them is
        # a sign-in that is (or will be) turned away - or it predates enrolment.
        if ($isEnrolled -and ($didNtlm -or $didCred -or $failCred)) {
            $n = 0
            if ($credRec) { $n = [int]$credRec.Succeeded + $failRelevant }
            $srcList = @(@($(if ($credRec) { $credRec.Sources }) ) + @($(if ($credRec) { $credRec.FailedSources })) | Where-Object { $_ } | Select-Object -Unique)
            $src = if ($srcList.Count) { ' from ' + (($srcList | Select-Object -First 4) -join ', ') } else { '' }
            $hints.Add((New-ADPUFinding 'NtlmWhileEnrolled' 'warn' ('already enrolled, yet NTLM was used or tried for it in the last {0} day(s){1}{2} - Protected Users refuses NTLM for members, so these sign-ins are probably failing (unless they predate enrolment); run -Verify to confirm' -f $window, $src, $(if ($n) { " ($n x, event 4776)" } else { '' }))))
        }
        if ($kerbRec -and [int]$kerbRec.NoAesAdv -gt 0) {
            $src = if (@($kerbRec.AdvSources).Count) { ' from ' + ((@($kerbRec.AdvSources) | Select-Object -First 4) -join ', ') } else { '' }
            $hints.Add((New-ADPUFinding 'ClientNoAes' 'warn' ('{0} Kerberos request(s){1} came from a client that offered no AES at all - that client will not be able to sign this account in once it is enrolled' -f $kerbRec.NoAesAdv, $src)))
        }
        if ($a.AdminCount -and -not $isEnrolled -and -not $breakGlassAcct) {
            $hints.Add((New-ADPUFinding 'AdminCount' 'warn' 'adminCount=1 but not in Protected Users - a protected admin left outside the group'))
        }
        if ($hasSpn -and $person) {
            $hints.Add((New-ADPUFinding 'HasSpn' 'warn' ('a user account carrying {0} service principal name(s) - this is a service account in disguise, kerberoastable, and very likely bound to something that will break' -f @($a.Spns).Count)))
        }
        if ($pwdStale) {
            $hints.Add((New-ADPUFinding 'PwdStale' 'warn' ('password is over a year old (set {0:yyyy-MM-dd}) - rotate it soon' -f $a.PwdLastSet)))
        }
        if ($a.PwdNeverExp) { $hints.Add((New-ADPUFinding 'PwdNeverExp' 'warn' 'password is set to never expire')) }
        if ($noPreAuth)     { $hints.Add((New-ADPUFinding 'NoPreAuth'   'warn' 'Kerberos pre-auth not required (AS-REP roastable)')) }
        if ($breakGlassAcct -and $isEnrolled) {
            $hints.Add((New-ADPUFinding 'BreakGlassEnrolled' 'warn' ('{0} is enrolled - make sure at least one emergency admin account stays outside Protected Users' -f $(if ($isRid500) { 'the built-in Administrator (RID 500)' } else { 'this break-glass account' }))))
        }

        # ---- coverage and confidence -------------------------------------------
        $coverGaps = [System.Collections.Generic.List[string]]::new()
        if (-not $ix -or -not @($ix.Dcs).Count) {
            $coverGaps.Add('no controller of this domain could be listed')
        } else {
            $reach = @($ix.Reachable).Count
            if (@($ix.Unreachable).Count) {
                $coverGaps.Add(('{0} of {1} controller(s) in this domain could not be read at all' -f @($ix.Unreachable).Count, @($ix.Dcs).Count))
            }
            # "Some controllers" is a gap too, not a pass: an account that only ever
            # authenticates against the unaudited one leaves no trace anywhere.
            $partialGap = {
                param([string]$What, $OnList, [string]$Missing)
                $on = @($OnList).Count
                if (-not $on)            { $coverGaps.Add("no controller had $What auditing on - $Missing") }
                elseif ($on -lt $reach)  { $coverGaps.Add("only $on of $reach readable controller(s) had $What auditing on - $Missing on the rest") }
            }
            & $partialGap 'Logon'                 $ix.LogonDcs   'NTLM aimed at a controller would not have been recorded'
            & $partialGap 'Credential Validation' $ix.CredValDcs 'NTLM against member servers would not have been recorded'
            & $partialGap 'Kerberos Authentication Service' $ix.KerbDcs 'DES/RC4 use and account key material would not have been recorded'
            if (@($ix.KerbDcs).Count -and @($ix.NewFieldDcs).Count -lt $reach) {
                $coverGaps.Add(('{0} of {1} readable controller(s) predate the newer 4768 fields (Server 2019+, or 2016 with the January 2025 update) - AES keys cannot be confirmed there and the DES/RC4 reading is weaker' -f
                                ($reach - @($ix.NewFieldDcs).Count), $reach))
            }
            if (@($ix.PartialDcs).Count) {
                $coverGaps.Add(('{0} controller(s) were only partly read (row cap or a read error) - see the environment notes' -f @($ix.PartialDcs).Count))
            }
        }

        $fullCover = [bool]($ix -and @($ix.Dcs).Count -and -not @($ix.Unreachable).Count -and
                     (@($ix.LogonDcs).Count -eq @($ix.Reachable).Count) -and
                     (@($ix.CredValDcs).Count -eq @($ix.Reachable).Count) -and
                     (@($ix.KerbDcs).Count -eq @($ix.Reachable).Count) -and
                     (@($ix.NewFieldDcs).Count -eq @($ix.Reachable).Count) -and
                     -not @($ix.PartialDcs).Count)

        $blind = -not $ix -or (-not @($ix.LogonDcs).Count -and -not @($ix.CredValDcs).Count -and -not @($ix.KerbDcs).Count)
        $active = [bool]($kerbRec -and [int]$kerbRec.Count -gt 0)
        # A handful of days is not enough to call anything proven, however clean.
        $longEnough = ($window -ge $minProven)

        $confidence =
            if ($outOfScope -or $blind) { 'Unknown' }
            elseif ($fullCover -and $aesProven -and $active -and $longEnough) { 'Proven' }
            else { 'Plausible' }

        # ---- evidence, for the accounts that come back clear --------------------
        # Evidence lines carry a third severity, 'sub', for a plain fact that is
        # neither a warning nor a problem - so they are built directly rather than
        # through New-ADPUFinding.
        $say = {
            param([string]$code, [string]$sev, [string]$text)
            $evidence.Add([pscustomobject]@{ Code = $code; Severity = $sev; Text = $text })
        }

        & $say 'Class' 'sub' ('account type "{0}" - a real user account, which is what the group is for' -f $a.Class)

        if ($aesProven) {
            & $say 'AesProven' 'sub' ('the KDC reported AES key material for this account (Available Keys: {0}) - AES keys are confirmed, not assumed' -f $kerbRec.Keys)
        } elseif ($a.PwdLastSet -is [datetime] -and $a.PugBornOn -is [datetime]) {
            & $say 'AesGuessed' 'sub' ('password set {0:yyyy-MM-dd}, after the group appeared on {1:yyyy-MM-dd} - AES keys are inferred from that, not observed' -f $a.PwdLastSet, $a.PugBornOn)
        } elseif ($a.PwdLastSet -is [datetime]) {
            & $say 'AesUnknown' 'warn' ('password set {0:yyyy-MM-dd}, but the group age is unknown here - AES keys are assumed, not proven' -f $a.PwdLastSet)
        } else {
            & $say 'AesUnknown' 'warn' 'password age unknown and no key material observed - AES keys are assumed, not proven'
        }

        if ($null -eq $a.EncTypes -or [int]$a.EncTypes -eq 0) {
            $shown = if ($null -eq $a.EncTypes) { 'is not set' } else { 'is 0' }
            & $say 'Etypes' 'sub' ('msDS-SupportedEncryptionTypes {0}, so the account follows the domain default (AES)' -f $shown)
        } else {
            & $say 'Etypes' 'sub' ('msDS-SupportedEncryptionTypes = 0x{0:X}, which includes AES' -f [int]$a.EncTypes)
        }
        & $say 'DesFlag' 'sub' 'the "use DES encryption types only" flag is not set'
        & $say 'Delegation' 'sub' 'no delegation is configured on the account, so the group''s delegation ban costs it nothing'

        if ($ix -and @($ix.LogonDcs).Count) {
            & $say 'Ntlm4624' 'sub' ('no NTLM logon (4624) for this SID in the last {0} day(s) on {1} controller(s) of {2}: {3}' -f $window, @($ix.LogonDcs).Count, $a.Domain, (& $shorten $ix.LogonDcs))
        } else {
            & $say 'Ntlm4624' 'warn' 'no controller in this domain had Logon auditing on - the NTLM check came back empty because it could not look'
        }
        if ($ix -and @($ix.CredValDcs).Count) {
            & $say 'Ntlm4776' 'sub' ('no NTLM credential validation (4776) for this account name in the last {0} day(s) on {1} controller(s): {2}' -f $window, @($ix.CredValDcs).Count, (& $shorten $ix.CredValDcs))
        } else {
            & $say 'Ntlm4776' 'warn' 'no controller in this domain had Credential Validation auditing on - NTLM against member servers would not have been seen at all'
        }
        if ($ix -and (@($ix.LogonDcs).Count -or @($ix.LogonFailDcs).Count)) {
            $seen = @(
                if (@($ix.LogonDcs).Count)     { 'successful (4624)' }
                if (@($ix.LogonFailDcs).Count) { 'failed (4625)' }
            ) -join ' or '
            & $say 'ServiceLogon' 'sub' ('no {0} service or scheduled-task logon on the controllers in the last {1} day(s) - member servers are not visible from here' -f $seen, $window)
        } else {
            & $say 'ServiceLogon' 'warn' 'Logon auditing (success or failure) is off on every controller - service and scheduled-task logons could not be looked for'
        }
        if ($ix -and @($ix.KerbDcs).Count) {
            $how = if (@($ix.NewFieldDcs).Count -ge @($ix.KerbDcs).Count) { 'negotiated session key' } else { 'session key or, on older controllers, ticket' }
            & $say 'WeakKerb' 'sub' ('no DES/RC4 {0} (4768) for this SID in the last {1} day(s) on {2} controller(s): {3}' -f $how, $window, @($ix.KerbDcs).Count, (& $shorten $ix.KerbDcs))
        } else {
            & $say 'WeakKerb' 'warn' 'no controller in this domain had Kerberos Authentication Service auditing on - the DES/RC4 check could not look'
        }
        if ($active) {
            & $say 'Activity' 'sub' ('the account did authenticate during the window ({0} Kerberos request(s), last {1:yyyy-MM-dd HH:mm}) - so a quiet result is a real result' -f $kerbRec.Count, $kerbRec.Last)
        } else {
            & $say 'Activity' 'warn' ('no authentication by this account was recorded in the last {0} day(s) - it may simply be idle, in which case the clean result proves very little' -f $window)
        }
        foreach ($g in $coverGaps) { & $say 'Coverage' 'warn' $g }
        if ($longEnough) {
            & $say 'Window' 'warn' ('the log window is {0} day(s) - anything older than that was not examined' -f $window)
        } else {
            & $say 'Window' 'warn' ('the log window is only {0} day(s) - below {1} days nothing is rated "proven"; re-run with -Days {1} or more' -f $window, $minProven)
        }

        # Out of scope is a third state, not a verdict: the account is privileged
        # in a reviewed domain but homed somewhere that was not reviewed, so
        # neither "clear" nor "blocked" would be an honest answer.
        if ($outOfScope) {
            $hints.Add((New-ADPUFinding 'OutOfScope' 'warn' ('homed in {0}, which was not part of this review - re-run with that domain in scope to judge it' -f $a.Domain)))
        }
        # A break-glass account that is not enrolled is where it should be. It is
        # neither clear (no enrolment command for it) nor blocked.
        $reserved = $breakGlassAcct -and -not $isEnrolled
        $clearNow = ($blockers.Count -eq 0) -and (-not $isEnrolled) -and (-not $outOfScope) -and (-not $reserved)

        $a | Add-Member -NotePropertyName OutOfScope  -NotePropertyValue $outOfScope  -Force
        $a | Add-Member -NotePropertyName Enrolled    -NotePropertyValue $isEnrolled  -Force
        $a | Add-Member -NotePropertyName Reserved    -NotePropertyValue $reserved    -Force
        $a | Add-Member -NotePropertyName BreakGlass  -NotePropertyValue $breakGlassAcct -Force
        $a | Add-Member -NotePropertyName Person      -NotePropertyValue $person      -Force
        $a | Add-Member -NotePropertyName HasSpn      -NotePropertyValue $hasSpn      -Force
        $a | Add-Member -NotePropertyName Disabled    -NotePropertyValue $disabled    -Force
        $a | Add-Member -NotePropertyName PwdStale    -NotePropertyValue $pwdStale    -Force
        $a | Add-Member -NotePropertyName PwdPreGroup -NotePropertyValue $pwdPreGroup -Force
        $a | Add-Member -NotePropertyName AesProven   -NotePropertyValue $aesProven   -Force
        $a | Add-Member -NotePropertyName AesDenied   -NotePropertyValue $aesDenied   -Force
        $a | Add-Member -NotePropertyName DidNtlm     -NotePropertyValue ($didNtlm -or $didCred) -Force
        $a | Add-Member -NotePropertyName DidWeakKerb -NotePropertyValue $didWeak     -Force
        $a | Add-Member -NotePropertyName Blockers    -NotePropertyValue @($blockers) -Force
        $a | Add-Member -NotePropertyName Hints       -NotePropertyValue @($hints)    -Force
        $a | Add-Member -NotePropertyName Evidence    -NotePropertyValue @($evidence) -Force
        $a | Add-Member -NotePropertyName Confidence  -NotePropertyValue $confidence  -Force
        $a | Add-Member -NotePropertyName ClearNow    -NotePropertyValue $clearNow    -Force
        $a
    }
}

#  ==========================================================================
#  >> Summary and command helpers (shared by console, HTML and JSON)
#  ==========================================================================

$script:ADPULevelNames = @{
    0 = 'Server 2000'; 1 = 'Server 2003 (interim)'; 2 = 'Server 2003'
    3 = 'Server 2008'; 4 = 'Server 2008 R2';        5 = 'Server 2012'
    6 = 'Server 2012 R2'; 7 = 'Server 2016';        10 = 'Server 2025'
}

function Get-ADPULevelName {
    param($Level)
    if ($script:ADPULevelNames.ContainsKey([int]$Level)) { $script:ADPULevelNames[[int]$Level] } else { "level $Level" }
}

function Get-ADPUSummary {
    <#
        One place that counts things, so the console, the HTML, the JSON and the
        exit code can never drift apart.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Topology)

    $all      = @($Topology.Accounts)
    $outside  = @($all | Where-Object { $_.OutOfScope })
    $inScope  = @($all | Where-Object { -not $_.OutOfScope })
    $enrolled = @($inScope | Where-Object { $_.Enrolled })
    # Break-glass accounts outside the group are where they belong: not pending,
    # not blocked, and they do not move the exit code.
    $reserved = @($inScope | Where-Object { -not $_.Enrolled -and $_.PSObject.Properties['Reserved'] -and $_.Reserved })
    $pending  = @($inScope | Where-Object { -not $_.Enrolled -and -not ($_.PSObject.Properties['Reserved'] -and $_.Reserved) })
    $clear    = @($pending | Where-Object { $_.ClearNow })
    $blocked  = @($pending | Where-Object { -not $_.ClearNow })
    $dcs      = @($Topology.Controllers)
    $reach    = @($dcs | Where-Object { $_.Reachable })

    # "Off" and "we could not tell" are reported apart: telling an admin that
    # auditing is disabled when the read simply failed sends them to fix the
    # wrong thing.
    $state = { param($dc, [string]$key) if ($dc.AuditState) { [string]$dc.AuditState[$key] } else { 'Unknown' } }
    $gaps = @{
        Unreachable    = @($dcs   | Where-Object { -not $_.Reachable })
        LogonOff       = @($reach | Where-Object { (& $state $_ 'Logon')   -eq 'Off' })
        KerbOff        = @($reach | Where-Object { (& $state $_ 'KerbAS')  -eq 'Off' })
        CredValOff     = @($reach | Where-Object { (& $state $_ 'CredVal') -eq 'Off' })
        LogonUnknown   = @($reach | Where-Object { (& $state $_ 'Logon')   -eq 'Unknown' })
        KerbUnknown    = @($reach | Where-Object { (& $state $_ 'KerbAS')  -eq 'Unknown' })
        CredValUnknown = @($reach | Where-Object { (& $state $_ 'CredVal') -eq 'Unknown' })
        OldKerb        = @($reach | Where-Object { $_.AuditKerbOk -and -not $_.NewKerbFields })
        # Read, but not completely - row cap or a reader that failed half-way.
        Partial        = @($reach | Where-Object {
                             $_.PSObject.Properties['AuditPartial'] -and $_.AuditPartial -and
                             ($_.AuditPartial['Logon'] -or $_.AuditPartial['KerbAS'] -or $_.AuditPartial['CredVal']) })
    }
    $gaps.AuditUnreadable = @($reach | Where-Object {
        (& $state $_ 'Logon') -eq 'Unknown' -and (& $state $_ 'KerbAS') -eq 'Unknown' -and (& $state $_ 'CredVal') -eq 'Unknown'
    })
    $krbtgtBad = @($Topology.Domains | Where-Object { $_.Krbtgt -and $_.Krbtgt.Readable -and $_.Krbtgt.HasAes -eq $false })
    $kdcRc4    = 0
    foreach ($dc in $reach) { foreach ($k in @($dc.KdcRc4)) { $kdcRc4 += [int]$k.Count } }

    # A privileged member homed in an unreviewed domain is an incomplete picture,
    # so it counts as a coverage gap rather than as a blocked account.
    # An excluded foreign member is not a gap: the operator asked for it to be
    # left out, and an exit code of 2 would nag them about their own decision.
    $hasGaps = [bool]($gaps.Unreachable.Count -or $gaps.LogonOff.Count -or $gaps.KerbOff.Count -or
                      $gaps.CredValOff.Count -or $gaps.LogonUnknown.Count -or $gaps.KerbUnknown.Count -or
                      $gaps.CredValUnknown.Count -or $gaps.Partial.Count -or $outside.Count -or -not $dcs.Count)

    [pscustomobject]@{
        Total        = $all.Count
        InScope      = $inScope.Count
        OutOfScope   = $outside.Count
        ExcludedForeign = [int]$Topology.ExcludedForeign
        StrictScope     = [bool]$Topology.StrictScope
        Enrolled     = $enrolled.Count
        Reserved     = $reserved.Count
        Pending      = $pending.Count
        Clear        = $clear.Count
        Blocked      = $blocked.Count
        Proven       = @($clear | Where-Object { $_.Confidence -eq 'Proven' }).Count
        Plausible    = @($clear | Where-Object { $_.Confidence -eq 'Plausible' }).Count
        Unknown      = @($clear | Where-Object { $_.Confidence -eq 'Unknown' }).Count
        Controllers  = $dcs.Count
        Gaps         = $gaps
        KrbtgtBad    = $krbtgtBad
        KdcRc4Events = $kdcRc4
        HasGaps      = $hasGaps
        ExitCode     = if ($blocked.Count) { 1 } elseif ($hasGaps) { 2 } else { 0 }
    }
}

# The machine's own domain, for the `net group /domain` fallback. Looked up once;
# empty when this box is not domain-joined (or not on Windows at all).
$script:ADPULocalDomain = $null
try { $script:ADPULocalDomain = [string][DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name } catch { }

function Get-ADPUEnrolCommand {
    <#
        The RSAT form first, because it is the one people know - and a fallback
        that needs nothing installed, since the analyzer itself deliberately does
        not require RSAT and is often run straight on a controller. The rollback is
        printed alongside on purpose: knowing how to get back out is part of
        enrolling safely.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Account,
        # The domain `net group /domain` actually reaches: the one of the machine
        # it runs on. Defaults to this machine's domain.
        [string]$LocalDomain = $script:ADPULocalDomain
    )

    $sam = ([string]$Account.Sam) -replace "'", "''"
    $dom = ([string]$Account.Domain) -replace "'", "''"
    # `net group ... /domain` always talks to the primary domain of the machine it
    # runs on. For an account homed anywhere else it would fail - or worse, hit
    # a same-named account in the wrong domain - so it is not offered as-is.
    $local  = (-not $LocalDomain) -or ([string]$Account.Domain -ieq $LocalDomain)
    $noRsat = if ($local) {
        "net group ""Protected Users"" ""$([string]$Account.Sam)"" /add /domain"
    } else {
        "# $([string]$Account.Domain)\$([string]$Account.Sam): run  net group ""Protected Users"" ""$([string]$Account.Sam)"" /add /domain  on a machine joined to $([string]$Account.Domain)"
    }
    [pscustomobject]@{
        Rsat     = "Add-ADGroupMember -Identity 'Protected Users' -Members '$sam' -Server '$dom'"
        NoRsat   = $noRsat
        Rollback = "Remove-ADGroupMember -Identity 'Protected Users' -Members '$sam' -Server '$dom' -Confirm:`$false"
    }
}

#  ==========================================================================
#  >> Walkthrough (present the findings)
#  ==========================================================================

function Get-ADPUCoverageNotes {
    <#
        .SYNOPSIS
            Turns the coverage gaps into sentences an admin can act on.
        .DESCRIPTION
            Built once and rendered by both the console and the HTML, because the
            two drifting apart is how a report starts contradicting itself.

            The important nuance this exists for: NTLM is watched by two
            independent subcategories, and both findings used to be announced as
            plain "NTLM". Reading "NTLM was not recorded" three lines above an
            account blocked for NTLM is a fair reason to distrust the whole
            report - so each note now names its own event and says explicitly
            what the other source still covers.
        .OUTPUTS
            Objects with .Severity ('bad'/'warn'/'sub') and .Text.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Summary,
        [Parameter(Mandatory)] $Topology
    )

    $out = [System.Collections.Generic.List[object]]::new()
    $add = { param([string]$sev, [string]$txt) $out.Add([pscustomobject]@{ Severity = $sev; Text = $txt }) }
    $g   = $Summary.Gaps
    $n   = { param($x) @($x).Count }

    $reach = @($Topology.Controllers | Where-Object { $_.Reachable }).Count

    if (& $n $g.Unreachable) {
        & $add 'bad' ("{0} controller(s) could not be read at all - anything that only happened there is invisible to this review." -f (& $n $g.Unreachable))
    }
    if ($g.ContainsKey('Partial') -and (& $n $g.Partial)) {
        & $add 'bad' ("{0} controller(s) were only partly read - the log harvest hit its row cap or the reader failed part-way. Findings from there are real, but a clean result is not; the per-controller notes say which source." -f (& $n $g.Partial))
    }
    if (& $n $g.AuditUnreadable) {
        & $add 'bad' ("{0} controller(s) would not report their audit policy at all - that is a rights or auditpol problem, not proof that auditing is off. Check the per-controller detail before changing any policy." -f (& $n $g.AuditUnreadable))
    }

    # ---- NTLM: two sources, and they cover different ground -------------------
    $logonOn = $reach - (& $n $g.LogonOff)   - (& $n $g.LogonUnknown)
    $credOn  = $reach - (& $n $g.CredValOff) - (& $n $g.CredValUnknown)
    $ntlmAffected = (& $n $g.LogonOff) -or (& $n $g.LogonUnknown) -or (& $n $g.CredValOff) -or (& $n $g.CredValUnknown)

    if ($ntlmAffected) {
        & $add 'sub' 'NTLM is watched by two independent subcategories: event 4624 (Audit Logon) sees NTLM aimed at a controller itself, event 4776 (Credential Validation) sees NTLM anywhere in the domain, including against member servers. One being off does not blind the other - findings below name the event they came from.'
    }

    if (& $n $g.LogonOff) {
        $t = "{0} controller(s) have Audit Logon switched off - event 4624 was not recorded there, so NTLM aimed directly at those controllers is invisible." -f (& $n $g.LogonOff)
        $t += if ($credOn -gt 0) {
            " Credential Validation is still on for {0} controller(s), and that is the broader of the two - NTLM use is still being detected. This gap costs detail, not detection." -f $credOn
        } else {
            ' Credential Validation is not covering it either, so there is no NTLM evidence at all.'
        }
        & $add 'warn' $t
    }
    if (& $n $g.LogonUnknown) {
        & $add 'warn' ("{0} controller(s) did not report their Audit Logon setting - unknown rather than off, and treated as no 4624 evidence." -f (& $n $g.LogonUnknown))
    }
    if (& $n $g.CredValOff) {
        $t = "{0} controller(s) have Credential Validation switched off - event 4776 was not recorded there, so NTLM against member servers and workstations was not seen." -f (& $n $g.CredValOff)
        $t += if ($logonOn -gt 0) {
            " Audit Logon still covers {0} controller(s), but 4624 only sees NTLM aimed at a controller - this is the bigger of the two blind spots." -f $logonOn
        } else {
            ' Audit Logon is off as well, so there is no NTLM evidence at all.'
        }
        & $add 'warn' $t
    }
    if (& $n $g.CredValUnknown) {
        & $add 'warn' ("{0} controller(s) did not report their Credential Validation setting - unknown rather than off, and treated as no 4776 evidence." -f (& $n $g.CredValUnknown))
    }

    # ---- Kerberos --------------------------------------------------------------
    if (& $n $g.KerbOff) {
        & $add 'warn' ("{0} controller(s) have Kerberos Authentication Service auditing switched off - event 4768 was not recorded there, so DES/RC4 use and account key material are missing, not clean." -f (& $n $g.KerbOff))
    }
    if (& $n $g.KerbUnknown) {
        & $add 'warn' ("{0} controller(s) did not report their Kerberos Authentication Service setting - unknown rather than off." -f (& $n $g.KerbUnknown))
    }
    if (& $n $g.OldKerb) {
        & $add 'warn' ("{0} controller(s) predate the newer 4768 fields (Server 2019+, or 2016 with the January 2025 update) - AES key material cannot be confirmed there, so the password-age fallback is used instead, and the DES/RC4 reading is weaker." -f (& $n $g.OldKerb))
    }

    foreach ($d in @($Summary.KrbtgtBad)) {
        & $add 'bad' ("krbtgt in {0} has no AES keys. Fix that first: until it is reset, every DES/RC4 finding in that domain is a domain-wide artefact rather than a statement about any single account." -f $d.Name)
    }
    if ($Summary.KdcRc4Events) {
        & $add 'warn' ("The KDCs logged {0} RC4-deprecation warning(s) (System log, Kerberos-KDC 201-209) inside the window - worth reading regardless of Protected Users." -f $Summary.KdcRc4Events)
    }
    if ($Summary.OutOfScope) {
        & $add 'warn' ("{0} privileged member(s) are homed in a domain that was not reviewed - listed separately and deliberately not judged. Pass -StrictScope to leave them out altogether." -f $Summary.OutOfScope)
    }

    $out
}

function Show-ADPUReadinessReport {
    <#
        .SYNOPSIS
            Renders the guided Protected Users readiness walkthrough.
        .DESCRIPTION
            Outcome first: the bottom line, then what can be enrolled now, then what
            is blocked and why, then the side effects nobody can read out of the
            directory, and finally the environment that decided how much of this
            could be seen at all.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Topology)

    $s       = Get-ADPUSummary -Topology $Topology
    $named   = { param($a) '{0}\{1}' -f $a.Domain, $a.Sam }
    $sorted  = @($Topology.Accounts | Sort-Object Domain, Sam)
    $outside = @($sorted | Where-Object { $_.OutOfScope })
    $inScope = @($sorted | Where-Object { -not $_.OutOfScope })
    $isRes   = { param($x) [bool]($x.PSObject.Properties['Reserved'] -and $x.Reserved) }
    $reserved = @($inScope | Where-Object { & $isRes $_ })
    $clear   = @($inScope | Where-Object { -not $_.Enrolled -and $_.ClearNow })
    $blocked = @($inScope | Where-Object { -not $_.Enrolled -and -not $_.ClearNow -and -not (& $isRes $_) })
    $already = @($inScope | Where-Object { $_.Enrolled })
    $window  = [int]$Topology.LookbackDays

    # ===== 1. Bottom line ====================================================
    Write-ADPULine head 'Summary'
    $idList = @(Get-ADPUField $Topology 'Identity' | Where-Object { $_ })
    if ($idList.Count) {
        Write-ADPULine sub  ("Reviewing the account(s) given with -Identity: {0}. Admin group membership is not required." -f ($idList -join ', '))
    } else {
        Write-ADPULine sub  ("Privileged = recursive membership of the {0} group set." -f $Topology.Scope.ToLowerInvariant())
    }
    Write-ADPULine sub  'Real user accounts belong in Protected Users; computer, service and managed accounts do not.'
    Write-ADPULine sub  ('Clear = no blocker found in the last {0} day(s) of the logs that could be read. Each verdict is itemised below.' -f $window)
    Write-ADPULine note ("{0} privileged account(s) in total." -f $s.Total)
    Write-ADPULine note ("{0} already enrolled, {1} still outside the group." -f $s.Enrolled, $s.Pending)
    if ($s.Reserved) {
        Write-ADPULine note ("{0} break-glass account(s) kept outside on purpose." -f $s.Reserved)
    }
    Write-ADPULine note ("{0} of the {1} pending account(s) are clear to enrol right now." -f $s.Clear, $s.Pending)
    if ($s.Clear) {
        Write-ADPULine sub ("of those: {0} proven, {1} plausible, {2} unknown (the checks could not look)." -f $s.Proven, $s.Plausible, $s.Unknown)
    }

    foreach ($note in (Get-ADPUCoverageNotes -Summary $s -Topology $Topology)) {
        switch ($note.Severity) {
            'bad'   { Write-ADPULine bad  $note.Text }
            'warn'  { Write-ADPULine warn $note.Text }
            default { Write-ADPULine sub  $note.Text }
        }
    }
    Wait-ADPUEnter

    # ===== 2. Action list first ==============================================
    Write-ADPULine head 'Clear to enrol now'
    if (-not $s.Pending) {
        Write-ADPULine good 'Nothing pending - every privileged account is already enrolled.'
    } elseif ($clear) {
        Write-ADPULine sub 'Each account lists the evidence its verdict rests on.'
        foreach ($a in $clear) {
            $tag = switch ($a.Confidence) {
                'Proven'    { 'proven' }
                'Plausible' { 'plausible - nothing was positively confirmed' }
                default     { 'UNKNOWN - the checks could not look; treat with care' }
            }
            Write-ADPULine good ('{0}   [{1}]' -f (& $named $a), $tag)
            foreach ($r in @($a.Evidence)) {
                if ($r.Severity -eq 'warn') { Write-ADPULine warn ('   ' + $r.Text) }
                else                        { Write-ADPULine sub  ('  - ' + $r.Text) }
            }
            foreach ($h in @($a.Hints)) { Write-ADPULine warn ('   hint: ' + $h.Text) }
        }
        Write-Host ''
        Write-ADPULine sub 'Enrolment commands (RSAT):'
        foreach ($a in $clear) { Write-ADPULine snippet (Get-ADPUEnrolCommand -Account $a).Rsat }
        Write-Host ''
        Write-ADPULine sub 'Same thing without RSAT (net group only reaches the domain of the machine it runs on):'
        foreach ($a in $clear) { Write-ADPULine snippet (Get-ADPUEnrolCommand -Account $a).NoRsat }
        Write-Host ''
        Write-ADPULine sub 'And the way back out, should a sign-in break:'
        foreach ($a in $clear) { Write-ADPULine snippet (Get-ADPUEnrolCommand -Account $a).Rollback }
        Write-Host ''
        Write-ADPULine tip 'Use an account allowed to change the group. New to this? Enrol one, prove it still works end to end, then do the rest.'
    } else {
        Write-ADPULine note 'Nothing is clear to enrol yet - work through the blockers below first.'
    }
    Wait-ADPUEnter

    # ===== 3. Blocked accounts, per account ==================================
    if ($blocked) {
        Write-ADPULine head 'Still blocked - per account'
        Write-ADPULine sub  'Each account lists only what is holding it back.'
        foreach ($a in $blocked) {
            Write-ADPULine note (& $named $a)
            foreach ($b in @($a.Blockers)) { Write-ADPULine bad ('   ' + $b.Text) }
            foreach ($h in @($a.Hints | Where-Object { $_.Code -eq 'WeakKerbUnreliable' })) {
                Write-ADPULine warn ('   ' + $h.Text)
            }
        }
        Wait-ADPUEnter
    }

    # ===== 3b. Break-glass, kept outside on purpose ==========================
    if ($reserved) {
        Write-ADPULine head 'Kept outside on purpose (break-glass)'
        Write-ADPULine sub  'Emergency admin accounts stay out of Protected Users, so an unforeseen side effect cannot lock out every administrator at once. The built-in Administrator (RID 500) always counts; -BreakGlass adds more.'
        foreach ($a in $reserved) {
            Write-ADPULine note (& $named $a)
            foreach ($b in @($a.Blockers)) { Write-ADPULine sub ('   would also be blocked by: ' + $b.Text) }
        }
        Write-ADPULine tip 'Protect these another way: a long random password in a safe, no day-to-day use, and an alert on every logon.'
        Wait-ADPUEnter
    }

    # ===== 4. Already enrolled ===============================================
    Write-ADPULine head 'Already enrolled'
    if ($already) {
        foreach ($a in $already) {
            Write-ADPULine good (& $named $a)
            foreach ($h in @($a.Hints | Where-Object { $_.Code -eq 'NtlmWhileEnrolled' })) { Write-ADPULine warn ('   ' + $h.Text) }
        }
    }
    else          { Write-ADPULine note 'None yet.' }
    Wait-ADPUEnter

    # ===== 4b. Privileged here, homed elsewhere ==============================
    # One line each. This is a pointer to work that belongs in another run, not
    # a findings list - the per-account detail lives in the HTML and the JSON.
    if ($outside) {
        Write-ADPULine head 'Privileged here, but homed elsewhere'
        Write-ADPULine sub  'Members of a reviewed domain''s privileged groups whose own domain was not part of this run. Not judged: a same-named account in another domain is a different account.'
        foreach ($a in $outside) {
            Write-ADPULine warn ('{0}\{1}   (via {2}: {3})' -f $a.Domain, $a.Sam, $a.FoundVia, (@($a.ViaGroups) -join ', '))
        }
        Write-ADPULine tip ("Re-run including {0} to judge these properly - or pass -StrictScope to leave them out of the report entirely." -f ((@($outside.Domain) | Sort-Object -Unique) -join ', '))
        Wait-ADPUEnter
    } elseif ($s.ExcludedForeign) {
        Write-ADPULine head 'Privileged here, but homed elsewhere'
        Write-ADPULine sub  ("{0} member(s) of this domain's privileged groups are homed in a domain that was not reviewed. -StrictScope was given, so they were left out of everything above." -f $s.ExcludedForeign)
        Wait-ADPUEnter
    }

    # ===== 5. Hardening hints ================================================
    # In-scope accounts only. The ones homed elsewhere already have their own
    # section, and repeating them here made five of nine entries duplicates of
    # something the reader had just been told not to act on.
    $hinted = @($inScope | Where-Object { @($_.Hints).Count })
    Write-ADPULine head 'Hardening hints (informational)'
    Write-ADPULine sub  'Side observations, unrelated to the enrol decision - worth a look, but they block nothing.'
    if (-not $hinted) {
        Write-ADPULine good 'Nothing flagged.'
    } else {
        foreach ($a in $hinted) {
            Write-ADPULine note (& $named $a)
            foreach ($h in @($a.Hints)) { Write-ADPULine warn ('   ' + $h.Text) }
        }
    }
    Wait-ADPUEnter

    # ===== 6. What the group changes, beyond NTLM and RC4 ====================
    Write-ADPULine head 'What enrolling actually changes'
    Write-ADPULine sub  'None of this can be read out of the directory, so no tool can clear you of it. Check it by hand.'
    foreach ($line in $script:ADPUSideEffects) { Write-ADPULine warn $line }
    Wait-ADPUEnter

    # ===== 7. Environment prerequisites, grouped by domain ===================
    Write-ADPULine head 'Environment - foundation (per domain)'
    Write-ADPULine sub  'These are the conditions that decide whether the group exists and whether this review could see everything.'
    $f = $Topology.Forest
    if ($f.ReadyFL) {
        Write-ADPULine good ("Forest {0} at {1} - the group is available forest-wide." -f $f.Name, (Get-ADPULevelName $f.ModeLevel))
    } else {
        Write-ADPULine warn ("Forest {0} at {1} - group availability is decided per domain (below)." -f $f.Name, (Get-ADPULevelName $f.ModeLevel))
    }
    Write-Host ''

    foreach ($d in @($Topology.Domains)) {
        $lvl = Get-ADPULevelName $d.ModeLevel
        if ($d.PugPresent -and $d.ReadyFL) {
            Write-ADPULine good "Domain $($d.Name) ($lvl): group present; full client- and DC-side cover inside the domain."
        } elseif ($d.PugPresent) {
            Write-ADPULine warn "Domain $($d.Name) ($lvl): group present, level too low for DC-side cover (client-side only)."
        } else {
            Write-ADPULine bad  "Domain $($d.Name) ($lvl): no Protected Users group - move the PDC emulator onto a 2012 R2+ controller to create it."
        }

        if ($d.Krbtgt -and $d.Krbtgt.Readable) {
            if ($d.Krbtgt.HasAes -eq $false) {
                Write-ADPULine bad  ('   krbtgt has an explicit encryption-type mask of 0x{0:X}, which permits no AES - reset it twice before reading anything into the DES/RC4 findings.' -f [int]$d.Krbtgt.EncTypes)
            } elseif ($d.Krbtgt.HasAes -eq $true) {
                Write-ADPULine good ('   krbtgt is explicitly configured for AES (msDS-SupportedEncryptionTypes = 0x{0:X}).' -f [int]$d.Krbtgt.EncTypes)
            } else {
                $shown = if ($null -eq $d.Krbtgt.EncTypes) { 'not set' } else { '0x{0:X}' -f [int]$d.Krbtgt.EncTypes }
                Write-ADPULine sub ('   krbtgt has no encryption types configured (msDS-SupportedEncryptionTypes {0}), so the KDC default applies - that includes AES from the 2008 functional level, and this domain is at {1}. Normal.' -f $shown, (Get-ADPULevelName $d.ModeLevel))
            }
            if ($d.Krbtgt.PwdLastSet -is [datetime]) {
                $age = [int]((Get-Date) - $d.Krbtgt.PwdLastSet).TotalDays
                $msg = '   krbtgt password last set {0:yyyy-MM-dd} ({1} days ago).' -f $d.Krbtgt.PwdLastSet, $age
                if ($age -gt 3650) {
                    Write-ADPULine warn ($msg + ' If that predates the day this domain reached the 2008 functional level, it has no AES keys regardless of the attribute above - a double reset is the fix, and it is overdue on age alone.')
                } elseif ($age -gt 400) {
                    Write-ADPULine warn ($msg + ' Rotating it periodically is good hygiene.')
                } else {
                    Write-ADPULine sub $msg
                }
            }
        }

        $dcs = @($Topology.Controllers | Where-Object { $_.DomainName -ieq $d.Name })
        if (-not $dcs.Count) { Write-ADPULine warn '   no controller could be listed in this domain - nothing was inspected here.' }
        $needFix = [System.Collections.Generic.List[object]]::new()
        foreach ($dc in ($dcs | Sort-Object Name)) {
            if (-not $dc.Reachable) {
                Write-ADPULine bad "   $($dc.Name): unreachable ($($dc.Error)) - contributed nothing."
                continue
            }
            $osText = if ($dc.OSOk) { "OS $($dc.OSVersion) ok" } else { "OS $($dc.OSVersion) too old" }
            $full = $dc.AuditLogonOk -and $dc.AuditKerbOk -and $dc.AuditCredValOk
            $line = "   $($dc.Name): $osText, 4768 $(if ($dc.NewKerbFields) { 'v2' } else { 'legacy' })."
            if     ($dc.OSOk -and $full) { Write-ADPULine good $line }
            elseif ($full)               { Write-ADPULine warn $line }
            else                         { Write-ADPULine bad  $line }

            # The exact setting auditpol reported, verbatim. Without it, "off" is
            # something you have to take on trust - and a failed read looks the
            # same as a policy decision.
            foreach ($sc in @(
                @{ Key = 'Logon';   Label = 'Logon (4624)' }
                @{ Key = 'KerbAS';  Label = 'Kerberos AS (4768)' }
                @{ Key = 'CredVal'; Label = 'Credential Validation (4776)' })) {
                $st  = if ($dc.AuditState) { [string]$dc.AuditState[$sc.Key] } else { 'Unknown' }
                $raw = if ($dc.AuditRaw)   { [string]$dc.AuditRaw[$sc.Key] }   else { $null }
                $shown = if ($raw) { $raw } else { '(nothing reported)' }
                $txt = "      {0,-32} {1,-8} auditpol says: {2}" -f $sc.Label, $st.ToLowerInvariant(), $shown
                switch ($st) {
                    'On'  { Write-ADPULine sub  $txt }
                    'Off' { Write-ADPULine warn $txt }
                    default { Write-ADPULine bad $txt }
                }
            }
            Write-ADPULine sub ("      read via: {0}" -f $dc.AuditMethod)

            foreach ($n in @($dc.Notes)) { Write-ADPULine sub ("      note: $n") }
            foreach ($k in @($dc.KdcRc4)) {
                Write-ADPULine warn ("      KDC RC4 warning {0}: {1}x, last {2:yyyy-MM-dd HH:mm}" -f $k.Id, $k.Count, $k.Last)
            }

            if (-not $full) { [void]$needFix.Add($dc) }
        }

        # Asked once for the domain, not once per controller: three identical
        # prompts in a row is just something to click through.
        if ($needFix.Count) {
            $missing = @(
                if (@($needFix | Where-Object { -not $_.AuditLogonOk }).Count)   { 'Logon' }
                if (@($needFix | Where-Object { -not $_.AuditKerbOk }).Count)    { 'KerbAS' }
                if (@($needFix | Where-Object { -not $_.AuditCredValOk }).Count) { 'CredVal' }
            )
            $q = "   Show the auditpol command(s) for the {0} controller(s) in {1} with auditing missing?" -f $needFix.Count, $d.Name
            if (Read-ADPUYesNo $q) {
                foreach ($dc in $needFix) {
                    Write-ADPULine sub ("      {0}" -f $dc.Name)
                    if (-not $dc.AuditLogonOk) {
                        Write-ADPULine snippet ("Invoke-Command -ComputerName {0} -ScriptBlock {{ auditpol /set /subcategory:{1} /success:enable /failure:enable }}" -f $dc.Name, $script:ADPUAuditGuid.Logon)
                    }
                    if (-not $dc.AuditKerbOk) {
                        Write-ADPULine snippet ("Invoke-Command -ComputerName {0} -ScriptBlock {{ auditpol /set /subcategory:{1} /success:enable }}" -f $dc.Name, $script:ADPUAuditGuid.KerbAS)
                    }
                    if (-not $dc.AuditCredValOk) {
                        Write-ADPULine snippet ("Invoke-Command -ComputerName {0} -ScriptBlock {{ auditpol /set /subcategory:{1} /success:enable }}" -f $dc.Name, $script:ADPUAuditGuid.CredVal)
                    }
                }
                if ($missing.Count) {
                    Write-ADPULine tip ('Same three settings by GPO, which is what makes them stick: Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration.')
                }
                Write-ADPULine tip 'Subcategories are addressed by GUID, so the command works on any system language.'
                Write-ADPULine tip 'Auditing is not retroactive - re-run this review after a few weeks of normal operation.'
            }
        }
        Write-Host ''
    }
    Wait-ADPUEnter
}

#  ==========================================================================
#  >> HTML report (same findings, as a standalone web page)
#  ==========================================================================

function ConvertTo-ADPUHtmlText {
    param([object]$Value)
    $x = [string]$Value
    $x.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
}

function Export-ADPUHtmlReport {
    <#
        .SYNOPSIS
            Writes the readiness findings to a self-contained HTML file.
        .DESCRIPTION
            Same data as the console walkthrough, rendered from the same Blockers /
            Hints / Evidence lists, so the two cannot describe an account
            differently. One file, inline CSS, no dependencies.
        .OUTPUTS
            The full path of the written file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)] $Topology,
        [Parameter(Mandatory, Position = 1)] [string]$Path
    )

    $s        = Get-ADPUSummary -Topology $Topology
    $sorted   = @($Topology.Accounts | Sort-Object Domain, Sam)
    $outside  = @($sorted | Where-Object { $_.OutOfScope })
    $inScope  = @($sorted | Where-Object { -not $_.OutOfScope })
    $isRes    = { param($x) [bool]($x.PSObject.Properties['Reserved'] -and $x.Reserved) }
    $reserved = @($inScope | Where-Object { & $isRes $_ })
    $clear    = @($inScope | Where-Object { -not $_.Enrolled -and $_.ClearNow })
    $blocked  = @($inScope | Where-Object { -not $_.Enrolled -and -not $_.ClearNow -and -not (& $isRes $_) })
    $already  = @($inScope | Where-Object { $_.Enrolled })
    # In-scope only, as on the console: out-of-scope members have their own table
    # (with their observations), and listing them twice contradicted the advice
    # not to act on them here.
    $hinted   = @($inScope | Where-Object { @($_.Hints).Count })
    $now      = if ($Topology.Generated) { $Topology.Generated } else { Get-Date }

    $css = @'
:root{color-scheme:light dark;--bg:#f4f5f7;--fg:#1f2430;--card:#fff;--line:#e3e6ea;--mut:#6b7280;
--good:#15803d;--warn:#b45309;--bad:#b91c1c;--info:#1d4ed8;--codebg:#1f2430;--codefg:#e7e9ee}
@media (prefers-color-scheme:dark){:root{--bg:#161a22;--fg:#e6e9ef;--card:#1e232c;--line:#2c333f;
--mut:#9aa1ad;--good:#4ade80;--warn:#fbbf24;--bad:#f87171;--info:#93c5fd;--codebg:#11151b;--codefg:#e7e9ee}}
*{box-sizing:border-box}
body{font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:var(--bg);color:var(--fg);line-height:1.45}
header{background:#2b2f3a;color:#fff;padding:24px 28px}
header h1{margin:0;font-size:22px;letter-spacing:.5px}
.muted{color:var(--mut)}
header .muted{color:#c8ccd4}
main,section{padding:0 28px}
h2{margin:28px 0 8px;font-size:17px;border-bottom:2px solid var(--line);padding-bottom:6px}
h3{margin:18px 0 4px;font-size:14px}
.cards{display:flex;flex-wrap:wrap;gap:14px;padding:20px 28px 0}
.card{flex:1 1 150px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card .num{font-size:26px;font-weight:700}
.card .lbl{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.4px}
.card.good .num{color:var(--good)}.card.warn .num{color:var(--warn)}.card.ok .num{color:var(--info)}
.card.bad .num{color:var(--bad)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden;margin:6px 0 4px}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);font-size:13px;vertical-align:top}
th{background:rgba(127,127,127,.10);font-weight:600}
tr:last-child td{border-bottom:none}
td.ok{color:var(--good)}td.bad{color:var(--bad)}td.warn{color:var(--warn)}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;margin:1px 2px;white-space:nowrap;border:1px solid transparent}
.badge.bad{background:rgba(185,28,28,.12);color:var(--bad);border-color:rgba(185,28,28,.3)}
.badge.warn{background:rgba(180,83,9,.12);color:var(--warn);border-color:rgba(180,83,9,.3)}
.badge.good{background:rgba(21,128,61,.12);color:var(--good);border-color:rgba(21,128,61,.3)}
p.good{color:var(--good)}p.warn{color:var(--warn)}p.bad{color:var(--bad)}
ul.why{margin:0;padding-left:16px}
ul.why li{font-size:12px;color:var(--mut);margin:1px 0}
ul.why li.warn{color:var(--warn)}
ul.plain{margin:6px 0;padding-left:18px}
ul.plain li{font-size:13px;margin:3px 0}
.banner{padding:10px 14px;border-radius:8px;margin:14px 0;border:1px solid}
.banner.warn{background:rgba(180,83,9,.10);color:var(--warn);border-color:rgba(180,83,9,.35)}
.banner.bad{background:rgba(185,28,28,.10);color:var(--bad);border-color:rgba(185,28,28,.35)}
pre{background:var(--codebg);color:var(--codefg);border-radius:8px;padding:12px 14px;overflow:auto;font-size:12.5px}
code{font-family:Consolas,Monaco,monospace}
button.copy{font:inherit;font-size:12px;padding:4px 10px;margin:4px 0 0;border:1px solid var(--line);
background:var(--card);color:var(--fg);border-radius:6px;cursor:pointer}
footer{padding:20px 28px 32px;color:var(--mut);font-size:12px}
'@

    $js = @'
document.addEventListener('click',function(e){
  var b=e.target.closest('button.copy'); if(!b) return;
  var pre=document.getElementById(b.dataset.target); if(!pre) return;
  navigator.clipboard.writeText(pre.innerText).then(function(){
    var t=b.textContent; b.textContent='Copied'; setTimeout(function(){b.textContent=t;},1200);
  });
});
'@

    $sb  = [System.Text.StringBuilder]::new()
    $add = { param([string]$x) [void]$sb.AppendLine($x) }
    $enc = { param($x) ConvertTo-ADPUHtmlText $x }

    & $add '<!DOCTYPE html>'
    & $add '<html lang="en"><head><meta charset="utf-8">'
    & $add '<meta name="viewport" content="width=device-width, initial-scale=1">'
    & $add ('<title>ADPU-Analyzer - {0}</title>' -f (& $enc $Topology.Forest.Name))
    & $add ('<style>{0}</style>' -f $css)
    & $add '</head><body>'

    $idList     = @(Get-ADPUField $Topology 'Identity' | Where-Object { $_ })
    $scopeLabel = if ($idList.Count) { '-Identity ' + ($idList -join ', ') + ' -' } else { $Topology.Scope }
    & $add '<header><h1>ADPU-Analyzer</h1>'
    & $add ('<p class="muted">Forest <strong>{0}</strong> &middot; {1} scope &middot; {2}-day window &middot; generated {3:yyyy-MM-dd HH:mm} &middot; Made by Carbon/Nobrac</p>' -f
            (& $enc $Topology.Forest.Name), (& $enc $scopeLabel), [int]$Topology.LookbackDays, $now)
    & $add '</header><main>'

    & $add '<section class="cards">'
    & $add ('<div class="card"><div class="num">{0}</div><div class="lbl">privileged accounts</div></div>' -f $s.Total)
    & $add ('<div class="card good"><div class="num">{0}</div><div class="lbl">already enrolled</div></div>' -f $s.Enrolled)
    & $add ('<div class="card ok"><div class="num">{0}</div><div class="lbl">clear to enrol now</div></div>' -f $s.Clear)
    & $add ('<div class="card bad"><div class="num">{0}</div><div class="lbl">blocked</div></div>' -f $s.Blocked)
    & $add ('<div class="card warn"><div class="num">{0}</div><div class="lbl">clear but unproven</div></div>' -f ($s.Plausible + $s.Unknown))
    & $add '</section>'

    $notes = @(Get-ADPUCoverageNotes -Summary $s -Topology $Topology)
    if ($notes.Count) {
        & $add '<section>'
        foreach ($note in $notes) {
            if ($note.Severity -eq 'sub') {
                & $add ('<p class="muted">{0}</p>' -f (& $enc $note.Text))
            } else {
                & $add ('<p class="banner {0}">{1}</p>' -f $note.Severity, (& $enc $note.Text))
            }
        }
        & $add '</section>'
    }

    & $add '<section><h2>Clear to enrol now</h2>'
    if ($clear.Count) {
        & $add '<table><thead><tr><th>Domain</th><th>Account</th><th>Confidence</th><th>Why it is clear</th></tr></thead><tbody>'
        foreach ($a in $clear) {
            $why = @(foreach ($r in @($a.Evidence)) {
                $cls = if ($r.Severity -eq 'warn') { ' class="warn"' } else { '' }
                '<li{0}>{1}</li>' -f $cls, (& $enc $r.Text)
            })
            $cc = switch ($a.Confidence) { 'Proven' { 'good' } 'Plausible' { 'warn' } default { 'bad' } }
            & $add ('<tr><td>{0}</td><td>{1}</td><td><span class="badge {2}">{3}</span></td><td><ul class="why">{4}</ul></td></tr>' -f
                    (& $enc $a.Domain), (& $enc $a.Sam), $cc, (& $enc $a.Confidence), ($why -join ''))
        }
        & $add '</tbody></table>'

        $blocks = @(
            @{ Id = 'cmd-rsat';     Title = 'Enrolment commands (RSAT)';         Sel = 'Rsat' }
            @{ Id = 'cmd-norsat';   Title = 'Without RSAT (reaches only the local machine&#39;s domain)';   Sel = 'NoRsat' }
            @{ Id = 'cmd-rollback'; Title = 'Rollback, if a sign-in breaks';     Sel = 'Rollback' }
        )
        foreach ($b in $blocks) {
            & $add ('<h3>{0}</h3>' -f $b.Title)
            & $add ('<pre id="{0}"><code>' -f $b.Id)
            foreach ($a in $clear) { & $add (& $enc (Get-ADPUEnrolCommand -Account $a).($b.Sel)) }
            & $add '</code></pre>'
            & $add ('<button class="copy" data-target="{0}">Copy</button>' -f $b.Id)
        }
    } elseif (-not $s.Pending) {
        & $add '<p class="good">Every privileged account is already enrolled.</p>'
    } else {
        & $add '<p class="muted">Nothing is clear yet - resolve the blockers below first.</p>'
    }
    & $add '</section>'

    if ($blocked.Count) {
        & $add '<section><h2>Still blocked</h2>'
        & $add '<table><thead><tr><th>Domain</th><th>Account</th><th>Blockers</th></tr></thead><tbody>'
        foreach ($a in $blocked) {
            $items = @(foreach ($b in @($a.Blockers)) { '<li>{0}</li>' -f (& $enc $b.Text) })
            & $add ('<tr><td>{0}</td><td>{1}</td><td><ul class="why">{2}</ul></td></tr>' -f
                    (& $enc $a.Domain), (& $enc $a.Sam), ($items -join ''))
        }
        & $add '</tbody></table></section>'
    }

    if ($outside.Count) {
        & $add '<section><h2>Privileged here, but homed elsewhere</h2>'
        & $add '<p class="muted">Members of a reviewed domain&#39;s privileged groups whose own domain was not part of this run. No log evidence is attributed to them - a same-named account in another domain is a different account.</p>'
        & $add '<table><thead><tr><th>Home domain</th><th>Account</th><th>Privileged in</th><th>Via</th><th>Observations</th></tr></thead><tbody>'
        foreach ($a in $outside) {
            $obs = @(foreach ($h in @($a.Hints | Where-Object { $_.Code -ne 'OutOfScope' })) { '<li class="warn">{0}</li>' -f (& $enc $h.Text) })
            & $add ('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td><ul class="why">{4}</ul></td></tr>' -f
                    (& $enc $a.Domain), (& $enc $a.Sam), (& $enc $a.FoundVia),
                    (& $enc ((@($a.ViaGroups)) -join ', ')), ($obs -join ''))
        }
        & $add '</tbody></table></section>'
    } elseif ($s.ExcludedForeign) {
        & $add ('<section><p class="muted">{0} privileged member(s) homed in an unreviewed domain were left out of this report (-StrictScope).</p></section>' -f $s.ExcludedForeign)
    }

    if ($reserved.Count) {
        & $add '<section><h2>Kept outside on purpose (break-glass)</h2>'
        & $add '<p class="muted">Emergency admin accounts stay out of Protected Users, so an unforeseen side effect cannot lock out every administrator at once. The built-in Administrator (RID 500) always counts; -BreakGlass adds more.</p>'
        & $add '<table><thead><tr><th>Domain</th><th>Account</th><th>Would also be blocked by</th></tr></thead><tbody>'
        foreach ($a in $reserved) {
            $items = @(foreach ($b in @($a.Blockers)) { '<li>{0}</li>' -f (& $enc $b.Text) })
            & $add ('<tr><td>{0}</td><td>{1}</td><td><ul class="why">{2}</ul></td></tr>' -f
                    (& $enc $a.Domain), (& $enc $a.Sam), ($items -join ''))
        }
        & $add '</tbody></table></section>'
    }

    & $add '<section><h2>Already enrolled</h2>'
    if ($already.Count) {
        & $add '<table><thead><tr><th>Domain</th><th>Account</th></tr></thead><tbody>'
        foreach ($a in $already) { & $add ('<tr><td>{0}</td><td>{1}</td></tr>' -f (& $enc $a.Domain), (& $enc $a.Sam)) }
        & $add '</tbody></table>'
    } else { & $add '<p class="muted">None yet.</p>' }
    & $add '</section>'

    & $add '<section><h2>Hardening hints (informational)</h2>'
    if ($hinted.Count) {
        & $add '<table><thead><tr><th>Domain</th><th>Account</th><th>Observations</th></tr></thead><tbody>'
        foreach ($a in $hinted) {
            $items = @(foreach ($h in @($a.Hints)) { '<li class="warn">{0}</li>' -f (& $enc $h.Text) })
            & $add ('<tr><td>{0}</td><td>{1}</td><td><ul class="why">{2}</ul></td></tr>' -f
                    (& $enc $a.Domain), (& $enc $a.Sam), ($items -join ''))
        }
        & $add '</tbody></table>'
    } else { & $add '<p class="good">Nothing flagged.</p>' }
    & $add '</section>'

    & $add '<section><h2>What enrolling actually changes</h2>'
    & $add '<p class="muted">None of this can be read out of the directory, so no tool can clear you of it.</p><ul class="plain">'
    foreach ($line in $script:ADPUSideEffects) { & $add ('<li>{0}</li>' -f (& $enc $line)) }
    & $add '</ul></section>'

    & $add '<section><h2>Environment</h2>'
    $f = $Topology.Forest
    if ($f.ReadyFL) {
        & $add ('<p class="good">Forest {0} at {1} - the group is available forest-wide.</p>' -f (& $enc $f.Name), (& $enc (Get-ADPULevelName $f.ModeLevel)))
    } else {
        & $add ('<p class="warn">Forest {0} at {1} - group availability decided per domain.</p>' -f (& $enc $f.Name), (& $enc (Get-ADPULevelName $f.ModeLevel)))
    }
    foreach ($d in @($Topology.Domains)) {
        & $add ('<h3>{0} <span class="muted">({1})</span></h3>' -f (& $enc $d.Name), (& $enc (Get-ADPULevelName $d.ModeLevel)))
        if ($d.PugPresent -and $d.ReadyFL) { & $add '<p class="good">Group present; full client- and DC-side cover inside the domain.</p>' }
        elseif ($d.PugPresent)             { & $add '<p class="warn">Group present, level too low for DC-side cover (client-side only).</p>' }
        else                               { & $add '<p class="bad">No Protected Users group - move the PDC emulator onto a 2012 R2+ controller to create it.</p>' }

        if ($d.Krbtgt -and $d.Krbtgt.Readable) {
            if ($d.Krbtgt.HasAes -eq $false) {
                & $add ('<p class="bad">krbtgt has an explicit encryption-type mask of 0x{0:X}, which permits no AES.</p>' -f [int]$d.Krbtgt.EncTypes)
            } elseif ($d.Krbtgt.HasAes -eq $true) {
                & $add ('<p class="good">krbtgt is explicitly configured for AES (0x{0:X}).</p>' -f [int]$d.Krbtgt.EncTypes)
            } else {
                & $add ('<p class="muted">krbtgt has no encryption types configured, so the KDC default applies - that includes AES from the 2008 functional level, and this domain is at {0}.</p>' -f (& $enc (Get-ADPULevelName $d.ModeLevel)))
            }
            if ($d.Krbtgt.PwdLastSet -is [datetime]) {
                $age = [int]((Get-Date) - $d.Krbtgt.PwdLastSet).TotalDays
                $cls = if ($age -gt 400) { 'warn' } else { 'muted' }
                & $add ('<p class="{0}">krbtgt password last set {1:yyyy-MM-dd} ({2} days ago).</p>' -f $cls, $d.Krbtgt.PwdLastSet, $age)
            }
        }

        $dcs = @($Topology.Controllers | Where-Object { $_.DomainName -ieq $d.Name })
        if (-not $dcs.Count) { & $add '<p class="warn">No controller could be listed in this domain.</p>' }
        else {
            & $add '<table><thead><tr><th>Controller</th><th>OS</th><th>Logon (4624)</th><th>Kerberos (4768)</th><th>Cred. validation (4776)</th><th>4768 fields</th></tr></thead><tbody>'
            foreach ($dc in $dcs) {
                if (-not $dc.Reachable) {
                    & $add ('<tr><td>{0}</td><td class="bad" colspan="5">unreachable - {1}</td></tr>' -f (& $enc $dc.Name), (& $enc $dc.Error))
                    continue
                }
                # Each audit cell shows the state and, underneath, the literal
                # text auditpol returned - so "off" can be checked, not believed.
                $auditCell = {
                    param($Key)
                    $st  = if ($dc.AuditState) { [string]$dc.AuditState[$Key] } else { 'Unknown' }
                    $raw = if ($dc.AuditRaw)   { [string]$dc.AuditRaw[$Key] }   else { $null }
                    $cls = switch ($st) { 'On' { 'ok' } 'Off' { 'warn' } default { 'bad' } }
                    '<td class="{0}">{1}<br><span class="muted" style="font-size:11px">{2}</span></td>' -f
                        $cls, $st.ToLowerInvariant(), (ConvertTo-ADPUHtmlText $(if ($raw) { $raw } else { 'nothing reported' }))
                }
                & $add ('<tr><td>{0}<br><span class="muted" style="font-size:11px">via {1}</span></td><td class="{2}">{3}</td>{4}{5}{6}<td class="{7}">{8}</td></tr>' -f
                        (& $enc $dc.Name), (& $enc $dc.AuditMethod),
                        $(if ($dc.OSOk) { 'ok' } else { 'bad' }), (& $enc $dc.OSVersion),
                        (& $auditCell 'Logon'),
                        (& $auditCell 'KerbAS'),
                        (& $auditCell 'CredVal'),
                        $(if ($dc.NewKerbFields) { 'ok' } else { 'warn' }),
                        $(if ($dc.NewKerbFields) { 'v2' } else { 'legacy' }))
                $dcNotes = @($dc.Notes | Where-Object { $_ })
                if ($dcNotes.Count) {
                    & $add ('<tr><td></td><td colspan="5" class="muted" style="font-size:12px">{0}</td></tr>' -f
                            ((@($dcNotes | ForEach-Object { 'note: ' + (& $enc $_) })) -join '<br>'))
                }
            }
            & $add '</tbody></table>'
        }
    }
    & $add '</section></main>'

    & $add ('<footer>ADPU-Analyzer &middot; generated {0:yyyy-MM-dd HH:mm:ss} &middot; read-only: nothing in the directory was changed.</footer>' -f $now)
    & $add ('<script>{0}</script>' -f $js)
    & $add '</body></html>'

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $sb.ToString() | Out-File -LiteralPath $Path -Encoding UTF8
    (Resolve-Path -LiteralPath $Path).Path
}

#  ==========================================================================
#  >> JSON report (for scheduled runs, diffing and ticketing)
#  ==========================================================================

function ConvertTo-ADPUResult {
    <#
        A flat, serialisable projection of the run - no live directory objects, no
        hash sets. This is what -JsonPath writes and what -PassThru emits, so a
        scheduled run can be diffed against the previous one.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Topology)

    $s = Get-ADPUSummary -Topology $Topology

    [pscustomobject]@{
        Tool      = 'ADPU-Analyzer'
        Schema    = 3
        Generated = $Topology.Generated
        Forest    = $Topology.Forest.Name
        Scope     = $Topology.Scope
        Identity  = @(Get-ADPUField $Topology 'Identity' | Where-Object { $_ })
        StrictScope = [bool]$Topology.StrictScope
        Days      = $Topology.LookbackDays
        Summary   = [pscustomobject]@{
            Total = $s.Total; InScope = $s.InScope; OutOfScope = $s.OutOfScope
            ExcludedForeign = $s.ExcludedForeign
            Enrolled = $s.Enrolled; Reserved = $s.Reserved; Pending = $s.Pending
            Clear = $s.Clear; Blocked  = $s.Blocked
            Proven = $s.Proven; Plausible = $s.Plausible; Unknown = $s.Unknown
            HasCoverageGaps = $s.HasGaps
            ExitCode = $s.ExitCode
        }
        Domains   = @(foreach ($d in @($Topology.Domains)) {
            [pscustomobject]@{
                Name = $d.Name; Sid = $d.Sid; Level = $d.ModeLevel
                LevelName = (Get-ADPULevelName $d.ModeLevel)
                ProtectedUsersPresent = $d.PugPresent
                ProtectedUsersCreated = $d.PugBornOn
                KrbtgtHasAes = $(if ($d.Krbtgt) { $d.Krbtgt.HasAes } else { $null })
            }
        })
        Controllers = @(foreach ($dc in @($Topology.Controllers)) {
            [pscustomobject]@{
                Name = $dc.Name; Domain = $dc.DomainName; OS = $dc.OSVersion; OSOk = $dc.OSOk
                Reachable = $dc.Reachable; Error = $dc.Error
                AuditLogon = $dc.AuditLogonOk; AuditLogonFailure = [bool](Get-ADPUField $dc 'AuditLogonFailOk'); AuditKerberos = $dc.AuditKerbOk
                AuditCredentialValidation = $dc.AuditCredValOk
                AuditState = $dc.AuditState; AuditReported = $dc.AuditRaw; AuditReadVia = $dc.AuditMethod
                NewKerberosFields = $dc.NewKerbFields
                PartlyRead = $dc.AuditPartial
                KdcRc4Warnings = @($dc.KdcRc4 | ForEach-Object { [pscustomobject]@{ Id = $_.Id; Count = $_.Count; Last = $_.Last } })
                Notes = @($dc.Notes)
            }
        })
        Accounts  = @(foreach ($a in @($Topology.Accounts | Sort-Object Domain, Sam)) {
            [pscustomobject]@{
                Domain = $a.Domain; Sam = $a.Sam; Sid = $a.Sid
                DistinguishedName = $a.Dn; ObjectClass = $a.Class
                PrivilegedVia = @($a.ViaGroups); PrivilegedIn = $a.FoundVia
                OutOfScope = $a.OutOfScope
                Enrolled = $a.Enrolled; BreakGlass = $a.BreakGlass; Reserved = $a.Reserved
                Clear = $a.ClearNow; Confidence = $a.Confidence
                PasswordLastSet = $a.PwdLastSet; Enabled = $a.Enabled
                AesKeysProven = $a.AesProven
                Blockers = @($a.Blockers | ForEach-Object { [pscustomobject]@{ Code = $_.Code; Text = $_.Text } })
                Hints    = @($a.Hints    | ForEach-Object { [pscustomobject]@{ Code = $_.Code; Text = $_.Text } })
            }
        })
    }
}

function Export-ADPUJsonReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)] $Topology,
        [Parameter(Mandatory, Position = 1)] [string]$Path
    )
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    (ConvertTo-ADPUResult -Topology $Topology) | ConvertTo-Json -Depth 8 |
        Out-File -LiteralPath $Path -Encoding UTF8
    (Resolve-Path -LiteralPath $Path).Path
}

#  ==========================================================================
#  >> Post-enrolment verification (did enrolling actually break anything?)
#  ==========================================================================

# The dedicated Protected Users channels. All three are OFF by default and have to
# be switched on before they record anything - the client one lives on the
# workstation, not on a controller.
$script:ADPUDcFailureLog = 'Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController'
$script:ADPUDcSuccessLog = 'Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController'
$script:ADPUClientLog    = 'Microsoft-Windows-Authentication/ProtectedUser-Client'

$script:ADPUVerifySource = @'
param($Days, $FailureLog, $SuccessLog)

$span = [int64]$Days * 86400000

function Read-Channel {
    param([string]$Log, [int[]]$Ids)

    $out = [pscustomobject]@{ Log = $Log; Present = $false; Enabled = $false; Events = @(); ReadError = $null }
    try {
        $cfg = [Diagnostics.Eventing.Reader.EventLogConfiguration]::new($Log)
        $out.Present = $true
        $out.Enabled = [bool]$cfg.IsEnabled
    } catch {
        return $out            # channel not on this build
    }
    if (-not $out.Enabled) { return $out }

    $idPart = ($Ids | ForEach-Object { "EventID=$_" }) -join ' or '
    $filter = "*[System[($idPart) and TimeCreated[timediff(@SystemTime) <= $span]]]"
    try {
        $out.Events = @(
            Get-WinEvent -LogName $Log -FilterXPath $filter -ErrorAction Stop | ForEach-Object {
                # The account field is not in a fixed slot across these channels,
                # so pick the first Data element that looks like one.
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
        # An empty result throws rather than returning nothing - that one really
        # is "none". Anything else (access denied, a corrupt channel) is a read
        # failure and must not be reported as a clean channel.
        if ([string]$_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
            $out.ReadError = $_.Exception.Message
        }
    }
    $out
}

[pscustomobject]@{
    Computer  = $env:COMPUTERNAME
    Failures  = (Read-Channel -Log $FailureLog -Ids @(100, 104))
    Successes = (Read-Channel -Log $SuccessLog -Ids @(303))
}
'@

function Invoke-ADPUVerification {
    <#
        .SYNOPSIS
            Checks the Protected Users operational logs after accounts were enrolled.
        .DESCRIPTION
            The readiness review is backward-looking; this is the other half. Once
            accounts are in the group, the dedicated channels record every time the
            group turned an account away (failures) or let it through (successes).
            Reads every reachable controller in scope in one fan-out call and prints
            the command to switch a channel on when it is off - which it is by
            default.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Domain,
        [int]$Days = 7,
        [pscredential]$Credential
    )

    Write-ADPULine head 'Post-enrolment verification'
    Write-ADPULine sub  "Reads the Protected Users channels on each controller, covering the last $Days day(s)."
    Write-ADPULine sub  'Failures = an enrolled account still tried NTLM or DES/RC4. Successes = the group is working.'

    $forest  = Get-ADPUForest -DomainName $Domain -Credential $Credential
    $known   = @($forest.Domains | ForEach-Object { [string]$_.Name })
    if ($Domain) {
        # Same rule as the readiness review: a name that is not in the forest is
        # an error, not something to skip in silence.
        $unknown = @($Domain | Where-Object { $n = $_; -not ($known | Where-Object { $_ -ieq $n }) })
        if ($unknown.Count) {
            throw ("Not a domain of forest {0}: {1}. Known domains: {2}" -f $forest.Name, ($unknown -join ', '), ($known -join ', '))
        }
    }
    $domains = if ($Domain) { @($forest.Domains | Where-Object { $Domain -contains [string]$_.Name }) } else { @($forest.Domains) }
    if (-not $domains) {
        Write-ADPULine bad 'No domain in scope is reachable.'
        return 3
    }

    $targets = foreach ($d in $domains) {
        try {
            $ctx = Get-ADPUDirectoryContext -Type Domain -Name ([string]$d.Name) -Credential $Credential
            foreach ($dc in @([DirectoryServices.ActiveDirectory.DomainController]::FindAll($ctx))) {
                [pscustomobject]@{ Name = [string]$dc.Name; Domain = [string]$d.Name }
            }
        } catch {
            Write-ADPULine warn "   Could not enumerate the controllers of $($d.Name) - skipped."
        }
    }
    $targets = @($targets)
    if (-not $targets.Count) {
        Write-ADPULine bad 'No controller could be listed.'
        return 3
    }

    $option = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 300000 -CancelTimeout 5000
    $work = {
        param($names, $src, $days, $failLog, $okLog, $cred, $option)
        $splat = @{
            ComputerName  = $names
            ScriptBlock   = [scriptblock]::Create($src)
            ArgumentList  = @($days, $failLog, $okLog)
            ThrottleLimit = 16
            SessionOption = $option
            ErrorAction   = 'SilentlyContinue'
        }
        if ($cred) { $splat.Credential = $cred }
        $problems = $null
        $results  = Invoke-Command @splat -ErrorVariable problems
        [pscustomobject]@{
            Results = @($results)
            Errors  = @($problems | ForEach-Object {
                $who = [string]$_.TargetObject
                if (-not $who -and $_.OriginInfo) { $who = [string]$_.OriginInfo.PSComputerName }
                [pscustomobject]@{ Computer = $who; Message = $_.Exception.Message }
            })
        }
    }

    $raw = Start-ADPUActivity "Reading the Protected Users channels on $($targets.Count) controller(s)" -Work $work -With @(
        [string[]]@($targets.Name), $script:ADPUVerifySource, [int]$Days,
        $script:ADPUDcFailureLog, $script:ADPUDcSuccessLog, $Credential, $option
    )

    $byName = @{}
    foreach ($r in @($raw.Results)) {
        $n = [string]$r.PSComputerName
        if (-not $n) { $n = [string]$r.Computer }
        if ($n) { $byName[$n] = $r }
    }
    $why = @{}
    foreach ($e in @($raw.Errors)) { if ($e.Computer -and -not $why.ContainsKey($e.Computer)) { $why[$e.Computer] = $e.Message } }

    $sawFailure = $false
    $sawSuccess = $false
    $blindSpots = 0

    foreach ($d in ($targets.Domain | Sort-Object -Unique)) {
        Write-ADPULine note "Domain $d"
        foreach ($t in @($targets | Where-Object { $_.Domain -eq $d })) {
            if (-not $byName.ContainsKey($t.Name)) {
                $reason = if ($why.ContainsKey($t.Name)) { $why[$t.Name] } else { 'no response' }
                Write-ADPULine warn "   $($t.Name): could not be reached ($reason) - skipped."
                $blindSpots++
                continue
            }
            $res = $byName[$t.Name]

            foreach ($flavor in 'Failures', 'Successes') {
                $ch = $res.$flavor
                if (-not $ch -or -not $ch.Present) {
                    Write-ADPULine warn "   $($t.Name): the $flavor channel does not exist on this build."
                    $blindSpots++
                    continue
                }
                if (-not $ch.Enabled) {
                    Write-ADPULine warn "   $($t.Name): the $flavor channel is switched off - nothing was recorded."
                    Write-ADPULine snippet ("Invoke-Command -ComputerName '{0}' -ScriptBlock {{ wevtutil sl '{1}' /e:true }}" -f $t.Name, $ch.Log)
                    $blindSpots++
                    continue
                }

                if ($ch.PSObject.Properties['ReadError'] -and $ch.ReadError) {
                    Write-ADPULine warn "   $($t.Name): the $flavor channel could not be read ($($ch.ReadError)) - no verdict from here."
                    $blindSpots++
                    continue
                }

                $events = @($ch.Events)
                if (-not $events.Count) {
                    if ($flavor -eq 'Failures') {
                        Write-ADPULine good "   $($t.Name): no protected-user failures in the last $Days day(s)."
                    } else {
                        Write-ADPULine note "   $($t.Name): no protected-user logons recorded - either nobody signed in here, or nobody is enrolled yet."
                    }
                    continue
                }

                if ($flavor -eq 'Successes') {
                    $sawSuccess = $true
                    $people = @($events.Account | Sort-Object -Unique).Count
                    Write-ADPULine good ("   {0}: {1} clean protected-user logon(s) from {2} account(s)." -f $t.Name, $events.Count, $people)
                    continue
                }

                $sawFailure = $true
                Write-ADPULine bad ("   {0}: {1} protected-user failure(s)." -f $t.Name, $events.Count)
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

    if ($sawFailure) { 1 } elseif ($blindSpots) { 2 } else { 0 }
}

#  ==========================================================================
#  >> Entry point
#  ==========================================================================

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
            Invoke-ADPUAnalyzer -Domain child.example.com -Scope Extended
        .EXAMPLE
            Invoke-ADPUAnalyzer -NonInteractive -JsonPath .\pu.json
            Unattended run for a scheduled task; the result object is also emitted
            with -PassThru so it can be diffed against the previous run.
        .OUTPUTS
            With -PassThru, the flat result object (see ConvertTo-ADPUResult).
    #>
    [CmdletBinding()]
    param(
        [string[]]$Domain,
        [ValidateSet('Core','Extended')] [string]$Scope = 'Core',
        [string[]]$IncludeGroup,
        [switch]$StrictScope,
        [string[]]$BreakGlass,
        [string[]]$Identity,
        [ValidateRange(1, 365)] [int]$Days = 7,
        [pscredential]$Credential,
        [string]$HtmlPath,
        [string]$JsonPath,
        [switch]$Verify,
        [switch]$PassThru,
        [switch]$NonInteractive
    )

    try {
        $script:ADPUNonInteractive = [bool]$NonInteractive
        $script:ADPULastExitCode   = 3
        if (-not $NonInteractive) { Show-ADPUBanner -Stamp (Get-Date -Format 'yyyy.MM.dd') }

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
        # forest's domains and, when there is more than one, let the operator pick.
        $picked = $Domain
        # With -Identity and no -Domain, every domain is searched - no prompt.
        if (-not $picked -and -not $NonInteractive -and -not $Identity) {
            $forest = Get-ADPUForest -Credential $Credential
            $names  = @($forest.Domains | ForEach-Object { [string]$_.Name } | Sort-Object)
            if ($names.Count -gt 1) {
                $sel = Read-ADPUMultiChoice 'Which domain(s) should I review?' $names
                # Picking every domain is treated as "all" (keeps forest-wide admins in scope).
                if (@($sel).Count -lt $names.Count) { $picked = @($sel) }
            }
        }

        # -Verify is the after-the-fact pass: no readiness sweep, just the operational
        # logs for accounts that are already in the group.
        if ($Verify) {
            $script:ADPULastExitCode = [int](Invoke-ADPUVerification -Domain $picked -Days $Days -Credential $Credential)
            Show-ADPUCredits
            return
        }

        $topology = Get-ADPUTopology -DomainName $picked -Days $Days -Scope $Scope `
                                     -IncludeGroup $IncludeGroup -StrictScope:$StrictScope -Credential $Credential `
                                         -Identity $Identity
        $topology | Add-Member -NotePropertyName BreakGlass -NotePropertyValue @($BreakGlass | Where-Object { $_ }) -Force
        $null = Set-ADPUReadiness -Topology $topology

        if (-not $NonInteractive) {
            Write-ADPULine note 'Survey complete - rendering the report.'
            Wait-ADPUEnter '   Press Enter to view the findings'
            Write-Host
        }
        Show-ADPUReadinessReport -Topology $topology

        # Optional HTML report: -HtmlPath writes silently; otherwise offer to save one.
        $target = $HtmlPath
        if (-not $target -and -not $NonInteractive) {
            if (Read-ADPUYesNo 'Save an HTML report of these findings?') {
                $suggest = Join-Path (Get-Location).Path ('ADPU-Analyzer-{0:yyyyMMdd-HHmmss}.html' -f (Get-Date))
                $typed   = Read-ADPUAnswer "Path for the HTML file [$suggest]"
                $target  = if ([string]::IsNullOrWhiteSpace($typed)) { $suggest } else { $typed }
            }
        }
        if ($target) {
            try {
                Write-ADPULine good ("HTML report saved: {0}" -f (Export-ADPUHtmlReport -Topology $topology -Path $target))
            } catch {
                Write-ADPULine bad "Could not write the HTML report: $($_.Exception.Message)"
            }
        }
        if ($JsonPath) {
            try {
                Write-ADPULine good ("JSON report saved: {0}" -f (Export-ADPUJsonReport -Topology $topology -Path $JsonPath))
            } catch {
                Write-ADPULine bad "Could not write the JSON report: $($_.Exception.Message)"
            }
        }

        Show-ADPUCredits

        # The exit code travels on a script-scope variable rather than on the return
        # value, so an interactive `Invoke-ADPUAnalyzer` does not dump an object into
        # the console the moment the walkthrough ends.
        $result = ConvertTo-ADPUResult -Topology $topology
        $script:ADPULastExitCode = [int]$result.Summary.ExitCode
        if ($PassThru) { $result }
    } finally {
        # Release the directory bindings only now, after every report has been
        # written - the account objects stay readable only while they are open.
        Clear-ADPUContextCache
    }
}

#  ----------------------------------------------------------------------------
#  Kick off automatically, unless the file was dot-sourced (then it only loads).
#  Parameters given to the script file are forwarded, so both of these work:
#      .\ADPU-Analyzer.ps1 -Domain corp.example.net
#      . .\ADPU-Analyzer.ps1 ; Invoke-ADPUAnalyzer -Domain corp.example.net
#  ----------------------------------------------------------------------------
if ($MyInvocation.InvocationName -ne '.') {
    $forward = @{}
    foreach ($k in $PSBoundParameters.Keys) {
        # Common parameters (-Verbose and friends) are not part of the function's
        # own signature and would break the splat.
        if ($k -in @('Domain','Scope','IncludeGroup','StrictScope','BreakGlass','Identity','Days','Credential','HtmlPath',
                     'JsonPath','Verify','PassThru','NonInteractive')) {
            $forward[$k] = $PSBoundParameters[$k]
        }
    }
    $script:ADPULastExitCode = 3
    try {
        Invoke-ADPUAnalyzer @forward
    } catch {
        Write-ADPULine bad $_.Exception.Message
        $script:ADPULastExitCode = 3
    }
    exit ([int]$script:ADPULastExitCode)
}
