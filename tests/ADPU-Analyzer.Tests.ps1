#  ADPU-Analyzer - unit tests
#  ---------------------------
#  No Active Directory, no Pester, no Windows needed. The scoring engine is a pure
#  function over plain objects, so the whole decision table runs on synthetic
#  input. The helpers that live inside the remote collector are lifted out of its
#  source text and tested on their own.
#
#    pwsh -File tests/ADPU-Analyzer.Tests.ps1
#    ADPU_STRICT=1 pwsh -File tests/ADPU-Analyzer.Tests.ps1     (under Set-StrictMode 3)
#
#  Exit code is the number of failed checks.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'ADPU-Analyzer.ps1')
if ($env:ADPU_STRICT -eq '1') { Set-StrictMode -Version 3 }
$script:ADPUNonInteractive = $true

$script:failed = 0
$script:passed = 0
function Assert-True {
    param([bool]$Condition, [string]$Name)
    if ($Condition) { $script:passed++ }
    else { $script:failed++; Write-Host "FAIL  $Name" -ForegroundColor Red }
}
function Assert-Equal {
    param($Actual, $Expected, [string]$Name)
    if ($Actual -eq $Expected) { $script:passed++ }
    else { $script:failed++; Write-Host "FAIL  $Name  (expected '$Expected', got '$Actual')" -ForegroundColor Red }
}
function Test-Code { param($Findings, [string]$Code) [bool](@($Findings | Where-Object { $_.Code -eq $Code }).Count) }

# ---------------------------------------------------------------------------
# Collector helpers, taken from the embedded remote source
# ---------------------------------------------------------------------------
$tokens = $null; $errors = $null
$collectorAst = [System.Management.Automation.Language.Parser]::ParseInput($script:ADPUCollectorSource, [ref]$tokens, [ref]$errors)
Assert-Equal $errors.Count 0 'collector source parses'
foreach ($fn in $collectorAst.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    if ($fn.Name -in 'Test-WeakEtype', 'Test-AesMask', 'Split-CsvLine', 'ConvertFrom-AuditCsv', 'Resolve-AuditText', 'Split-Chunk') {
        . ([scriptblock]::Create($fn.Extent.Text))
    }
}
$verifyAst = [System.Management.Automation.Language.Parser]::ParseInput($script:ADPUVerifySource, [ref]$tokens, [ref]$errors)
Assert-Equal $errors.Count 0 'verify source parses'

Assert-Equal (Test-WeakEtype '0x17') $true  'etype 0x17 (RC4) is weak'
Assert-Equal (Test-WeakEtype '0x3')  $true  'etype 0x3 (DES) is weak'
Assert-Equal (Test-WeakEtype '0x12') $false 'etype 0x12 (AES256) is not weak'
Assert-Equal (Test-WeakEtype '0x11') $false 'etype 0x11 (AES128) is not weak'
Assert-Equal (Test-WeakEtype '18')   $false 'decimal 18 is AES256'
Assert-True  ($null -eq (Test-WeakEtype '0xffffffff')) 'failure sentinel is no evidence'
Assert-True  ($null -eq (Test-WeakEtype ''))  'empty etype is no evidence'
Assert-True  ($null -eq (Test-WeakEtype '-')) 'dash etype is no evidence'

Assert-Equal (Test-AesMask '0x18') $true  'key mask 0x18 has AES'
Assert-Equal (Test-AesMask '0x4')  $false 'key mask 0x4 (RC4 only) has no AES'
Assert-Equal (Test-AesMask 'AES-SHA1, RC4') $true 'textual key list with AES'
Assert-Equal (Test-AesMask 'RC4') $false 'textual key list without AES'
Assert-True  ($null -eq (Test-AesMask '-')) 'dash key list is no evidence'

# auditpol CSV: seven-column backup layout and five-column /get /r layout
$seven = @(
    'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value',
    'DC01,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3',
    'DC01,System,Kerberos Authentication Service,{0CCE9242-69AE-11D9-BED3-505054503030},No Auditing,,0'
)
$m = ConvertFrom-AuditCsv -Lines $seven
Assert-Equal $m['0cce9215-69ae-11d9-bed3-505054503030'].Value 3 'auditpol 7-col: logon = 3'
Assert-Equal $m['0cce9242-69ae-11d9-bed3-505054503030'].Value 0 'auditpol 7-col: kerb = 0'
$five = @('DC01,System,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Success')
$m = ConvertFrom-AuditCsv -Lines $five
Assert-True ($null -eq $m['0cce923f-69ae-11d9-bed3-505054503030'].Value) 'auditpol 5-col without number: value unknown'
Assert-Equal (Resolve-AuditText 'Erfolg') 1 'German success text resolves'
Assert-Equal (Format-ADPUStatusCounts @{ '0xC0000234' = 1; '0xC000006A' = 5; '0xC0DEFFFF' = 2 }) 'wrong password 5, 0xC0DEFFFF 2, locked out 1' 'status counts are named and sorted'
Assert-Equal (Resolve-AuditText 'Keine Überwachung') 0 'German no-auditing text resolves'

# ---------------------------------------------------------------------------
# Synthetic topology
# ---------------------------------------------------------------------------
$domSid  = 'S-1-5-21-1-2-3'
$domSid2 = 'S-1-5-21-9-9-9'
$pugBorn = (Get-Date).AddYears(-5)

function New-TestDomain {
    param([string]$Name = 'corp.example.net', [string]$Sid = $domSid, $KrbtgtHasAes = $null)
    [pscustomobject]@{
        Name = $Name; Sid = $Sid; ModeLevel = 7; ReadyFL = $true; IsRoot = $true
        PugSid = "$Sid-525"; PugPresent = $true; PugBornOn = $pugBorn
        Krbtgt = [pscustomobject]@{
            Readable = $true; EncTypes = $(if ($KrbtgtHasAes -eq $false) { 4 } else { $null })
            Explicit = ($KrbtgtHasAes -eq $false); HasAes = $KrbtgtHasAes; PwdLastSet = (Get-Date).AddDays(-100)
        }
    }
}

function New-TestDc {
    param(
        [string]$Name = 'dc01.corp.example.net', [string]$Domain = 'corp.example.net',
        [bool]$New = $true, [bool]$Audit = $true, [bool]$Reachable = $true,
        $Ntlm4624 = @(), $Ntlm4776 = @(), $Kerb = @(), [hashtable]$Partial = $null,
        $SvcLogons = @(), [bool]$LogonSuccess = $true, [bool]$LogonFailure = $true
    )
    $state = if ($Audit) { 'On' } else { 'Off' }
    [pscustomobject]@{
        Name = $Name; DomainName = $Domain; OSVersion = 'Windows Server 2022 Standard'; OSOk = $true
        Reachable = $Reachable; Error = $(if ($Reachable) { $null } else { 'no response' })
        AuditLogonOk = ($Audit -and $Reachable -and $LogonSuccess)
        AuditLogonFailOk = ($Audit -and $Reachable -and $LogonFailure)
        AuditKerbOk = ($Audit -and $Reachable); AuditCredValOk = ($Audit -and $Reachable)
        AuditState = @{ Logon = $state; KerbAS = $state; CredVal = $state }
        AuditRaw   = @{ Logon = 'Success'; KerbAS = 'Success'; CredVal = 'Success' }
        AuditMethod = 'auditpol /backup'
        NewKerbFields = $New
        AuditPartial = $(if ($Partial) { $Partial } else { @{ Logon = $false; KerbAS = $false; CredVal = $false } })
        Ntlm4624 = @($Ntlm4624); SvcLogons = @($SvcLogons); Ntlm4776 = @($Ntlm4776); KerbSeen = @($Kerb); KdcRc4 = @()
        Notes = @()
    }
}

function New-TestAccount {
    param(
        [string]$Sam, [int]$Rid, [string]$Domain = 'corp.example.net', [string]$DomainSid = $domSid,
        [bool]$Foreign = $false, [bool]$Enabled = $true, $EncTypes = $null, [int]$Uac = 0x200
    )
    [pscustomobject]@{
        Sid = "$DomainSid-$Rid"; Sam = $Sam; Display = $Sam; Dn = "CN=$Sam,DC=corp"; Class = 'user'
        Domain = $Domain; DomainSid = $DomainSid; Foreign = $Foreign; FoundVia = 'corp.example.net'
        PugBornOn = $(if ($Foreign) { $null } else { $pugBorn }); PugPresent = (-not $Foreign)
        ViaGroups = @('Domain Admins'); PwdLastSet = (Get-Date).AddDays(-30); Enabled = $Enabled
        PwdNeverExp = $false; AdminCount = $true; Uac = $Uac; EncTypes = $EncTypes
        Spns = @(); DelegateTo = @(); IsGmsa = $false
    }
}

function New-KerbRecord {
    param([string]$Sid, [int]$Count = 5, [int]$WeakNew = 0, [int]$WeakLegacy = 0, $HasAes = $true, [int]$NoAesAdv = 0)
    @{
        Sid = $Sid; Account = 'x'; Count = $Count; NewEvents = $Count
        Weak = $WeakNew + $WeakLegacy; WeakNew = $WeakNew; WeakLegacy = $WeakLegacy
        HasAes = [bool]$HasAes; KeysSeen = ($null -ne $HasAes); Keys = $(if ($HasAes) { 'AES-SHA1, RC4' } else { 'RC4' })
        Etypes = '0x0'; NoAesAdv = $NoAesAdv; AdvSources = @($(if ($NoAesAdv) { '10.0.0.9' }))
        Last = (Get-Date)
    }
}

function New-TestTopology {
    param($Domains, $Dcs, $Accounts, [int]$Days = 30, $Enrolled = @(), $BreakGlass = @())
    [pscustomobject]@{
        Forest = [pscustomobject]@{ Name = 'corp.example.net'; ModeLevel = 7; ReadyFL = $true; RootName = 'corp.example.net' }
        Domains = @($Domains); Controllers = @($Dcs); Accounts = @($Accounts)
        EnrolledSids = @($Enrolled); LookbackDays = $Days; Scope = 'Core'; StrictScope = $false
        ExcludedForeign = 0; Generated = (Get-Date); BreakGlass = @($BreakGlass)
    }
}

function Get-Scored {
    param($Topology)
    $null = Set-ADPUReadiness -Topology $Topology
    $h = @{}
    foreach ($a in $Topology.Accounts) { $h[$a.Sam] = $a }
    $h
}

# ---------------------------------------------------------------------------
# 1. Clean, active, fully covered account: proven with a long window only
# ---------------------------------------------------------------------------
$acc = New-TestAccount -Sam 'alice' -Rid 1101
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $acc -Days 30 `
        -Dcs (New-TestDc -Kerb (New-KerbRecord -Sid $acc.Sid))
$r = Get-Scored $t
Assert-True  $r.alice.ClearNow 'clean account is clear'
Assert-Equal $r.alice.Confidence 'Proven' 'clean account with 30-day window is Proven'

$acc = New-TestAccount -Sam 'alice' -Rid 1101
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $acc -Days 7 `
        -Dcs (New-TestDc -Kerb (New-KerbRecord -Sid $acc.Sid))
$r = Get-Scored $t
Assert-Equal $r.alice.Confidence 'Plausible' 'a 7-day window is never Proven'
Assert-True  (@($r.alice.Evidence | Where-Object { $_.Code -eq 'Window' -and $_.Text -match 'only 7' }).Count -eq 1) 'short window is explained'

# ---------------------------------------------------------------------------
# 2. The krbtgt trap: RC4-only krbtgt must not block every account
# ---------------------------------------------------------------------------
$acc = New-TestAccount -Sam 'bob' -Rid 1102
$t = New-TestTopology -Domains (New-TestDomain -KrbtgtHasAes $false) -Accounts $acc `
        -Dcs (New-TestDc -New $true -Kerb (New-KerbRecord -Sid $acc.Sid -WeakNew 0))
$r = Get-Scored $t
Assert-True (-not (Test-Code $r.bob.Blockers 'WeakKerb')) 'RC4 krbtgt + new DC + AES session: no WeakKerb'
Assert-True $r.bob.ClearNow 'RC4 krbtgt + new DC + AES session: clear'

# legacy ticket-field finding with a bad krbtgt: hint only
$acc = New-TestAccount -Sam 'bob' -Rid 1102
$t = New-TestTopology -Domains (New-TestDomain -KrbtgtHasAes $false) -Accounts $acc `
        -Dcs (New-TestDc -New $false -Kerb (New-KerbRecord -Sid $acc.Sid -WeakLegacy 3 -HasAes $null))
$r = Get-Scored $t
Assert-True (Test-Code $r.bob.Hints 'WeakKerbUnreliable') 'legacy weak + RC4 krbtgt: hint'
Assert-True (-not (Test-Code $r.bob.Blockers 'WeakKerbLegacy')) 'legacy weak + RC4 krbtgt: not blocked'

# legacy ticket-field finding with a healthy krbtgt: blocked
$acc = New-TestAccount -Sam 'bob' -Rid 1102
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $acc `
        -Dcs (New-TestDc -New $false -Kerb (New-KerbRecord -Sid $acc.Sid -WeakLegacy 3 -HasAes $null))
$r = Get-Scored $t
Assert-True (Test-Code $r.bob.Blockers 'WeakKerbLegacy') 'legacy weak + healthy krbtgt: blocked'

# a real RC4 session key blocks, whatever krbtgt looks like
$acc = New-TestAccount -Sam 'bob' -Rid 1102
$t = New-TestTopology -Domains (New-TestDomain -KrbtgtHasAes $false) -Accounts $acc `
        -Dcs (New-TestDc -New $true -Kerb (New-KerbRecord -Sid $acc.Sid -WeakNew 2))
$r = Get-Scored $t
Assert-True (Test-Code $r.bob.Blockers 'WeakKerb') 'RC4 session key: blocked even with RC4 krbtgt'

# no AES key observed
$acc = New-TestAccount -Sam 'bob' -Rid 1102
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $acc `
        -Dcs (New-TestDc -Kerb (New-KerbRecord -Sid $acc.Sid -HasAes $false))
$r = Get-Scored $t
Assert-True (Test-Code $r.bob.Blockers 'NoAesKeys') 'no AES keys observed: blocked'

# client that offers no AES: hint
$acc = New-TestAccount -Sam 'bob' -Rid 1102
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $acc `
        -Dcs (New-TestDc -Kerb (New-KerbRecord -Sid $acc.Sid -NoAesAdv 2))
$r = Get-Scored $t
Assert-True (Test-Code $r.bob.Hints 'ClientNoAes') 'client offering no AES: hint'

# ---------------------------------------------------------------------------
# 3. 4776: successes and stale-password failures both block
# ---------------------------------------------------------------------------
$acc = New-TestAccount -Sam 'carol' -Rid 1103
$fail = @{ Account = 'Carol'; Count = 12; Succeeded = 0; Failed = 12; Last = (Get-Date); Sources = @(); FailedSources = @('WS99')
           FailedStatus = @{ '0xC000006A' = 10; '0xC0000234' = 2 } }
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $acc `
        -Dcs (New-TestDc -Ntlm4776 $fail -Kerb (New-KerbRecord -Sid $acc.Sid))
$r = Get-Scored $t
Assert-True (Test-Code $r.carol.Blockers 'Ntlm4776Failed') '4776 stale-password failures: blocked'
Assert-True (-not $r.carol.ClearNow) '4776 stale-password failures: not clear'
$txt = @($r.carol.Blockers | Where-Object { $_.Code -eq 'Ntlm4776Failed' })[0].Text
Assert-True ($txt -match 'WS99') '4776 failure blocker names the source'
Assert-True ($txt -match 'wrong password 10, locked out 2') '4776 failure blocker spells out the status codes, largest first'
Assert-True ($txt -match 'old saved password') 'few sources read as a configured consumer'

# many sources: worded as "consumer or attack"
$acc = New-TestAccount -Sam 'carol' -Rid 1103
$spray = @{ Account = 'carol'; Count = 40; Succeeded = 0; Failed = 40; Last = (Get-Date); Sources = @()
            FailedSources = @('A1','A2','A3','A4','A5'); FailedStatus = @{ '0xC000006A' = 40 } }
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $acc `
        -Dcs (New-TestDc -Ntlm4776 $spray -Kerb (New-KerbRecord -Sid $acc.Sid))
$r = Get-Scored $t
$txt = @($r.carol.Blockers | Where-Object { $_.Code -eq 'Ntlm4776Failed' })[0].Text
Assert-True ($txt -match 'someone is trying the account') 'many sources are worded as possibly an attack'

# "no such user" only: not about this account, so hint instead of blocker
$acc = New-TestAccount -Sam 'carol' -Rid 1103
$nsu = @{ Account = 'carol'; Count = 5; Succeeded = 0; Failed = 5; Last = (Get-Date); Sources = @()
          FailedSources = @('WS1'); FailedStatus = @{ '0xC0000064' = 5 } }
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $acc `
        -Dcs (New-TestDc -Ntlm4776 $nsu -Kerb (New-KerbRecord -Sid $acc.Sid))
$r = Get-Scored $t
Assert-True (-not (Test-Code $r.carol.Blockers 'Ntlm4776Failed')) '"no such user" failures only: not blocked'
Assert-True (Test-Code $r.carol.Hints 'Ntlm4776UnknownUser') '"no such user" failures only: hint'

# an enrolled account that still sees NTLM gets a pointer to -Verify
$acc = New-TestAccount -Sam 'carol' -Rid 1103
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $acc -Enrolled @($acc.Sid) `
        -Dcs (New-TestDc -Ntlm4776 $fail -Kerb (New-KerbRecord -Sid $acc.Sid))
$r = Get-Scored $t
Assert-True (Test-Code $r.carol.Hints 'NtlmWhileEnrolled') 'enrolled account with NTLM: hint to run -Verify'

$acc = New-TestAccount -Sam 'carol' -Rid 1103
$ok = @{ Account = 'CAROL'; Count = 3; Succeeded = 2; Failed = 1; Last = (Get-Date); Sources = @('APP01'); FailedSources = @() }
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $acc `
        -Dcs (New-TestDc -Ntlm4776 $ok -Kerb (New-KerbRecord -Sid $acc.Sid))
$r = Get-Scored $t
Assert-True (Test-Code $r.carol.Blockers 'Ntlm4776') '4776 success: blocked (case-insensitive name match)'

# a record from the old collector (no Succeeded/Failed split) still blocks
$acc = New-TestAccount -Sam 'carol' -Rid 1103
$old = @{ Account = 'carol'; Count = 4; Last = (Get-Date); Sources = @() }
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $acc `
        -Dcs (New-TestDc -Ntlm4776 $old -Kerb (New-KerbRecord -Sid $acc.Sid))
$r = Get-Scored $t
Assert-True (Test-Code $r.carol.Blockers 'Ntlm4776') 'old-format 4776 record: still blocked'

# ---------------------------------------------------------------------------
# 4. Disabled accounts and break-glass accounts
# ---------------------------------------------------------------------------
$acc = New-TestAccount -Sam 'dave' -Rid 1104 -Enabled $false
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $acc -Dcs (New-TestDc)
$r = Get-Scored $t
Assert-True (Test-Code $r.dave.Blockers 'Disabled') 'disabled account: blocked'
Assert-True (-not $r.dave.ClearNow) 'disabled account: not clear'

$admin = New-TestAccount -Sam 'Administrator' -Rid 500
$emerg = New-TestAccount -Sam 'emergency' -Rid 1190
$norm  = New-TestAccount -Sam 'erin' -Rid 1105
$t = New-TestTopology -Domains (New-TestDomain) -Accounts @($admin, $emerg, $norm) -BreakGlass 'corp.example.net\emergency' `
        -Dcs (New-TestDc -Kerb @((New-KerbRecord -Sid $admin.Sid), (New-KerbRecord -Sid $emerg.Sid), (New-KerbRecord -Sid $norm.Sid)))
$r = Get-Scored $t
Assert-True ($r.Administrator.Reserved -and -not $r.Administrator.ClearNow) 'RID 500 is reserved, not clear'
Assert-True ($r.emergency.Reserved) '-BreakGlass DOMAIN\name is reserved'
Assert-True ($r.erin.ClearNow -and -not $r.erin.Reserved) 'ordinary account unaffected by break-glass'
$s = Get-ADPUSummary -Topology $t
Assert-Equal $s.Reserved 2 'summary counts reserved accounts'
Assert-Equal $s.Pending 1 'reserved accounts are not pending'
Assert-Equal $s.Blocked 0 'reserved accounts are not blocked'
Assert-Equal $s.ExitCode 0 'reserved accounts do not move the exit code'

$admin = New-TestAccount -Sam 'Administrator' -Rid 500
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $admin -Enrolled @($admin.Sid) -Dcs (New-TestDc)
$r = Get-Scored $t
Assert-True (Test-Code $r.Administrator.Hints 'BreakGlassEnrolled') 'enrolled RID 500: hint'

# ---------------------------------------------------------------------------
# 5. Coverage: partial reads, unreachable controllers, blind domains
# ---------------------------------------------------------------------------
$acc = New-TestAccount -Sam 'frank' -Rid 1106
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $acc `
        -Dcs (New-TestDc -Kerb (New-KerbRecord -Sid $acc.Sid) -Partial @{ Logon = $false; KerbAS = $true; CredVal = $false })
$r = Get-Scored $t
Assert-Equal $r.frank.Confidence 'Plausible' 'partly read controller: not Proven'
$s = Get-ADPUSummary -Topology $t
Assert-True $s.HasGaps 'partly read controller is a coverage gap'
Assert-Equal $s.ExitCode 2 'partly read controller: exit code 2'
Assert-True (@(Get-ADPUCoverageNotes -Summary $s -Topology $t | Where-Object { $_.Text -match 'only partly read' }).Count -eq 1) 'coverage note for partial read'

$acc = New-TestAccount -Sam 'frank' -Rid 1106
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $acc `
        -Dcs @((New-TestDc -Kerb (New-KerbRecord -Sid $acc.Sid)), (New-TestDc -Name 'dc02.corp.example.net' -Reachable $false))
$r = Get-Scored $t
Assert-Equal $r.frank.Confidence 'Plausible' 'one unreachable controller: not Proven'

$acc = New-TestAccount -Sam 'frank' -Rid 1106
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $acc -Dcs (New-TestDc -Audit $false)
$r = Get-Scored $t
Assert-Equal $r.frank.Confidence 'Unknown' 'no auditing at all: Unknown'

# ---------------------------------------------------------------------------
# 6. Out-of-scope members and evidence scoping
# ---------------------------------------------------------------------------
$home1 = New-TestAccount -Sam 'sameName' -Rid 1107
$away  = New-TestAccount -Sam 'sameName' -Rid 2107 -Domain 'child.example.net' -DomainSid $domSid2 -Foreign $true
$ntlm  = @{ Account = 'sameName'; Count = 1; Succeeded = 1; Failed = 0; Last = (Get-Date); Sources = @(); FailedSources = @() }
$t = New-TestTopology -Domains (New-TestDomain) -Accounts @($home1, $away) `
        -Dcs (New-TestDc -Ntlm4776 $ntlm -Kerb (New-KerbRecord -Sid $home1.Sid))
$null = Set-ADPUReadiness -Topology $t
Assert-True ($away.OutOfScope -and -not $away.ClearNow) 'foreign member is out of scope'
Assert-True (-not (Test-Code $away.Blockers 'Ntlm4776')) 'foreign member never borrows name-keyed 4776 evidence'
Assert-True (Test-Code $home1.Blockers 'Ntlm4776') 'home member gets its own 4776 evidence'

# ---------------------------------------------------------------------------
# 7. Evidence wording and enrolment commands
# ---------------------------------------------------------------------------
$acc = New-TestAccount -Sam 'gina' -Rid 1108 -EncTypes 0
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $acc -Dcs (New-TestDc -Kerb (New-KerbRecord -Sid $acc.Sid))
$r = Get-Scored $t
$et = @($r.gina.Evidence | Where-Object { $_.Code -eq 'Etypes' })[0].Text
Assert-True ($et -match 'is 0' -and $et -notmatch 'includes AES') 'etype 0 is described as the domain default'

$acc = New-TestAccount -Sam 'hank' -Rid 1109
$cmd = Get-ADPUEnrolCommand -Account $acc -LocalDomain 'corp.example.net'
Assert-True ($cmd.NoRsat -like 'net group*') 'net group offered for the local domain'
$cmd = Get-ADPUEnrolCommand -Account $acc -LocalDomain 'other.example.net'
Assert-True ($cmd.NoRsat -like '#*') 'net group not offered as-is for another domain'
Assert-True ($cmd.Rsat -match "-Server 'corp.example.net'") 'RSAT command targets the home domain'

$quote = New-TestAccount -Sam "o'brien" -Rid 1110
$cmd = Get-ADPUEnrolCommand -Account $quote -LocalDomain 'corp.example.net'
Assert-True ($cmd.Rsat -match "'o''brien'") 'apostrophe is escaped in the RSAT command'

# ---------------------------------------------------------------------------
# 7b. Service and scheduled-task logons on the controllers
# ---------------------------------------------------------------------------
$acc = New-TestAccount -Sam 'svcadm' -Rid 1120
$svc = @{ Key = 'svcadm'; Account = 'svcadm'; Sid = $acc.Sid; Batch = 3; Service = 1; BatchFailed = 0; ServiceFailed = 0
          Processes = @('C:\Windows\System32\services.exe'); FailedStatus = @{}; Last = (Get-Date) }
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $acc `
        -Dcs (New-TestDc -SvcLogons $svc -Kerb (New-KerbRecord -Sid $acc.Sid))
$r = Get-Scored $t
Assert-True (Test-Code $r.svcadm.Blockers 'ServiceLogon') 'service/batch logon on a DC: blocked'
$txt = @($r.svcadm.Blockers | Where-Object { $_.Code -eq 'ServiceLogon' })[0].Text
Assert-True ($txt -match '1 service logon' -and $txt -match '3 scheduled-task' -and $txt -match 'dc01') 'service logon blocker counts both kinds and names the DC'

# failing task with an old password: 4625, matched by name
$acc = New-TestAccount -Sam 'oldtask' -Rid 1121
$fail = @{ Key = 'oldtask'; Account = 'OLDTASK'; Sid = $null; Batch = 0; Service = 0; BatchFailed = 40; ServiceFailed = 0
           Processes = @(); FailedStatus = @{ '0xC000006A' = 40 }; Last = (Get-Date) }
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $acc `
        -Dcs (New-TestDc -SvcLogons $fail -Kerb (New-KerbRecord -Sid $acc.Sid))
$r = Get-Scored $t
Assert-True (Test-Code $r.oldtask.Blockers 'ServiceLogonFailed') 'failing scheduled task: blocked'
$txt = @($r.oldtask.Blockers | Where-Object { $_.Code -eq 'ServiceLogonFailed' })[0].Text
Assert-True ($txt -match 'wrong password 40') 'failing task blocker spells out the status'

# clean account: evidence says what was looked at
$acc = New-TestAccount -Sam 'clean' -Rid 1122
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $acc `
        -Dcs (New-TestDc -LogonSuccess $false -Kerb (New-KerbRecord -Sid $acc.Sid))
$r = Get-Scored $t
$ev = @($r.clean.Evidence | Where-Object { $_.Code -eq 'ServiceLogon' })[0]
Assert-True ($ev.Severity -eq 'sub' -and $ev.Text -match 'failed \(4625\)' -and $ev.Text -notmatch 'successful') 'failure-only logon auditing is described as such'

$acc = New-TestAccount -Sam 'clean' -Rid 1122
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $acc `
        -Dcs (New-TestDc -LogonSuccess $false -LogonFailure $false -Kerb (New-KerbRecord -Sid $acc.Sid))
$r = Get-Scored $t
$ev = @($r.clean.Evidence | Where-Object { $_.Code -eq 'ServiceLogon' })[0]
Assert-Equal $ev.Severity 'warn' 'no logon auditing at all: service check could not look'

# a same-named failure in another domain's DCs must not stick to this account
$acc = New-TestAccount -Sam 'oldtask' -Rid 1121
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $acc `
        -Dcs (New-TestDc -Name 'dc09.child.example.net' -Domain 'child.example.net' -SvcLogons $fail)
$r = Get-Scored $t
Assert-True (-not (Test-Code $r.oldtask.Blockers 'ServiceLogonFailed')) 'service logon evidence stays within the account''s domain'

# ---------------------------------------------------------------------------
# 7c. -Identity mode renders its own wording
# ---------------------------------------------------------------------------
$acc = New-TestAccount -Sam 'alice' -Rid 1101
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $acc -Dcs (New-TestDc -Kerb (New-KerbRecord -Sid $acc.Sid))
$t | Add-Member -NotePropertyName Identity -NotePropertyValue @('alice') -Force
$null = Set-ADPUReadiness -Topology $t
$out = & { Show-ADPUReadinessReport -Topology $t } 6>&1 | Out-String
Assert-True ($out -match 'given with -Identity: alice') 'console summary names the -Identity accounts'
$html = Join-Path ([IO.Path]::GetTempPath()) ('adpu-id-{0}.html' -f [guid]::NewGuid())
try {
    $null = Export-ADPUHtmlReport -Topology $t -Path $html
    Assert-True ((Get-Content -LiteralPath $html -Raw) -match '-Identity alice') 'HTML header names the -Identity accounts'
    Assert-True (@((ConvertTo-ADPUResult -Topology $t).Identity) -contains 'alice') 'JSON carries the -Identity list'
} finally { Remove-Item -LiteralPath $html -ErrorAction SilentlyContinue }

# ---------------------------------------------------------------------------
# 8. Kitchen sink: every report path renders
# ---------------------------------------------------------------------------
$accs = @(
    (New-TestAccount -Sam 'alice' -Rid 1101),
    (New-TestAccount -Sam 'bob' -Rid 1102),
    (New-TestAccount -Sam 'dave' -Rid 1104 -Enabled $false),
    (New-TestAccount -Sam 'Administrator' -Rid 500),
    (New-TestAccount -Sam 'ivan' -Rid 1111),
    (New-TestAccount -Sam 'sameName' -Rid 2107 -Domain 'child.example.net' -DomainSid $domSid2 -Foreign $true)
)
$dcs = @(
    (New-TestDc -Kerb @((New-KerbRecord -Sid $accs[0].Sid), (New-KerbRecord -Sid $accs[1].Sid -WeakNew 1)) `
                -Partial @{ Logon = $true; KerbAS = $false; CredVal = $false }),
    (New-TestDc -Name 'dc02.corp.example.net' -New $false -Audit $false),
    (New-TestDc -Name 'dc03.corp.example.net' -Reachable $false)
)
$dcs[0].Notes = @('4624 harvest stopped at the row cap - the harvest is incomplete')
$t = New-TestTopology -Domains (New-TestDomain) -Accounts $accs -Dcs $dcs -Enrolled @($accs[4].Sid) -Days 10
$null = Set-ADPUReadiness -Topology $t

$renderOk = $true
try { Show-ADPUReadinessReport -Topology $t 6>$null | Out-Null } catch { $renderOk = $false; Write-Host $_ }
Assert-True $renderOk 'console report renders'

$html = Join-Path ([IO.Path]::GetTempPath()) ('adpu-test-{0}.html' -f [guid]::NewGuid())
$json = Join-Path ([IO.Path]::GetTempPath()) ('adpu-test-{0}.json' -f [guid]::NewGuid())
try {
    $null = Export-ADPUHtmlReport -Topology $t -Path $html
    $page = Get-Content -LiteralPath $html -Raw
    Assert-True ($page -match 'Kept outside on purpose') 'HTML has the break-glass section'
    Assert-True ($page -match 'row cap') 'HTML shows controller notes'
    $hintsSection = ($page -split '<h2>Hardening hints')[1]
    Assert-True ($hintsSection -notmatch 'sameName') 'HTML hardening hints leave out out-of-scope members'

    $null = Export-ADPUJsonReport -Topology $t -Path $json
    $obj = Get-Content -LiteralPath $json -Raw | ConvertFrom-Json
    Assert-Equal $obj.Schema 3 'JSON schema version'
    Assert-Equal $obj.Summary.Reserved 1 'JSON summary carries reserved count'
    Assert-Equal $obj.Summary.ExitCode 1 'kitchen sink exit code is 1 (blocked accounts)'
} finally {
    Remove-Item -LiteralPath $html, $json -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
Write-Host ''
$colour = if ($script:failed) { 'Red' } else { 'Green' }
Write-Host ("{0} passed, {1} failed{2}" -f $script:passed, $script:failed, $(if ($env:ADPU_STRICT -eq '1') { ' (strict mode)' } else { '' })) -ForegroundColor $colour
exit $script:failed
