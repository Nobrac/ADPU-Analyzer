# Usage

[← Documentation](README.md)

```powershell
.\ADPU-Analyzer.ps1
.\ADPU-Analyzer.ps1 -Domain corp.example.net
.\ADPU-Analyzer.ps1 -Domain corp.example.net -Scope Extended -Days 30
.\ADPU-Analyzer.ps1 -Credential (Get-Credential) -Domain corp.example.net -HtmlPath .\report.html
```

On a multi-domain forest the startup prompt lets you pick one, several, or all domains. Parameters work directly on the script; dot-sourcing also works if you would rather call the functions yourself:

```powershell
. .\ADPU-Analyzer.ps1
Invoke-ADPUAnalyzer -Domain corp.example.net
```

> [!TIP]
> **Enrol one account first**, confirm it still signs in end to end (interactive, RDP, and any dependent services), and only then do the rest. Protected Users takes full effect only on a **fresh logon** — existing tickets and sessions can hide a problem until the account authenticates again. The report prints the rollback command next to the enrolment command for exactly that reason.

## Parameters

| Parameter | Purpose |
| --- | --- |
| `-Domain <string[]>` | One or more domain names to review. Omit to choose interactively. A name that is not in the forest is rejected up front. |
| `-Scope Core\|Extended` | Which groups count as privileged. Default `Core`. |
| `-IncludeGroup <string[]>` | Extra groups to fold in, by SID or by name. |
| `-StrictScope` | Leave out privileged members homed in a domain that is not in scope. |
| `-BreakGlass <string[]>` | Emergency admin accounts to keep outside the group on purpose — by SID, `sAMAccountName` or `DOMAIN\name`. The built-in Administrator (RID 500) always counts. |
| `-Days <int>` | How far back the log harvest reaches. Default `7`; at least `14` for a *Proven* verdict. |
| `-Credential <pscredential>` | Credentials for forest and controller discovery, every directory read, and the remote log reads. From a machine outside the domain, also pass `-Domain`. |
| `-HtmlPath <string>` | Write the self-contained HTML report here (skips the save prompt). |
| `-JsonPath <string>` | Write the machine-readable result here. |
| `-PassThru` | Emit the result object to the pipeline. |
| `-NonInteractive` | Never prompt, never pause — for scheduled runs. |
| `-Verify` | Skip the readiness review and read the Protected Users channels instead. |

## Automation

The run returns a flat, serialisable result object and sets an exit code, so it can sit in a scheduled task and be diffed against the previous run:

```powershell
.\ADPU-Analyzer.ps1 -NonInteractive -Days 30 -JsonPath .\pu-$(Get-Date -f yyyyMMdd).json
```

| Exit code | Meaning |
| --- | --- |
| `0` | Nothing blocked and the evidence was complete. |
| `1` | At least one account is blocked. |
| `2` | No blockers, but the evidence has gaps (auditing off, controller unreachable or only partly read, members from unreviewed domains). |
| `3` | The run could not be completed. |

The JSON (schema `3`) carries the summary, every domain and controller with its audit state and whether it was only partly read, and every account with its blockers and hints as stable `Code` values (`Ntlm4776`, `Ntlm4776Failed`, `NoAesKeys`, `DelegatesOut`, `WeakKerb`, `WeakKerbLegacy`, `Disabled`, …) — so a diff between two runs shows exactly what changed.

## Post-enrolment verification

The readiness review looks backwards; `-Verify` is the other half. Once accounts are in the group, Windows records every time the group turned one away — or let it through — on dedicated channels:

```powershell
.\ADPU-Analyzer.ps1 -Verify -Days 7
```

| Channel (`Microsoft-Windows-Authentication/…`) | Event IDs | Where it lives |
| --- | --- | --- |
| `ProtectedUserFailures-DomainController` | `100`, `104` | Domain controller — an enrolled account still tried NTLM or DES/RC4 |
| `ProtectedUserSuccesses-DomainController` | `303` | Domain controller — an enrolled account authenticated cleanly |
| `ProtectedUser-Client` | `104`, `304` | Workstation — **not** covered by this run |

A channel that exists and is on but cannot be read (access denied, a damaged log) is reported as a blind spot — never as "no failures".

> [!CAUTION]
> All three channels are **disabled by default**. A quiet result from a channel that was never switched on means nothing — the tool tells the two apart and prints the command to enable it:

```powershell
Invoke-Command -ComputerName 'DC01' -ScriptBlock {
    wevtutil sl 'Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController' /e:true
}
```
