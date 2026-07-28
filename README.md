<div align="center">

# ADPU-Analyzer

### Find out which privileged Active Directory accounts you can safely move into the **Protected Users** group — and which ones still need work first.

A single read-only PowerShell script that surveys a forest, scores every privileged account, and tells you plainly: **who is clear to enrol now**, **who is blocked and why**, and — after enrolling — **whether it actually held**.

![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B%20%7C%207-5391FE?logo=powershell&logoColor=white)
&nbsp;
![Platform: Windows](https://img.shields.io/badge/platform-Windows%20Server-0078D6)
&nbsp;
![Read-only](https://img.shields.io/badge/mode-read--only-16C60C)
&nbsp;
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

[Features](#what-it-checks) · [Screenshots](#screenshots) · [Quick start](#quick-start) · [Verification](#post-enrolment-verification) · [Limitations](#limitations--notes)

</div>

```
   _   ___  ___ _   _      _             _
  /_\ |   \| _ \ | | |___ /_\  _ _  __ _| |_  _ ______ _ _
 / _ \| |) |  _/ |_| |___/ _ \| ' \/ _` | | || |_ / -_) '_|
/_/ \_\___/|_|  \___/   /_/ \_\_||_\__,_|_|\_, /__\___|_|
                                           |__/
```

---

Checking every Windows event log by hand for NTLM logons and weak Kerberos usage — just to be sure an account can join the *Protected Users* group without breaking its sign-in — is tedious and easy to get wrong. So I built this tool to do it for me.

The *Protected Users* group hardens its members against common credential attacks: no NTLM, no DES/RC4 Kerberos, no long-lived credential caching. The catch is that those protections **cannot be turned off per member**. Add an account that still relies on legacy authentication and it may suddenly **fail to log in** — and if that account is a Domain Admin, you find out the hard way. ADPU-Analyzer surfaces that risk *before* you make the change. It never modifies the directory; it prints the `Add-ADGroupMember` commands for you to run yourself.

> [!NOTE]
> **Built with AI assistance.** Parts of the code and this documentation were written with Claude (Anthropic) in a pair-programming workflow: I defined the requirements, reviewed the results, and tested everything in a real Active Directory environment. As with any code you did not write yourself, review it before running it in production.

---

## Contents

- [What it checks](#what-it-checks)
- [How the verdict works](#how-the-verdict-works)
- [Screenshots](#screenshots)
- [Requirements](#requirements)
- [Auditing prerequisites](#auditing-prerequisites)
- [Quick start](#quick-start)
- [Parameter reference](#parameter-reference)
- [Post-enrolment verification](#post-enrolment-verification)
- [Limitations & notes](#limitations--notes)
- [Repository layout](#repository-layout)
- [License](#license)

---

## What it checks

Privileged accounts are everything inside **Administrators**, **Domain Admins**, **Enterprise Admins** and **Schema Admins**, expanded recursively across every domain in scope.

### Blockers — these decide the verdict

| Check | Source | Why it blocks |
| --- | --- | --- |
| **Recent NTLM logon** | Security event **4624**, `AuthenticationPackageName = NTLM` | Members of the group cannot authenticate over NTLM at all. |
| **Recent weak Kerberos** | Security event **4768**, ticket encryption type other than AES | DES/RC4 pre-authentication is refused for members. |
| **Password predates the group** | `pwdLastSet` vs. the group's `whenCreated` | A password set before AES was available leaves the account without modern Kerberos keys. |
| **DES only** | `userAccountControl & 0x200000` (`USE_DES_KEY_ONLY`) | Forces exactly the cipher the group rejects. |
| **No AES in the etype mask** | `msDS-SupportedEncryptionTypes` set, non-zero, without AES128/AES256 | Same result, configured on the account itself. Absent or `0` means the domain default (AES) and is fine. |
| **Wrong account type** | `objectClass` | Computer, service and **gMSA** accounts must never be members — a gMSA gets its own hint pointing at authentication policy silos instead. |
| **Group present & effective** | Domain functional level, DC operating systems | Below 2012 R2 DFL there are client-side protections only; without the group there is nothing to join. |

The two cipher checks come straight out of AD, so unlike the log-based ones they are reliable even when auditing was switched off.

### Hardening hints — informational, never affect the verdict

`adminCount=1` but not in Protected Users · *password never expires* · *no Kerberos pre-auth* (AS-REP roastable) · *unconstrained delegation* · disabled accounts still sitting in admin groups.

---

## How the verdict works

Every pending account ends up in one of two lists, and **both are itemised** — the tool shows its reasoning rather than asking you to trust a green line:

- **Clear to enrol now** — each account lists the evidence its verdict rests on: account type, password age against the group age, the encryption-type configuration, and which controllers were actually searched for NTLM and DES/RC4. Thin evidence is called out in amber, most importantly when a controller could not be read at all.
- **Still blocked** — each account lists only what is holding it back, and nothing else.

> [!IMPORTANT]
> The NTLM and Kerberos checks are **backward-looking**. They see what is in the current event logs, and only where logon auditing was enabled. An account that simply has not used NTLM *recently* looks identical to one that never will.

---

## Screenshots

![Readiness report](screenshots/screenshot-report.png)

*The readiness walkthrough: bottom line first, then the accounts that are clear to enrol — each with the evidence behind the verdict and a ready-to-run command.*

![Blocked accounts](screenshots/screenshot-blocked.png)

*Blocked accounts list only what is holding them back — legacy authentication, cipher configuration, or an account type that does not belong in the group.*

![Post-enrolment verification](screenshots/screenshot-verify.png)

*`-Verify` reads the dedicated Protected Users channels after enrolling: who is still being turned away, and where a channel is switched off and recorded nothing.*

---

## Requirements

- **Windows PowerShell 5.1+** or **PowerShell 7+**. No RSAT and no `ActiveDirectory` module needed — the script uses `System.DirectoryServices` directly.
- Run on, or with line of sight to, a domain controller. **On a DC the session must be elevated**, since reading the local Security log requires it; the script refuses to continue otherwise.
- **WinRM** reachable on the controllers — the log reads run through `Invoke-Command`.
- An account allowed to read the Security log on every domain controller in scope.
- Logon auditing enabled (see below). Without it the tool reports what it could not see rather than pretending the result is complete.

> [!WARNING]
> The audit-policy check selects both subcategories by **GUID**, so it is not affected by the system language there — but it still parses `auditpol`'s *Inclusion Setting* text and expects **English** output (`Success`, `Success and Failure`). On a localised domain controller it will report auditing as off even when it is on.

---

## Auditing prerequisites

`Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies`

| Category → Subcategory | Value | Produces |
| --- | --- | --- |
| Logon/Logoff → **Audit Logon** | `Success` (Success and Failure is fine) | **Event 4624** — the NTLM evidence. |
| Account Logon → **Audit Kerberos Authentication Service** | `Success` | **Event 4768** — the DES/RC4 evidence. |

Both are checked **separately**, per controller, and each one gates only its own evidence: a controller with logon auditing on but Kerberos auditing off contributes NTLM findings and is explicitly excluded from the DES/RC4 conclusion. Where a subcategory is off, the report says the finding is *missing*, not *clean*, and offers the matching `auditpol` command — addressed by GUID, so it works on any system language.

Apply and confirm:

```cmd
gpupdate /force
auditpol /get /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}
auditpol /get /subcategory:{0CCE9242-69AE-11D9-BED3-505054503030}
```

> [!IMPORTANT]
> Events are written **from the moment auditing is enabled — not retroactively.** Give a newly enabled policy a few weeks of normal operation before reading much into a quiet result.

---

## Quick start

Run it and pick a domain when prompted:

```powershell
.\ADPU-Analyzer.ps1
```

To pass parameters, **dot-source first** so the script loads its commands instead of auto-starting:

```powershell
. .\ADPU-Analyzer.ps1
Invoke-ADPUAnalyzer -Domain corp.example.net
Invoke-ADPUAnalyzer -Domain corp.example.net -HtmlPath .\report.html
```

On a multi-domain forest the startup prompt lets you pick one, several, or all domains.

> [!TIP]
> **Enrol one account first**, confirm it still signs in end-to-end (interactive, RDP, and any dependent services), and only then do the rest. Protected Users only takes full effect on a **fresh logon** — existing tickets and sessions can hide a problem until the account authenticates again.

---

## Parameter reference

| Parameter | Purpose |
| --- | --- |
| `-Domain <string[]>` | One or more domain names to review. Omit to choose interactively. |
| `-HtmlPath <string>` | Write the self-contained HTML report to this path (skips the save prompt). |
| `-Verify` | Skip the readiness review and read the Protected Users channels for accounts that are already enrolled. |
| `-Days <int>` | How far back `-Verify` looks. Default `7`. |

The HTML report is a single file with inline CSS and no dependencies — it carries the same findings as the console walkthrough, including the per-account reasoning.

---

## Post-enrolment verification

The readiness review looks backwards; `-Verify` is the other half. Once accounts are in the group, Windows records every time the group turned one away — or let it through — on dedicated channels:

```powershell
. .\ADPU-Analyzer.ps1
Invoke-ADPUAnalyzer -Verify -Days 7
```

| Channel | Event IDs | Where it lives |
| --- | --- | --- |
| `…/ProtectedUserFailures-DomainController` | `100`, `104` | Domain controller — an enrolled account still tried NTLM or DES/RC4 |
| `…/ProtectedUserSuccesses-DomainController` | `303` | Domain controller — an enrolled account authenticated cleanly |
| `…/ProtectedUser-Client` | `104`, `304` | Workstation — **not** covered by this run |

(Full prefix: `Microsoft-Windows-Authentication/`.)

> [!CAUTION]
> All three channels are **disabled by default**. A quiet result from a channel that was never switched on means nothing at all — the tool distinguishes the two and prints the command to enable it:

```powershell
Invoke-Command -ComputerName 'DC01' -ScriptBlock {
    wevtutil sl 'Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController' /e:true
}
```

---

## Limitations & notes

<details>
<summary><strong>Read this before you trust a green verdict</strong></summary>

<br>

- **Backward-looking evidence.** The NTLM and Kerberos checks see only what the current Security logs still hold, and only on controllers that could be read. Log retention silently defines the observation window.
- **NTLM coverage is partial.** Event 4624 on a domain controller records NTLM logons *to that controller*. NTLM against a member server appears on the DC as event **4776**, which this version does not evaluate — so a clean result is weaker evidence than it looks.
- **Failures degrade towards "clear".** If a controller is unreachable, WinRM is closed, or a subcategory was never enabled, the corresponding check returns nothing found. Both audit subcategories are tracked separately and every gap is flagged in amber — in the summary, per controller, and inside each account's reasoning — but the verdict itself does not yet distinguish *no evidence* from *could not look*.
- **English `auditpol` output only** for reading the audit state (see [Requirements](#requirements)); the subcategories themselves are selected by GUID and are language-independent.
- **Password age is a proxy.** "Password predates the group" approximates "the account has no AES keys". The precise trigger is the domain functional level being raised, not the group's creation.
- **Blind spots it cannot see at all:** Kerberos time skew, external trusts that do not support AES, non-domain-joined or offline clients, and applications that hardcode NTLM.

The tool flags **known blockers** from the evidence available; it cannot guarantee a sign-in will not break. Treat the recommendation as a well-informed starting point, not a promise.

</details>

---

## Repository layout

```
README.md                 this file
LICENSE                   MIT
ADPU-Analyzer.ps1         the whole tool (single file, read-only)
screenshots/              images used in this README
```

## License

[MIT](LICENSE) — see the `LICENSE` file.

<div align="center">

Made by Carbon/Nobrac

</div>
