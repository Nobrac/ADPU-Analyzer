<div align="center">

# ADPU-Analyzer

### Which privileged AD accounts can safely go into **Protected Users** — and which still need work first.

![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B%20%7C%207-5391FE?logo=powershell&logoColor=white)
&nbsp;
![Platform: Windows](https://img.shields.io/badge/platform-Windows%20Server-0078D6)
&nbsp;
![Read-only](https://img.shields.io/badge/mode-read--only-16C60C)
&nbsp;
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

<img src="screenshots/report.png" alt="ADPU-Analyzer readiness report" width="840">

</div>

*Protected Users* blocks NTLM, DES/RC4, delegation and credential caching for its members — with no per-account exceptions. Add an admin that still depends on any of that and its sign-in breaks. ADPU-Analyzer reads the directory and the domain controllers' event logs and tells you, per privileged account:

- **clear to enrol** — with how strong the evidence is (*proven*, *plausible*, *unknown*)
- **blocked** — and exactly why (NTLM use, no AES keys, RC4, delegation, …)
- **what it could not see** — auditing gaps, unreachable controllers
- **whether it held** after enrolling (`-Verify`)

It never changes anything. It prints the commands for you to run, including the rollback.

## Quick start

```powershell
.\ADPU-Analyzer.ps1                                   # pick a domain interactively
.\ADPU-Analyzer.ps1 -Domain corp.example.net -Days 30 -HtmlPath .\report.html
.\ADPU-Analyzer.ps1 -Verify -Days 7                   # after enrolling
```

Needs Windows PowerShell 5.1+ or PowerShell 7, WinRM to the domain controllers, rights to read their Security log, and **Logon**, **Kerberos Authentication Service** and **Credential Validation** auditing. No RSAT required.

> [!TIP]
> Enrol one account first, confirm it still signs in end to end, then do the rest.

## Documentation

| | |
| --- | --- |
| [What it checks](docs/checks.md) | blockers, hints, and what no tool can clear you of |
| [How the verdict works](docs/verdict.md) | confidence levels, scoping, break-glass accounts, the krbtgt trap |
| [Setup & auditing](docs/setup.md) | requirements and the audit policy it needs |
| [Usage](docs/usage.md) | all parameters, automation and exit codes, post-enrolment verification |
| [Limitations](docs/limitations.md) | read this before you trust a green verdict |
| [Development](docs/development.md) | repository layout and tests |

> [!NOTE]
> **Built with AI assistance.** Parts of the code and documentation were written with Claude (Anthropic): I defined the requirements, reviewed the results and tested everything in a real Active Directory environment. Review it before running it in production.

## License

[MIT](LICENSE) · Made by Carbon/Nobrac
