<a id="readme-top"></a>

<div align="center">
  
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]

</div>

<br />
<div align="center">
  <a href="https://github.com/AKapaldo/BOD_26-04">
    <img width="200" height="160" alt="Wildwood Security Logo" src="https://github.com/user-attachments/assets/148f76d6-7266-41b3-97ae-044fde0122ac" />
  </a>

<h3 align="center">BOD 26-04 CVE Lookup Tool</h3>

  <p align="center">
    A fast, concurrent command-line tool for evaluating CVEs against CISA BOD 26-04 remediation timelines.
    <br />
    <a href="https://github.com/AKapaldo/BOD_26-04"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/AKapaldo/BOD_26-04/issues/new?labels=bug&template=bug-report---.md">Report Bug</a>
    &middot;
    <a href="https://github.com/AKapaldo/BOD_26-04/issues/new?labels=enhancement&template=feature-request---.md">Request Feature</a>
  </p>
</div>

<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#features">Features</a></li>
        <li><a href="#remediation-timeline-matrix">Remediation Timeline Matrix</a></li>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li>
      <a href="#usage">Usage</a>
    </li>
    <li><a href="#data-sources--schema">Data Sources & Schema</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>

## About The Project

BOD 26-04 establishes mandatory vulnerability remediation timelines for federal agencies based on four decision variables. This tool pulls CVE data directly from the [CVE Program's public repository](https://github.com/CVEProject/cvelistV5) and computes those timelines automatically.

Both the **exposed** and **not-exposed** timelines are always shown side by side — you make the asset exposure call from your own inventory; the tool handles everything else.

| Variable | Source |
|---|---|
| **Asset Exposure** | Self-assessed from your asset inventory |
| **KEV Status** | CISA Known Exploited Vulnerabilities catalog |
| **Automatable** | CISA SSVC decision point (via Vulnrichment) |
| **Technical Impact** | CISA SSVC decision point (via Vulnrichment) |

The three server-side variables (KEV, Automatable, Technical Impact) are published by CISA through the [Vulnrichment Program](https://github.com/cisagov/vulnrichment) and are embedded directly in CVE JSON 5 records — no separate API or key required for core functionality.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Features

- **Dual-Language Support** — Available as both a Python 3 script and a native PowerShell script.
- **Fast Concurrency** — Utilizes parallel execution (`ThreadPoolExecutor` in Python, concurrent fetching batches) to fetch and parse CVE records simultaneously.
- **Zero Dependencies** — The scripts run entirely on standard libraries.
- **Both timelines always shown** — No flags needed; exposed and not-exposed side by side.
- **Recent CVE mode** — Pulls CVEs published or updated in the last N hours via `deltaLog.json`.
- **Assume KEV Mode** — Use `--assume-kev` (or `-AssumeKev`) to simulate remediation timelines as if the vulnerabilities were actively listed in the Known Exploited Vulnerabilities catalog.
- **JSON output** — Pipe-friendly `--json` flag for integration with jq, SIEM, or dashboards.
- **Pipeline exit codes** — Exits `1` if any result has a 3- or 7-day exposed timeline (cron-friendly).

### Remediation Timeline Matrix

| # | Exposed | KEV | Automatable | Technical Impact | Timeline |
|:---:|:---:|:---:|:---:|:---:|:---:|
| 1 | ✅ | ✅ | ✅ | Total | **3 days & Forensic Triage** |
| 2 | ✅ | ✅ | ✅ | Partial | **3 days** |
| 3 | ✅ | ✅ | — | Total | **3 days & Forensic Triage** |
| 4 | ✅ | ✅ | — | Partial | **14 days** |
| 5 | ✅ | — | ✅ | Total | **3 days** |
| 6 | ✅ | — | ✅ | Partial | **14 days** |
| 7 | ✅ | — | — | Total | **14 days** |
| 8 | ✅ | — | — | Partial | **60 days** |
| 9 | — | ✅ | ✅ | Total | **3 days & Forensic Triage** |
| 10 | — | ✅ | ✅ | Partial | **14 days** |
| 11 | — | ✅ | — | Total | **14 days** |
| 12 | — | ✅ | — | Partial | **14 days** |
| 13 | — | — | ✅ | Total | **60 days** |
| 14 | — | — | ✅ | Partial | **60 days** |
| 15 | — | — | — | Total | **Fix on System Upgrade** |
| 16 | — | — | — | Partial | **Fix on System Upgrade** |

### Built With

* [![Python][Python-shield]][Python-url]
* [![PowerShell][PowerShell-shield]][PowerShell-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Getting Started

### Prerequisites

* Python 3.10+ **OR** PowerShell 5.1+
* Internet access to `raw.githubusercontent.com`

### Installation

1. Clone the repo
   ```sh
   git clone [https://github.com/AKapaldo/BOD_26-04.git](https://github.com/AKapaldo/BOD_26-04.git)
   cd BOD_26-04
