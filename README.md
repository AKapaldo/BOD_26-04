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
   ```
2. (Mac/Linux) Make the Python script executable
   ```sh
   chmod +x bod_2604_lookup.py
   ```

## Usage

> Note: The examples below use the Python script. If you are on Windows, simply replace python3 bod2604_lookup.py with .\bod2604_lookup.ps1 and use standard PowerShell -Parameter syntax instead of --flag syntax.

### Look up specific CVEs

```sh
python3 bod2604_lookup.py CVE-2021-44228
python3 bod2604_lookup.py CVE-2021-44228 CVE-2023-34362 CVE-2023-45727
```

### Assume KEV Status

Assess a vulnerability as if it is in the KEV catalog, regardless of its current status:

```sh
python3 bod2604_lookup.py CVE-2024-1234 --assume-kev
```

### Pull recent CVEs

```sh
# CVEs published or updated in the last 24 hours (default)
python3 bod2604_lookup.py --recent

# Custom time window
python3 bod2604_lookup.py --recent --hours 6

# Only show entries already in the KEV catalog
python3 bod2604_lookup.py --recent --kev-only

# Cap results at 20, sorted KEV-first then by severity
python3 bod2604_lookup.py --recent --limit 20
```

### JSON Output

```sh
# Full JSON for all results
python3 bod2604_lookup.py CVE-2021-44228 --json

# Extract just the decision fields via jq
python3 bod2604_lookup.py --recent --kev-only --json \
  | jq '.[] | {cve_id, kev, automatable, technical_impact, timeline_if_exposed}'
```

## Data Sources & Schema

| Source | URL | Notes |
|--------|-----|-------|
CVE JSON 5 records | raw.githubusercontent.com/CVEProject/cvelistV5 | authoritative CVE data including CISA Vulnrichment ADP container|
Delta log| `.../cves/deltaLog.json` | Rolling 30-day log of hourly changes; used by `--recent` | 

All data is fetched at runtime. No local database, no caching.

> [!Note]
> SSVC enrichment (Automatable, Technical Impact) is provided by CISA for a growing subset of CVEs.
> Records without enrichment will show N/A for those fields, and the timeline will reflect what can be computed from the available data.

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

Distributed under the Apache V2.0 License. See `LICENSE.txt` for more information.

## Contact

Andrew Kapaldo - Wildwood Security

Project Link: [https://github.com/AKapaldo/BOD_26-04](https://github.com/AKapaldo/BOD_26-04) 


[contributors-shield]: https://img.shields.io/github/contributors/AKapaldo/BOD_26-04.svg?style=for-the-badge
[contributors-url]: https://github.com/AKapaldo/BOD_26-04/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/AKapaldo/BOD_26-04.svg?style=for-the-badge
[forks-url]: https://github.com/AKapaldo/BOD_26-04/network/members
[stars-shield]: https://img.shields.io/github/stars/AKapaldo/BOD_26-04.svg?style=for-the-badge
[stars-url]: https://github.com/AKapaldo/BOD_26-04/stargazers
[issues-shield]: https://img.shields.io/github/issues/AKapaldo/BOD_26-04.svg?style=for-the-badge
[issues-url]: https://github.com/AKapaldo/BOD_26-04/issues
[license-shield]: https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge
[license-url]: https://opensource.org/licenses/Apache-2.0
[Python-shield]: https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white
[Python-url]: https://python.org/ 
[PowerShell-url]: https://learn.microsoft.com/en-us/powershell/
[PowerShell-shield]: https://img.shields.io/badge/PowerShell-2B4A6E?style=for-the-badge&logo=powershell&logoColor=white
