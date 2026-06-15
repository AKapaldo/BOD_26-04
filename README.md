# BOD 26-04 CVE Lookup Tool

A command-line tool for pulling CVE data directly from the [CVE Program's public repository](https://github.com/CVEProject/cvelistV5) and computing remediation timelines under [CISA Binding Operational Directive 26-04](https://www.cisa.gov/binding-operational-directive-26-04).

Both the **exposed** and **not-exposed** timelines are always shown side by side — you make the asset exposure call from your own inventory; the tool handles everything else.

---

## Background

BOD 26-04 establishes mandatory vulnerability remediation timelines for federal agencies based on four decision variables:

| Variable | Source |
|---|---|
| **Asset Exposure** | Self-assessed from your asset inventory |
| **KEV Status** | CISA Known Exploited Vulnerabilities catalog |
| **Automatable** | CISA SSVC decision point (via Vulnrichment) |
| **Technical Impact** | CISA SSVC decision point (via Vulnrichment) |

The three server-side variables (KEV, Automatable, Technical Impact) are published by CISA through the [Vulnrichment Program](https://github.com/cisagov/vulnrichment) and are embedded directly in CVE JSON 5 records — no separate API or key required.

### Remediation Timeline Matrix

| # | Exposed | KEV | Automatable | Technical Impact | Timeline |
|:---:|:---:|:---:|:---:|:---:|:---:|
| 1 | ✅ | ✅ | ✅ | Total | **3 days & Forensic Triage** |
| 2 | ✅ | ✅ | ✅ | Partial | **3 days** |
| 3 | ✅ | ✅ | — | Total | **3 days & Forensic Triage** |
| 4 | ✅ | ✅ | — | Partial | **14 days** |
| 5 | ✅ | — | ✅ | Total | **3 days** |
| 6 | ✅ | — | ✅ | Partial | **14 days** |
| 7 | ✅ | — | — | Total | **30 days** |
| 8 | ✅ | — | — | Partial | **60 days** |
| 9 | — | ✅ | ✅ | Total | **3 days & Forensic Triage** |
| 10 | — | ✅ | ✅ | Partial | **14 days** |
| 11 | — | ✅ | — | Total | **14 days** |
| 12 | — | ✅ | — | Partial | **14 days** |
| 13 | — | — | ✅ | Total | **60 days** |
| 14 | — | — | ✅ | Partial | **60 days** |
| 15 | — | — | — | Total | **Fix on System Upgrade** |
| 16 | — | — | — | Partial | **Fix on System Upgrade** |


---

## Features

- **Zero dependencies** — pure Python 3 stdlib (`urllib`, `json`, `re`, `argparse`)
- **Both timelines always shown** — no flags needed; exposed and not-exposed side by side
- **Recent CVE mode** — pulls CVEs published or updated in the last N hours via `deltaLog.json`
- **KEV filter** — `--kev-only` narrows recent results to catalog entries (usually a handful per day)
- **Smart limiting** — `--limit` caps results sorted KEV-first, then by severity
- **JSON output** — pipe-friendly `--json` flag for integration with jq, SIEM, or dashboards
- **Color-coded output** — severity and timelines highlighted at a glance; `--no-color` for logging
- **Pipeline exit codes** — exits `1` if any result has a 3- or 7-day exposed timeline (cron-friendly)

---

## Requirements

- Python 3.10+
- Internet access to `raw.githubusercontent.com`
- No API keys, no third-party packages

---

## Installation

```bash
git clone https://github.com/AKapaldo/BOD_26-04.git
cd BOD_26-04
chmod +x bod2604_lookup.py
```

That's it.

---

## Usage

### Look up specific CVEs

```bash
python3 bod2604_lookup.py CVE-2021-44228
python3 bod2604_lookup.py CVE-2021-44228 CVE-2023-34362 CVE-2023-45727
```

### Pull recent CVEs

```bash
# CVEs published or updated in the last 24 hours (default)
python3 bod2604_lookup.py --recent

# Custom time window
python3 bod2604_lookup.py --recent --hours 6

# Only show entries already in the KEV catalog
python3 bod2604_lookup.py --recent --kev-only

# Cap results at 20, sorted KEV-first then by severity
python3 bod2604_lookup.py --recent --limit 20

# Recommended daily run: KEV entries, top 10 by severity
python3 bod2604_lookup.py --recent --kev-only --limit 10
```

### Feed from a file

```bash
cat cve_list.txt | xargs python3 bod2604_lookup.py
```

### JSON output

```bash
# Full JSON for all results
python3 bod2604_lookup.py CVE-2021-44228 --json

# Filter with jq — only KEV entries from the last 24h
python3 bod2604_lookup.py --recent --json | jq '.[] | select(.kev == "YES")'

# Extract just the decision fields
python3 bod2604_lookup.py --recent --kev-only --json \
  | jq '.[] | {cve_id, kev, automatable, technical_impact, timeline_if_exposed}'
```

### Other flags

```bash
# Disable ANSI color (for log files or non-TTY output)
python3 bod2604_lookup.py CVE-2021-44228 --no-color

# Force a summary table even for a single result
python3 bod2604_lookup.py CVE-2021-44228 --summary
```

---

## Sample Output

```
CVE-2021-44228  (PUBLISHED · Published: 2021-12-10)
──────────────────────────────────────────────────────────────────────────
  Description:               Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in…

  ──────────────────────── BOD 26-04 INPUT FIELDS ────────────────────────
  KEV Status:                YES  (added 2021-12-10)
  Automatable:               Yes
  Technical Impact:          Total
  Severity (CVSS):           CRITICAL  10 (3.1)
  Exploitation:              active

  ─────────────────── BOD 26-04 REMEDIATION TIMELINES ───────────────────
    ⚑ If Asset EXPOSED:      3 DAYS    KEV + Exposed + Automatable + Total Impact
    ⚑ If Asset NOT Exposed:  30 DAYS   KEV — asset not publicly exposed

  ────────────────────────── ADDITIONAL CONTEXT ──────────────────────────
  CWE(s):                    CWE-502 – Deserialization of Untrusted Data
  CVSS Vector:               CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
  SSVC Scored:               2025-02-04
  Affected Products:
    • Apache Software Foundation – Apache Log4j2 (< log4j-core*)
  References:
    • https://logging.apache.org/log4j/2.x/security.html
    • [KEV] https://www.cisa.gov/known-exploited-vulnerabilities-catalog?id=CVE-2021-44228
──────────────────────────────────────────────────────────────────────────
```

Summary table (auto-shown for multiple results):

```
BOD 26-04 Summary
──────────────────────────────────────────────────────────────────────────────────────
CVE ID               KEV   Auto  Impact    Sev       If Exposed       If Not Exposed
──────────────────────────────────────────────────────────────────────────────────────
CVE-2021-44228       YES   Yes   Total     CRITICAL  3 DAYS           30 DAYS
CVE-2023-45727       YES   Yes   Partial   HIGH      7 DAYS           30 DAYS
CVE-2023-34362       YES   Yes   Total     CRITICAL  3 DAYS           30 DAYS
──────────────────────────────────────────────────────────────────────────────────────
```

---

## Data Sources

| Source | URL | Notes |
|---|---|---|
| CVE JSON 5 records | `raw.githubusercontent.com/CVEProject/cvelistV5` | Authoritative CVE data including CISA Vulnrichment ADP container |
| Delta log | `.../cves/deltaLog.json` | Rolling 30-day log of hourly changes; used by `--recent` |

All data is fetched at runtime — no local database, no caching. CVE records are updated continuously by CNAs and enriched by CISA's Vulnrichment Program.

> **Note:** SSVC enrichment (Automatable, Technical Impact) is provided by CISA for a growing subset of CVEs. Records without enrichment will show `N/A` for those fields, and the timeline will reflect what can be computed from the available data.

---


## JSON Schema

Each result object contains:

```json
{
  "cve_id":                  "CVE-2021-44228",
  "state":                   "PUBLISHED",
  "published":               "2021-12-10",
  "description":             "Apache Log4j2 ...",
  "severity":                "CRITICAL",
  "cvss_score":              "10",
  "cvss_version":            "3.1",
  "cvss_vector":             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "kev":                     "YES",
  "kev_date_added":          "2021-12-10",
  "kev_reference":           "https://www.cisa.gov/...",
  "automatable":             "Yes",
  "technical_impact":        "Total",
  "exploitation":            "active",
  "ssvc_timestamp":          "2025-02-04T...",
  "cwes":                    ["CWE-502 – Deserialization of Untrusted Data"],
  "affected":                [{"vendor": "...", "product": "...", "versions": [...]}],
  "references":              ["https://..."],
  "timeline_if_exposed":     "3 DAYS",
  "reason_if_exposed":       "KEV + Exposed + Automatable + Total Impact",
  "timeline_if_not_exposed": "30 DAYS",
  "reason_if_not_exposed":   "KEV — asset not publicly exposed",
  "error":                   null
}
```

---

## Scope and Limitations

- **Asset exposure is not automated.** BOD 26-04 requires agencies to assess which assets are publicly accessible. This tool provides both timeline scenarios. You apply your inventory knowledge.
- **SSVC enrichment coverage.** Not all CVEs have been scored by CISA Vulnrichment. New CVEs may have `N/A` for Automatable/Technical Impact until enrichment is published.
- **Rate limiting.** `raw.githubusercontent.com` is unauthenticated and may throttle bulk requests.
- **Scope.** BOD 26-04 applies to FCEB agencies. This tool is useful for any organization that wants to align with the directive's prioritization methodology.

---

## References

- [CISA BOD 26-04](https://www.cisa.gov/binding-operational-directive-26-04)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA Vulnrichment Program](https://github.com/cisagov/vulnrichment)
- [CVE Program — cvelistV5](https://github.com/CVEProject/cvelistV5)
- [SSVC (Stakeholder-Specific Vulnerability Categorization)](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc)

---

## License

MIT License. See [LICENSE](LICENSE) for details.
