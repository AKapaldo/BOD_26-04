#!/usr/bin/env python3
"""
BOD 26-04 CVE Lookup Tool
Fetches CVE data from the CVE Program's public GitHub (cvelistV5) and extracts the fields required to make remediation timeline decisions under CISA BOD 26-04.

BOD 26-04 Remediation Decision Variables:
  1. Asset Exposure    - Must be determined by your own asset inventory
  2. KEV Status        - In CISA's Known Exploited Vulnerabilities catalog?
  3. Automatable       - Can an adversary automate all exploitation steps?
  4. Technical Impact  - Partial or total control post-exploitation?

Both "If Exposed" and "If Not Exposed" timelines are always shown so you can make the call based on your own asset inventory.

BOD 26-04 Remediation Timelines are determined by the BOD 26-04, Appendix A, Table 1: Remediation Timelines

Data sources (no API keys required):
  CVE records:   https://github.com/CVEProject/cvelistV5  (JSON 5 + Vulnrichment)
  Recent deltas: .../cvelistV5/main/cves/deltaLog.json    (rolling 30-day history)

Usage:
  # Look up one or more specific CVEs
  python3 bod2604_lookup.py CVE-2023-45727
  python3 bod2604_lookup.py CVE-2021-44228 CVE-2023-34362

  # Pull CVEs published/updated in the last N hours (default: 24)
  python3 bod2604_lookup.py --recent
  python3 bod2604_lookup.py --recent --hours 48

  # Recent, but only show KEV entries (much smaller result set)
  python3 bod2604_lookup.py --recent --kev-only

  # Recent, cap results (sorted newest-first, then by severity)
  python3 bod2604_lookup.py --recent --limit 20

  # Machine-readable JSON (pipe-friendly)
  python3 bod2604_lookup.py --recent --kev-only --json | jq '.[] | {cve_id, timeline_if_exposed}'

  # Feed CVE list from a file
  cat cve_list.txt | xargs python3 bod2604_lookup.py
"""

import sys
import json
import re
import argparse
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RAW_CVE_BASE  = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
DELTA_LOG_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"

BOLD = "\033[1m"
RED  = "\033[91m"
YEL  = "\033[93m"
GRN  = "\033[92m"
CYN  = "\033[96m"
DIM  = "\033[2m"
RST  = "\033[0m"

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "N/A": 0}

# ---------------------------------------------------------------------------
# URL builder
# ---------------------------------------------------------------------------

def cve_url(cve_id: str) -> str:
    m = re.fullmatch(r"CVE-(\d{4})-(\d{4,})", cve_id, re.IGNORECASE)
    if not m:
        raise ValueError(f"Invalid CVE ID format: {cve_id}")
    year   = m.group(1)
    seq    = m.group(2)
    bucket = seq[:-3] + "xxx" if len(seq) > 3 else "0xxx"
    return f"{RAW_CVE_BASE}/{year}/{bucket}/{cve_id.upper()}.json"

# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def fetch_json(url: str) -> dict | list:
    req = urllib.request.Request(
        url, headers={"User-Agent": "BOD26-04-Lookup/2.1 (security research)"}
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_recent_cve_ids(hours: int = 24) -> list[dict]:
    """
    Return CVE entries from deltaLog.json published/updated within the last N hours.
    Each entry: {cve_id, github_url, date_updated, change_type}
    Deduplicated; sorted newest-first.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    log    = fetch_json(DELTA_LOG_URL)   # list of hourly snapshot dicts

    seen = {}
    for snapshot in log:
        for change_type in ("new", "updated"):
            for entry in snapshot.get(change_type, []):
                dt_str = entry.get("dateUpdated", "")
                try:
                    dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
                except ValueError:
                    continue
                if dt < cutoff:
                    continue
                cve_id = entry["cveId"]
                if cve_id not in seen or dt > seen[cve_id]["_dt"]:
                    seen[cve_id] = {
                        "cve_id":       cve_id,
                        "github_url":   entry.get("githubLink", ""),
                        "date_updated": dt_str[:19].replace("T", " ") + " UTC",
                        "change_type":  change_type,
                        "_dt":          dt,
                    }

    results = sorted(seen.values(), key=lambda x: x["_dt"], reverse=True)
    for r in results:
        del r["_dt"]
    return results

# ---------------------------------------------------------------------------
# CVE JSON parsers
# ---------------------------------------------------------------------------

def get_english(items: list, key: str = "value") -> str:
    for item in items:
        if item.get("lang", "").lower().startswith("en"):
            return item.get(key, "").strip()
    return items[0].get(key, "").strip() if items else "N/A"


def parse_affected(affected: list) -> list[dict]:
    products = []
    for entry in affected:
        versions = []
        for v in entry.get("versions", []):
            if v.get("status") == "affected":
                ver = v.get("version", "")
                les = v.get("lessThanOrEqual", "")
                lt  = v.get("lessThan", "")
                ver = f"<= {les}" if les else (f"< {lt}" if lt else ver)
                if ver:
                    versions.append(ver)
        products.append({
            "vendor":   entry.get("vendor", "N/A"),
            "product":  entry.get("product", "N/A"),
            "versions": versions or ["(unspecified)"],
        })
    return products


def parse_cvss(metrics: list) -> dict:
    result   = {"version": "N/A", "score": "N/A", "severity": "N/A", "vector": "N/A"}
    priority = {"cvssV4_0": 4, "cvssV3_1": 3, "cvssV3_0": 2, "cvssV2_0": 1}
    best_pri = 0
    for metric in metrics:
        for key, pri in priority.items():
            if key in metric and pri > best_pri:
                best_pri = pri
                m = metric[key]
                result = {
                    "version":  m.get("version", key),
                    "score":    str(m.get("baseScore", "N/A")),
                    "severity": m.get("baseSeverity", "N/A").upper(),
                    "vector":   m.get("vectorString", "N/A"),
                }
    return result


def parse_ssvc_and_kev(adp_list: list) -> dict:
    out = {
        "kev": "NO", "kev_date_added": "N/A", "kev_reference": "N/A",
        "automatable": "N/A", "technical_impact": "N/A",
        "exploitation": "N/A", "ssvc_timestamp": "N/A",
    }
    for adp in adp_list:
        for metric in adp.get("metrics", []):
            other   = metric.get("other", {})
            mtype   = other.get("type", "").lower()
            content = other.get("content", {})
            if mtype == "ssvc":
                for opt in content.get("options", []):
                    if "Exploitation"     in opt: out["exploitation"]     = opt["Exploitation"].lower()
                    if "Automatable"      in opt: out["automatable"]      = opt["Automatable"].capitalize()
                    if "Technical Impact" in opt: out["technical_impact"] = opt["Technical Impact"].capitalize()
                out["ssvc_timestamp"] = content.get("timestamp", "N/A")
            elif mtype == "kev":
                out["kev"]            = "YES"
                out["kev_date_added"] = content.get("dateAdded", "N/A")
                out["kev_reference"]  = content.get("reference", "N/A")
    return out


def parse_cwes(problem_types: list) -> list[str]:
    cwes = []
    for pt in problem_types:
        for d in pt.get("descriptions", []):
            cid  = d.get("cweId", "")
            name = d.get("description", "")
            if cid:
                cwes.append(f"{cid} – {name}" if name else cid)
            elif name.upper().startswith("CWE"):
                cwes.append(name)
    return cwes or ["N/A"]

# ---------------------------------------------------------------------------
# BOD 26-04 timeline calculator
# ---------------------------------------------------------------------------

def bod_timeline(kev: str, exposed: bool, automatable: str, tech_impact: str) -> tuple[str, str]:
    k = kev.upper() == "YES"
    e = exposed
    a = automatable.lower() == "yes"
    t = tech_impact.lower() == "total"

    if e and k and a and t: return "3 DAYS & FORENSIC TRIAGE", "KEV + Exposed + Automatable + Total Impact"
    if e and k and a: return "3 DAYS", "KEV + Exposed + Automatable"
    if e and k and t: return "3 DAYS & FORENSIC TRIAGE", "KEV + Exposed + Total Impact"
    if e and k: return "14 DAYS", "KEV + Exposed"
    if e and a and t: return "3 DAYS", "Exposed + Automatable + Total Impact (not KEV)"
    if e and (a or t): return "30 DAYS", "Exposed + (Automatable OR Total Impact, not KEV)"
    if e: return "60 DAYS", "Exposed"
    if k and a and t: return "3 DAYS & FORENSIC TRIAGE", "KEV + Automatable + Total Impact"
    if k and a: return "14 DAYS", "KEV + Automatable"
    if k and t: return "14 DAYS", "KEV + Total Impact"
    if k: return "14 DAYS", "KEV — asset not publicly exposed"
    if a and t: return "60 DAYS", "Automatable + Total Impact"
    if a: return "60 DAYS", "Automatable"
    return "FIX ON SYSTEM UPGRADE", "Does not meet accelerated criteria"

# ---------------------------------------------------------------------------
# Main lookup
# ---------------------------------------------------------------------------

def lookup_cve(cve_id: str, github_url: str = "") -> dict:
    cve_id = cve_id.strip().upper()
    url    = github_url or cve_url(cve_id)

    try:
        data = fetch_json(url)
    except urllib.error.HTTPError as e:
        return {"cve_id": cve_id, "error": f"HTTP {e.code} – not found or unavailable"}
    except urllib.error.URLError as e:
        return {"cve_id": cve_id, "error": f"Network error: {e.reason}"}
    except Exception as e:
        return {"cve_id": cve_id, "error": str(e)}

    meta     = data.get("cveMetadata", {})
    cna      = data.get("containers", {}).get("cna", {})
    adp_list = data.get("containers", {}).get("adp", [])

    # Prefer Vulnrichment CVSS; fall back to CNA
    vuln_metrics = next(
        (adp.get("metrics", []) for adp in adp_list if adp.get("title") == "CISA ADP Vulnrichment"), []
    )
    all_metrics = vuln_metrics + list(cna.get("metrics", []))

    cvss     = parse_cvss(all_metrics)
    ssvc_kev = parse_ssvc_and_kev(adp_list)

    tl_exp,   r_exp   = bod_timeline(ssvc_kev["kev"], True,  ssvc_kev["automatable"], ssvc_kev["technical_impact"])
    tl_unexp, r_unexp = bod_timeline(ssvc_kev["kev"], False, ssvc_kev["automatable"], ssvc_kev["technical_impact"])

    return {
        "cve_id":                  cve_id,
        "state":                   meta.get("state", "N/A"),
        "published":               meta.get("datePublished", "N/A")[:10],
        "description":             get_english(cna.get("descriptions", [])),
        "severity":                cvss["severity"],
        "cvss_score":              cvss["score"],
        "cvss_version":            cvss["version"],
        "cvss_vector":             cvss["vector"],
        "kev":                     ssvc_kev["kev"],
        "kev_date_added":          ssvc_kev["kev_date_added"],
        "kev_reference":           ssvc_kev["kev_reference"],
        "automatable":             ssvc_kev["automatable"],
        "technical_impact":        ssvc_kev["technical_impact"],
        "exploitation":            ssvc_kev["exploitation"],
        "ssvc_timestamp":          ssvc_kev["ssvc_timestamp"],
        "cwes":                    parse_cwes(cna.get("problemTypes", [])),
        "affected":                parse_affected(cna.get("affected", [])),
        "references":              [r.get("url", "") for r in cna.get("references", []) if r.get("url")],
        "timeline_if_exposed":     tl_exp,
        "reason_if_exposed":       r_exp,
        "timeline_if_not_exposed": tl_unexp,
        "reason_if_not_exposed":   r_unexp,
        "error":                   None,
    }

# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------

def c_sev(s: str)  -> str:
    m = {"CRITICAL": f"{RED}{BOLD}", "HIGH": RED, "MEDIUM": YEL, "LOW": GRN}
    return f"{m.get(s.upper(), '')}{s}{RST}" if s.upper() in m else s

def c_yn(v: str)   -> str:
    return f"{RED}YES{RST}" if v.upper() == "YES" else (f"{GRN}NO{RST}" if v.upper() == "NO" else v)

def c_tl(t: str) -> str:
    if "3 DAYS"   in t: return f"{RED}{BOLD}{t}{RST}"
    if "14 DAYS"  in t: return f"{YEL}{t}{RST}"
    if "30 DAYS"  in t: return f"{YEL}{t}{RST}"
    if "60 DAYS"  in t: return f"{GRN}{t}{RST}"
    return f"{GRN}{t}{RST}"

def c_tech(v: str) -> str:
    return f"{RED}{v}{RST}" if v.lower() == "total" else v

def c_expl(v: str) -> str:
    return f"{RED}{BOLD}{v}{RST}" if v == "active" else (f"{YEL}{v}{RST}" if v == "poc" else v)

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _field(label: str, value: str, c: bool) -> str:
    return (f"  {DIM}{label:<26}{RST} {value}" if c else f"  {label:<26} {value}")

def _section(title: str, c: bool) -> str:
    pad  = max(0, (72 - len(title) - 2) // 2)
    line = f"{'─'*pad} {title} {'─'*pad}"
    return (f"  {DIM}{line}{RST}" if c else f"  {line}")


def print_result(r: dict, c: bool = True) -> None:
    if r.get("error"):
        msg = f"[ERROR] {r['cve_id']}: {r['error']}"
        print(f"\n{RED}{msg}{RST}\n" if c else f"\n{msg}\n")
        return

    sep = "─" * 74
    kev_tag = (f"  {DIM}(added {r['kev_date_added']}){RST}" if c else f"  (added {r['kev_date_added']})") \
              if r["kev"] == "YES" else ""

    hdr = (f"{BOLD}{CYN}{r['cve_id']}{RST}  {DIM}({r['state']} · Published: {r['published']}){RST}"
           if c else f"{r['cve_id']}  ({r['state']} · Published: {r['published']})")

    print(f"\n{hdr}")
    print(sep)
    desc = r["description"]
    print(_field("Description:", desc[:117] + ("…" if len(desc) > 117 else ""), c))

    print()
    print(_section("BOD 26-04 INPUT FIELDS", c))
    print(_field("KEV Status:",        (c_yn(r["kev"]) if c else r["kev"]) + kev_tag, c))
    print(_field("Automatable:",       c_yn(r["automatable"]) if c else r["automatable"], c))
    print(_field("Technical Impact:",  c_tech(r["technical_impact"]) if c else r["technical_impact"], c))
    print(_field("Severity (CVSS):",   f"{c_sev(r['severity']) if c else r['severity']}  {r['cvss_score']} ({r['cvss_version']})", c))
    print(_field("Exploitation:",      c_expl(r["exploitation"]) if c else r["exploitation"], c))

    print()
    print(_section("BOD 26-04 REMEDIATION TIMELINES", c))

    def tl_row(label, tl, reason):
        tl_d = c_tl(tl) if c else tl
        rea  = f"  {DIM}{reason}{RST}" if c else f"  {reason}"
        print(_field(label, f"{tl_d}{rea}", c))

    tl_row("  ⚑ If Asset EXPOSED:",     r["timeline_if_exposed"],     r["reason_if_exposed"])
    tl_row("  ⚑ If Asset NOT Exposed:", r["timeline_if_not_exposed"], r["reason_if_not_exposed"])

    print()
    print(_section("ADDITIONAL CONTEXT", c))
    print(_field("CWE(s):",        " | ".join(r["cwes"]), c))
    print(_field("CVSS Vector:",   r["cvss_vector"], c))
    print(_field("SSVC Scored:",   r["ssvc_timestamp"][:10] if r["ssvc_timestamp"] != "N/A" else "N/A", c))

    print(_field("Affected Products:", "", c))
    bullet = f"{DIM}•{RST}" if c else "•"
    for prod in r["affected"][:5]:
        vers = ", ".join(prod["versions"][:3])
        print(f"    {bullet} {prod['vendor']} – {prod['product']} ({vers})")
    if len(r["affected"]) > 5:
        more = f"  {DIM}… and {len(r['affected'])-5} more{RST}" if c else f"  … and {len(r['affected'])-5} more"
        print(more)

    print(_field("References:", "", c))
    for ref in r["references"][:4]:
        print(f"    {bullet} {ref}")
    if r["kev_reference"] != "N/A" and r["kev_reference"] not in r["references"]:
        print(f"    {bullet} [KEV] {r['kev_reference']}")

    print(sep)
    print()


def print_summary_table(results: list[dict], c: bool = True) -> None:
    hdr = f"{'CVE ID':<20} {'KEV':<5} {'Auto':<5} {'Impact':<9} {'Sev':<9} {'If Exposed':<26} {'If Not Exposed':<23}"
    sep = "─" * len(hdr)
    print(f"\n{BOLD}BOD 26-04 Summary{RST}\n{sep}" if c else f"\nBOD 26-04 Summary\n{sep}")
    print(hdr)
    print(sep)
    for r in results:
        if r.get("error"):
            print(f"{r['cve_id']:<20} ERROR: {r['error']}")
            continue
        row = (f"{r['cve_id']:<20} {r['kev']:<5} {r['automatable']:<5} "
               f"{r['technical_impact']:<9} {r['severity']:<9} "
               f"{r['timeline_if_exposed']:<26} {r['timeline_if_not_exposed']:<23}")
        if c:
            tl = r["timeline_if_exposed"]
            if   "3 DAYS"  in tl: row = f"{RED}{BOLD}{row}{RST}"
            elif "14 DAYS" in tl: row = f"{YEL}{row}{RST}"
            elif "30 DAYS" in tl: row = f"{YEL}{row}{RST}"
        print(row)
    print(sep + "\n")

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="BOD 26-04 CVE Lookup — both Exposed / Not-Exposed timelines always shown",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("cve_ids", nargs="*", metavar="CVE-ID",
                        help="CVE IDs to look up (omit with --recent to pull latest)")
    parser.add_argument("--recent",   action="store_true",
                        help="Fetch CVEs published/updated in the last N hours")
    parser.add_argument("--hours",    type=int, default=24, metavar="N",
                        help="Hours window for --recent (default: 24)")
    parser.add_argument("--kev-only", action="store_true",
                        help="With --recent: only show KEV entries (much smaller set)")
    parser.add_argument("--limit",    type=int, default=0, metavar="N",
                        help="With --recent: cap results at N (sorted: KEV-first, then severity)")
    parser.add_argument("--json",     action="store_true",
                        help="Output raw JSON")
    parser.add_argument("--summary",  action="store_true",
                        help="Print a compact summary table (auto-enabled for 3+ CVEs)")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI color output")
    args = parser.parse_args()

    use_color = not args.no_color and sys.stdout.isatty()

    # ── Recent mode ─────────────────────────────────────────────────────────
    if args.recent or not args.cve_ids:
        hours = args.hours
        print(f"  Fetching CVEs from the last {hours}h via deltaLog.json…", file=sys.stderr)
        try:
            recent_entries = fetch_recent_cve_ids(hours)
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(2)

        if not recent_entries:
            print(f"No CVEs found in the last {hours} hour(s).", file=sys.stderr)
            sys.exit(0)

        total_found = len(recent_entries)
        print(f"  Found {total_found} CVE(s) — fetching details…", file=sys.stderr)

        results = []
        for entry in recent_entries:
            r = lookup_cve(entry["cve_id"], github_url=entry.get("github_url", ""))
            r["_change_type"]  = entry["change_type"]
            r["_date_updated"] = entry["date_updated"]
            results.append(r)

        if args.kev_only:
            results = [r for r in results if r.get("kev") == "YES"]
            print(f"  KEV filter: {len(results)} of {total_found} are in the KEV catalog.", file=sys.stderr)

        if args.limit and len(results) > args.limit:
            results.sort(key=lambda r: (
                0 if r.get("kev") == "YES" else 1,
                -SEV_RANK.get(r.get("severity", "N/A"), 0),
            ))
            results = results[:args.limit]
            print(f"  Capped at {args.limit} result(s) (KEV-first, then by severity).", file=sys.stderr)

    # ── Explicit CVE mode ────────────────────────────────────────────────────
    else:
        results = []
        for cve_id in args.cve_ids:
            cve_id = cve_id.strip()
            if not cve_id:
                continue
            print(f"  Fetching {cve_id}…", file=sys.stderr)
            results.append(lookup_cve(cve_id))

    if not results:
        print("No results.", file=sys.stderr)
        sys.exit(0)

    # ── Output ───────────────────────────────────────────────────────────────
    if args.json:
        clean = [{k: v for k, v in r.items() if not k.startswith("_")} for r in results]
        print(json.dumps(clean, indent=2))
        return

    for r in results:
        if "_change_type" in r:
            ct = r["_change_type"].upper()
            dt = r.get("_date_updated", "")
            r["state"] = r.get("state", "N/A") + f" · {ct} {dt}"
        print_result(r, c=use_color)

    if len(results) > 1 or args.summary:
        print_summary_table(results, c=use_color)

    urgent = any(
        "3 DAYS" in r.get("timeline_if_exposed", "") 
        for r in results if not r.get("error")
    )
    sys.exit(1 if urgent else 0)


if __name__ == "__main__":
    main()
