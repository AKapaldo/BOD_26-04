#!/usr/bin/env python3

"""
NAME
    bod2604_lookup.py - CISA BOD 26-04 CVE Timeline Calculator

SYNOPSIS
    python3 bod2604_lookup.py [CVE-ID ...] [OPTIONS]

DESCRIPTION
    Fetches vulnerability data from the CVE Program's public GitHub (cvelistV5) 
    and evaluates it against CISA BOD 26-04 criteria. The tool calculates accelerated 
    remediation timelines by extracting SSVC Vulnrichment data and checking KEV status.

    Both "If Exposed" and "If Not Exposed" timelines are calculated automatically, 
    allowing you to make final remediation decisions based on your internal asset inventory.

DECISION VARIABLES (BOD 26-04, Appendix A)
    1. Asset Exposure    - Determined by your asset inventory (Exposed / Not Exposed)
    2. KEV Status        - Is the vulnerability in CISA's Known Exploited catalog?
    3. Automatable       - Can an adversary automate all exploitation steps?
    4. Technical Impact  - Does exploitation yield partial or total system control?

DATA SOURCES (No API keys required for base functionality)
    CVE Records:    https://github.com/CVEProject/cvelistV5
    Recent Deltas:  .../cvelistV5/main/cves/deltaLog.json (rolling 30-day history)

ENVIRONMENT VARIABLES
    If using the optional --tenable flag, the following variables must be exported:
    TENABLE_HOST         - The IP or hostname of your Tenable.sc instance
    TENABLE_ACCESS_KEY   - Tenable API access key
    TENABLE_SECRET_KEY   - Tenable API secret key

EXAMPLES
    Lookup specific CVEs:
        python3 bod2604_lookup.py CVE-2023-45727
        python3 bod2604_lookup.py CVE-2021-44228 CVE-2023-34362

    Pull the latest updates from the last 24 hours:
        python3 bod2604_lookup.py --recent

    Pull updates from the last 48 hours, but only show KEV entries:
        python3 bod2604_lookup.py --recent --hours 48 --kev-only

    Pipe machine-readable JSON to jq:
        python3 bod2604_lookup.py --recent --kev-only --json | jq '.[] | {cve_id, timeline_if_exposed}'

    Feed a list of CVEs from a text file:
        cat cve_list.txt | xargs python3 bod2604_lookup.py
"""

__author__ = "Andrew Kapaldo"
__copyright__ = "Copyright 2026, Wildwood Security"
__license__ = "Apache v2.0"
__version__ = "1.0.0"
__maintainer__ = "Andrew Kapaldo"
__status__ = "Production"


import sys
import os
import json
import re
import argparse
import urllib.request
import urllib.error
import concurrent.futures
from datetime import datetime, timezone, timedelta


try:
    from tenable.sc import TenableSC
    HAS_TENABLE = True
except ImportError:
    HAS_TENABLE = False

try:
    import argcomplete
    HAS_ARGCOMPLETE = True
except ImportError:
    HAS_ARGCOMPLETE = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RAW_CVE_BASE  = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
DELTA_LOG_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
ALLOWED_URL_PREFIXES = ("https://raw.githubusercontent.com/CVEProject/",)

FETCH_TIMEOUT   = 20   # seconds per individual HTTP request
FETCH_WORKERS   = 10   # max concurrent CVE fetches

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
    if not any(url.startswith(p) for p in ALLOWED_URL_PREFIXES):
        raise ValueError(f"URL not in allowlist: {url}")
 
    req = urllib.request.Request(
        url,
        headers={"User-Agent": f"BOD26-04-Lookup/{__version__} (security research)"},
    )
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:  # nosec B310 – URL validated above
        return json.loads(resp.read().decode("utf-8"))



def fetch_recent_cve_ids(hours: int = 24) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    log    = fetch_json(DELTA_LOG_URL)

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
    if e and (a or t): return "30 DAYS", "Exposed + Automatable OR Total Impact (not KEV)"
    if e: return "60 DAYS", "Exposed"
    if k and a and t: return "3 DAYS & FORENSIC TRIAGE", "KEV + Automatable + Total Impact"
    if k and (a or t): return "14 DAYS", "KEV + Automatable OR Total Impact"
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
    hdr = f"{'CVE ID':<20} {'KEV':<5} {'Auto':<5} {'Impact':<9} {'Sev':<9} {'If Exposed':<26} {'If Not Exposed':<26}"
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
               f"{r['timeline_if_exposed']:<26} {r['timeline_if_not_exposed']:<26}")
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
        formatter_class=argparse.RawTextHelpFormatter,
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
    parser.add_argument("--full",     action="store_true",
                        help="Print the full detailed output for each CVE")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI color output")
    parser.add_argument("--tenable", action="store_true",
                        help="Pull active CVEs from Tenable.sc (requires 'pytenable' module)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}",
                        help="Show program's version number and exit")
    if HAS_ARGCOMPLETE:
        argcomplete.autocomplete(parser)

    args = parser.parse_args()

    use_color = not args.no_color and sys.stdout.isatty()

    # ── 1. Tenable.sc mode ───────────────────────────────────────────────────
    # If Tenable is used, get the CVEs and add them to args.cve_ids so explicit mode can use them below.
    if args.tenable:
        if not HAS_TENABLE:
            print(f"{RED}ERROR: --tenable requires the 'pytenable' library.{RST}", file=sys.stderr)
            print("Install it with:  pip install pytenable", file=sys.stderr)
            sys.exit(1)

        t_host   = os.environ.get("TENABLE_HOST", "")
        t_access = os.environ.get("TENABLE_ACCESS_KEY", "")
        t_secret = os.environ.get("TENABLE_SECRET_KEY", "")
        missing  = [k for k, v in [
            ("TENABLE_HOST", t_host),
            ("TENABLE_ACCESS_KEY", t_access),
            ("TENABLE_SECRET_KEY", t_secret),
        ] if not v]

        if missing:
            print(f"{RED}ERROR: Missing environment variable(s): {', '.join(missing)}{RST}", file=sys.stderr)
            sys.exit(1)

        try:
            tsc_cves = get_tenable_cves(t_host, t_access, t_secret)
            print(f"  Found {len(tsc_cves)} unique CVE(s) in Tenable.sc.", file=sys.stderr)
            # Merge, preserving any CVEs already specified on the command line
            existing = set(c.upper() for c in cve_list)
            cve_list.extend(c for c in tsc_cves if c not in existing)
        except Exception as e:
            print(f"{RED}Tenable error: {e}{RST}", file=sys.stderr)
            # Non-fatal if CVEs were also supplied on the CLI; fatal otherwise
            if not cve_list:
                sys.exit(1)
            print("  Continuing with CLI-supplied CVEs only.", file=sys.stderr)


    # ── 2. Recent mode ───────────────────────────────────────────────────────
    # Run this if explicitly requested, OR if no CVE IDs were provided at all.
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
        print(f"  Found {total_found} CVE(s) — fetching details concurrently…", file=sys.stderr)

        def fetch_and_enrich(entry):
            r = lookup_cve(entry["cve_id"], github_url=entry.get("github_url", ""))
            r["_change_type"]  = entry["change_type"]
            r["_date_updated"] = entry["date_updated"]
            return r

        with concurrent.futures.ThreadPoolExecutor(max_workers=FETCH_WORKERS) as executor:
            results = list(executor.map(fetch_and_enrich, recent_entries))

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

    # ── 3. Explicit CVE mode ─────────────────────────────────────────────────
    # Run this if CVE IDs exist (either from CLI args or Tenable API)
    else:
        cve_list = [c.strip() for c in args.cve_ids if c.strip()]
        if not cve_list:
            print("No results.", file=sys.stderr)
            sys.exit(0)
            
        print(f"  Fetching {len(cve_list)} CVE(s) concurrently…", file=sys.stderr)
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(lookup_cve, cve_list))

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
            
        # Only print the verbose details if the switch is used
        if args.full:
            print_result(r, c=use_color)

    # Always print the summary table 
    print_summary_table(results, c=use_color)

    urgent = any(
        "3 DAYS" in r.get("timeline_if_exposed", "") 
        for r in results if not r.get("error")
    )
    sys.exit(1 if urgent else 0)


if __name__ == "__main__":
    main()
