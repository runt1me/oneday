#!/usr/bin/env python3
"""
vuln_poc.py — basic PoC to fetch CVEs with CVSS filtering and enrich via NVD.

Pipeline (with graceful fallbacks):
1) Initial fetch:
   - If both --vendor and --product are provided:
       Try OpenCVE API first (vendor/product filters).
       Fallback to CIRCL cve-search if OpenCVE is unavailable.
   - If neither vendor nor product is provided:
       Fetch recent CVEs from NVD for the last --days window (default 7).
2) Filter locally by CVSS >= --min-cvss (default 8.0).
3) Enrich each CVE via NVD's v2.0 API to pull CVSS v3.x scores, vectors, and CPEs.
   Optional: set NVD_API_KEY environment variable to raise rate limits.

Outputs:
- Pretty console table of results
- CSV saved to ./cves.csv (unless --no-save is passed)

Usage examples:
  python vuln_poc.py --vendor microsoft --product edge
  python vuln_poc.py --vendor cisco --product ios --min-cvss 9.0 --limit 50
  python vuln_poc.py --min-cvss 8.5 --days 3              # no vendor/product: get recent NVD CVEs

Notes:
- This is a PoC. Network availability, API changes, and rate limits may affect results.
- OpenCVE may require authentication for some endpoints; we try public first and fallback to CIRCL.
"""

import argparse
import csv
import os
import sys
import time
import datetime as dt
import requests # pip install requests
from typing import Any, Dict, List, Optional, Tuple

OPEN_CVE_BASE = "https://www.opencve.io/api/cve"
CIRCL_SEARCH_BASE = "https://cve.circl.lu/api/search"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Fetch CVEs with CVSS filtering and NVD enrichment.")
    p.add_argument("--vendor", help="Vendor name (e.g., microsoft, cisco).", default=None)
    p.add_argument("--product", help="Product name (e.g., windows_10, ios).", default=None)
    p.add_argument("--min-cvss", type=float, default=8.0, help="Minimum CVSS base score (default: 8.0).")
    p.add_argument("--limit", type=int, default=100, help="Max CVEs to return before enrichment (default: 100).")
    p.add_argument("--days", type=int, default=7, help="Recent days window when vendor/product not provided (default: 7).")
    p.add_argument("--sleep", type=float, default=0.8, help="Seconds to sleep between NVD requests (respect rate limits).")
    p.add_argument("--no-save", action="store_true", help="Do not write cves.csv output.")
    p.add_argument("--verbose", action="store_true", help="Verbose logging.")
    return p.parse_args()


def log(msg: str, verbose: bool):
    if verbose:
        print(msg, file=sys.stderr)


def try_opencve(vendor: str, product: str, limit: int, verbose: bool) -> List[Dict[str, Any]]:
    """
    Try to fetch CVEs from OpenCVE. Public endpoint may support vendor/product filtering.
    We'll attempt simple pagination via 'page' and 'per_page' if available.
    """
    results: List[Dict[str, Any]] = []
    session = requests.Session()

    page = 1
    per_page = min(100, limit)  # try to fetch in chunks
    while len(results) < limit:
        params = {"vendor": vendor, "product": product, "page": page, "per_page": per_page}
        log(f"[OpenCVE] GET {OPEN_CVE_BASE} params={params}", verbose)
        r = session.get(OPEN_CVE_BASE, params=params, timeout=30)
        if r.status_code != 200:
            log(f"[OpenCVE] HTTP {r.status_code}: {r.text[:200]}", verbose)
            break
        data = r.json()
        if not isinstance(data, list) or not data:
            break
        results.extend(data)
        if len(data) < per_page:
            break
        page += 1
    return results[:limit]


def try_circl(vendor: str, product: str, limit: int, verbose: bool) -> List[Dict[str, Any]]:
    """
    Use CIRCL cve-search as a fallback when OpenCVE isn't available.
    """
    url = f"{CIRCL_SEARCH_BASE}/{vendor}/{product}"
    log(f"[CIRCL] GET {url}", verbose)
    r = requests.get(url, timeout=60)
    if r.status_code != 200:
        log(f"[CIRCL] HTTP {r.status_code}: {r.text[:200]}", verbose)
        return []
    data = r.json()
    if isinstance(data, dict) and "results" in data:
        items = data.get("results", [])
    elif isinstance(data, list):
        items = data
    else:
        items = []
    return items[:limit]


def fetch_recent_from_nvd(days: int, limit: int, verbose: bool) -> List[Dict[str, Any]]:
    """
    When vendor/product aren't specified, pull recent CVEs from NVD in the last X days.
    We'll request in pages until we reach 'limit' or run out.
    """
    now = dt.datetime.utcnow()
    start = now - dt.timedelta(days=days)

    # NVD requires ISO8601 timestamps with Z.
    pubStartDate = start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    pubEndDate = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    results: List[Dict[str, Any]] = []
    start_index = 0
    page_size = 200 if limit > 200 else limit
    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    while len(results) < limit:
        params = {
            "pubStartDate": pubStartDate,
            "pubEndDate": pubEndDate,
            "startIndex": start_index,
            "resultsPerPage": min(2000, page_size),
        }
        log(f"[NVD:recent] GET {NVD_CVE_API} params={params}", verbose)
        r = requests.get(NVD_CVE_API, params=params, headers=headers, timeout=60)
        if r.status_code != 200:
            log(f"[NVD:recent] HTTP {r.status_code}: {r.text[:200]}", verbose)
            break
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break
        results.extend(vulns)
        if len(vulns) < page_size:
            break
        start_index += page_size
    return results[:limit]


def extract_cve_ids(initial_items: List[Dict[str, Any]]) -> List[str]:
    """
    Normalize CVE IDs from different sources into a simple list.
    """
    cve_ids: List[str] = []

    for item in initial_items:
        # OpenCVE returns dicts with "cve_id" or "id"? Keep flexible:
        if "cve_id" in item and isinstance(item["cve_id"], str):
            cve_ids.append(item["cve_id"])
            continue
        if "id" in item and isinstance(item["id"], str) and item["id"].startswith("CVE-"):
            cve_ids.append(item["id"])
            continue

        # CIRCL entries often have "id" or "cve":
        if "cve" in item and isinstance(item["cve"], str) and item["cve"].startswith("CVE-"):
            cve_ids.append(item["cve"])
            continue

        # NVD recent list case: nested structure
        if "cve" in item and isinstance(item["cve"], dict):
            meta = item["cve"].get("id") or item["cve"].get("CVE_data_meta", {}).get("ID")
            if isinstance(meta, str) and meta.startswith("CVE-"):
                cve_ids.append(meta)
                continue

    # Deduplicate, preserve order
    seen = set()
    unique = []
    for cid in cve_ids:
        if cid not in seen:
            unique.append(cid)
            seen.add(cid)
    return unique


def extract_cvss_from_circl_item(item: Dict[str, Any]) -> Optional[float]:
    # CIRCL may have "cvss" (v2) and/or "cvss3" fields; handle both.
    for key in ("cvss3", "cvss", "cvss2"):
        val = item.get(key)
        if isinstance(val, (int, float)):
            return float(val)
    return None


def initial_fetch(args: argparse.Namespace) -> Tuple[List[Dict[str, Any]], str]:
    if args.vendor and args.product:
        # Try OpenCVE, fall back to CIRCL
        items = try_opencve(args.vendor, args.product, args.limit, args.verbose)
        if items:
            return items, "opencve"
        items = try_circl(args.vendor, args.product, args.limit, args.verbose)
        return items, "circl"
    else:
        # Pull recent list from NVD
        items = fetch_recent_from_nvd(args.days, args.limit, args.verbose)
        return items, "nvd_recent"


def nvd_get_cve(cve_id: str, api_key: Optional[str], verbose: bool) -> Optional[Dict[str, Any]]:
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    params = {"cveId": cve_id}
    try:
        r = requests.get(NVD_CVE_API, params=params, headers=headers, timeout=60)
        if r.status_code != 200:
            log(f"[NVD:detail] {cve_id} HTTP {r.status_code}: {r.text[:200]}", verbose)
            return None
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        return vulns[0]
    except requests.RequestException as e:
        log(f"[NVD:detail] {cve_id} error: {e}", verbose)
        return None


def nvd_extract_metrics(nvd_item: Dict[str, Any]) -> Tuple[Optional[float], Optional[str], Optional[str]]:
    """
    Return (cvss_base_score, cvss_severity, vector) preferring v3.1 -> v3.0 -> v2.0.
    """
    metrics = nvd_item.get("cve", {}).get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV3", "cvssMetricV2"):
        arr = metrics.get(key)
        if isinstance(arr, list) and arr:
            entry = arr[0]
            data = entry.get("cvssData", {})
            score = data.get("baseScore")
            severity = entry.get("baseSeverity") or data.get("baseSeverity")
            vector = data.get("vectorString")
            return (float(score) if score is not None else None,
                    str(severity) if severity else None,
                    str(vector) if vector else None)
    return (None, None, None)


def nvd_extract_cpes(nvd_item: Dict[str, Any]) -> List[str]:
    cpes: List[str] = []
    configs = nvd_item.get("cve", {}).get("configurations", {})
    nodes = configs.get("nodes", [])
    for node in nodes:
        matches = node.get("cpeMatch", [])
        for m in matches:
            crit = m.get("criteria")
            if isinstance(crit, str) and crit not in cpes:
                cpes.append(crit)
        # children nodes (rare)
        for child in node.get("children", []):
            for m in child.get("cpeMatch", []):
                crit = m.get("criteria")
                if isinstance(crit, str) and crit not in cpes:
                    cpes.append(crit)
    return cpes


def format_table(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return "No results."
    # calculate column widths
    headers = ["CVE", "CVSS", "Severity", "Vector", "Published", "CPE count", "Summary"]
    widths = [len(h) for h in headers]
    for r in rows:
        widths[0] = max(widths[0], len(r["cve"]))
        widths[1] = max(widths[1], len(f'{r.get("cvss","")}'))
        widths[2] = max(widths[2], len(r.get("severity","") or ""))
        widths[3] = max(widths[3], len(r.get("vector","") or ""))
        widths[4] = max(widths[4], len(r.get("published","") or ""))
        widths[5] = max(widths[5], len(str(r.get("cpe_count",0))))
        widths[6] = max(widths[6], len((r.get("summary","") or "")[:80]))
    # build
    def pad(s, w):
        return s + " " * max(0, w - len(s))
    line = " | ".join(pad(h, widths[i]) for i, h in enumerate(headers))
    sep = "-+-".join("-" * widths[i] for i in range(len(headers)))
    out = [line, sep]
    for r in rows:
        out.append(" | ".join([
            pad(r["cve"], widths[0]),
            pad(f'{r.get("cvss","")}', widths[1]),
            pad(r.get("severity","") or "", widths[2]),
            pad(r.get("vector","") or "", widths[3]),
            pad(r.get("published","") or "", widths[4]),
            pad(str(r.get("cpe_count",0)), widths[5]),
            pad((r.get("summary","") or "")[:80], widths[6]),
        ]))
    return "\n".join(out)


def main():
    args = parse_args()
    verbose = args.verbose

    initial_items, source = initial_fetch(args)
    if not initial_items:
        print("No initial results (source: {}).".format(source))
        sys.exit(0)

    # Build an initial list of (CVE, rough_score) from the first hop if present
    cve_ids = extract_cve_ids(initial_items)
    if not cve_ids:
        print("No CVE IDs could be extracted from source:", source)
        sys.exit(0)

    # NVD enrichment & final filtering
    api_key = os.getenv("NVD_API_KEY")
    results: List[Dict[str, Any]] = []
    for idx, cve_id in enumerate(cve_ids):
        nvd_item = nvd_get_cve(cve_id, api_key, verbose)
        if not nvd_item:
            continue

        score, severity, vector = nvd_extract_metrics(nvd_item)
        if score is None or score < args.min_cvss:
            # Skip if score missing or below threshold
            continue

        cpes = nvd_extract_cpes(nvd_item)

        # Timestamps/summary
        cve_core = nvd_item.get("cve", {})
        published = cve_core.get("published")
        descriptions = cve_core.get("descriptions", [])
        summary = ""
        if isinstance(descriptions, list) and descriptions:
            # pick English if possible
            en = next((d for d in descriptions if d.get("lang") == "en"), descriptions[0])
            summary = en.get("value", "")[:300]

        results.append({
            "cve": cve_id,
            "cvss": f"{score:.1f}" if score is not None else "",
            "severity": severity or "",
            "vector": vector or "",
            "published": published or "",
            "cpe_count": len(cpes),
            "summary": summary,
            "cpes": cpes,
        })

        # be kind to NVD rate limits
        if idx < len(cve_ids) - 1:
            time.sleep(args.sleep)

    # Output
    if not results:
        print("No results after CVSS filtering and NVD enrichment (min-cvss = {}).".format(args.min_cvss))
        sys.exit(0)

    # Pretty table
    print(format_table(results))

    # Save CSV unless disabled
    if not args.no_save:
        csv_path = "cves.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["cve","cvss","severity","vector","published","cpe_count","summary","cpes"])
            writer.writeheader()
            for r in results:
                # Join CPEs for CSV readability
                r_copy = dict(r)
                r_copy["cpes"] = " ".join(r_copy.get("cpes", []))
                writer.writerow(r_copy)
        print(f"\nSaved {len(results)} records to {csv_path}")
        print("Tip: open with a spreadsheet or parse in your pipeline.")
    

if __name__ == "__main__":
    main()
