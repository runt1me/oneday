#!/usr/bin/env python3
"""
vuln_poc.py — basic PoC to fetch CVEs with CVSS filtering and enrich via NVD.
"""

import argparse
import csv
import os
import sys
import time
import datetime as dt

try:
    import requests
except ImportError:
    print("This script requires the 'requests' package. Try: pip install requests", file=sys.stderr)
    sys.exit(1)

OPEN_CVE_BASE = "https://www.opencve.io/api/cve"
CIRCL_SEARCH_BASE = "https://cve.circl.lu/api/search"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def parse_args():
    p = argparse.ArgumentParser(description="Fetch CVEs with CVSS filtering and NVD enrichment.")
    p.add_argument("--vendor", help="Vendor name (e.g., microsoft, cisco).", default=None)
    p.add_argument("--product", help="Product name (e.g., windows_10, ios).", default=None)
    p.add_argument("--min-cvss", type=float, default=8.0, help="Minimum CVSS base score (default: 8.0).")
    p.add_argument("--limit", type=int, default=100, help="Max CVEs to return before enrichment (default: 100).")
    p.add_argument("--days", type=int, default=7, help="Recent days window when vendor/product not provided (default: 7).")
    p.add_argument("--sleep", type=float, default=0.8, help="Seconds to sleep between NVD requests (respect rate limits).")
    p.add_argument("--tech", help="Filter by vendor/product/CPE keyword (e.g. coldfusion, apache, windows).")
    p.add_argument("--no-save", action="store_true", help="Do not write cves.csv output.")
    p.add_argument("--verbose", action="store_true", help="Verbose logging.")
    p.add_argument("--min-year", type=int, help="Minimum CVE year (e.g., 2023).")
    return p.parse_args()

def log(msg, verbose):
    if verbose:
        print(msg, file=sys.stderr)

def try_opencve(vendor, product, limit, verbose):
    results = []
    session = requests.Session()
    page = 1
    per_page = min(100, limit)
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

def fetch_recent_from_nvd(days, limit, verbose):
    now = dt.datetime.utcnow()
    start = now - dt.timedelta(days=days)
    pubStartDate = start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    pubEndDate = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    results = []
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

def extract_cve_ids(initial_items):
    cve_ids = []
    for item in initial_items:
        if "cve_id" in item and isinstance(item["cve_id"], str):
            cve_ids.append(item["cve_id"])
            continue

        if "id" in item and isinstance(item["id"], str) and item["id"].startswith("CVE-"):
            cve_ids.append(item["id"])
            continue

        if "cve" in item and isinstance(item["cve"], str) and item["cve"].startswith("CVE-"):
            cve_ids.append(item["cve"])
            continue

        if "cve" in item and isinstance(item["cve"], dict):
            meta = item["cve"].get("id") or item["cve"].get("CVE_data_meta", {}).get("ID")
            if isinstance(meta, str) and meta.startswith("CVE-"):
                cve_ids.append(meta)
                continue

    seen = set()
    unique = []
    for cid in cve_ids:
        if cid not in seen:
            unique.append(cid)
            seen.add(cid)
    
    return unique

def extract_cvss_from_circl_item(item):
    for key in ("cvss3", "cvss", "cvss2"):
        val = item.get(key)
        if isinstance(val, (int, float)):
            return float(val)
    
    return None

def initial_fetch(args):
    if args.vendor and args.product:
        items = try_opencve(args.vendor, args.product, args.limit, args.verbose)
        return items, "opencve"

    else:
        items = fetch_recent_from_nvd(args.days, args.limit, args.verbose)
        return items, "nvd_recent"

def nvd_get_cve(cve_id, api_key, verbose):
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

def nvd_extract_metrics(nvd_item):
    metrics = nvd_item.get("cve", {}).get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV3", "cvssMetricV2"):
        arr = metrics.get(key)
        if isinstance(arr, list) and arr:
            entry = arr[0]
            data = entry.get("cvssData", {})
            score = data.get("baseScore")
            severity = entry.get("baseSeverity") or data.get("baseSeverity")
            vector = data.get("vectorString")
            return (float(score) if score is not None else None, severity, vector)
    
    return (None, None, None)

def nvd_extract_cpes(nvd_item):
    """
    Extract all CPE 'criteria' strings from an NVD 2.0 CVE item.
    Handles configurations as a list (NVD 2.0) and falls back
    gracefully if it is a dict.
    """
    cpes = set()

    def walk_nodes(nodes):
        for node in nodes or []:
            # Direct cpeMatch entries
            for m in node.get("cpeMatch", []):
                crit = m.get("criteria")
                if isinstance(crit, str):
                    cpes.add(crit)

            # Recurse into children if present
            children = node.get("children") or []
            if children:
                walk_nodes(children)

    configs = nvd_item.get("cve", {}).get("configurations", [])

    # NVD 2.0: configurations is typically a list; but be defensive.
    if isinstance(configs, dict):
        configs = [configs]

    if isinstance(configs, list):
        for conf in configs:
            if not isinstance(conf, dict):
                continue
            nodes = conf.get("nodes", [])
            walk_nodes(nodes)

    return list(cpes)

def nvd_extract_vendors_products(nvd_item):
    """
    Use CPEs from configurations to derive sets of vendors and products.
    """
    cpes = nvd_extract_cpes(nvd_item)
    vendors = set()
    products = set()

    for crit in cpes:
        parsed = parse_cpe(crit)
        if not parsed:
            continue
        vendors.add(parsed["vendor"])
        products.add(parsed["product"])

    # Return sorted lists for nicer output
    return sorted(vendors), sorted(products)

def parse_cpe(criteria):
    """
    Parse a CPE 2.3 URI like:
      cpe:2.3:a:vendor:product:version:...
    and return a dict with vendor/product/etc.
    """
    if not isinstance(criteria, str):
        return None

    parts = criteria.split(":")

    # Basic sanity check for CPE 2.3
    if len(parts) < 5:
        return None
    if parts[0] != "cpe" or parts[1] not in ("2.3", "2.2"):
        return None

    return {
        "part": parts[2],                 # a = application, o = OS, h = hardware
        "vendor": parts[3],
        "product": parts[4],
        "version": parts[5] if len(parts) > 5 else "*",
    }

def format_table(rows):
    if not rows:
        return "No results."

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

    cve_ids = extract_cve_ids(initial_items)
    if not cve_ids:
        print("No CVE IDs could be extracted from source:", source)
        sys.exit(0)

    api_key = os.getenv("NVD_API_KEY")

    results = []
    for idx, cve_id in enumerate(cve_ids):
        # Remove old CVEs that just got recently updated
        if args.min_year:
            try:
                year = int(cve_id.split("-")[1])
                if year < args.min_year:
                    continue
            except (IndexError, ValueError):
                pass

        nvd_item = nvd_get_cve(cve_id, api_key, verbose)
        if not nvd_item:
            continue

        score, severity, vector = nvd_extract_metrics(nvd_item)
        if score is None or score < args.min_cvss:
            continue

        cpes = nvd_extract_cpes(nvd_item)
        cve_core = nvd_item.get("cve", {})
        published = cve_core.get("published")
        descriptions = cve_core.get("descriptions", [])
        summary = ""

        vendors, products = nvd_extract_vendors_products(nvd_item)

        if isinstance(descriptions, list) and descriptions:
            en = next((d for d in descriptions if d.get("lang") == "en"), descriptions[0])
            summary = en.get("value", "")[:300]

        if args.tech:
            needle = args.tech.lower()
            haystack = (
                " ".join(cpes + vendors + products + [summary])
            ).lower()
            if needle not in haystack:
                continue

        results.append({
            "cve": cve_id,
            "cvss": f"{score:.1f}" if score is not None else "",
            "severity": severity or "",
            "vector": vector or "",
            "published": published or "",
            "cpe_count": len(cpes),
            "summary": summary,
            "cpes": cpes,
            "vendors": vendors,
            "products": products,
        })

        if idx < len(cve_ids) - 1:
            time.sleep(args.sleep)

    if not results:
        print("No results after CVSS filtering and NVD enrichment (min-cvss = {}).".format(args.min_cvss))
        sys.exit(0)

    print(format_table(results))
    if not args.no_save:
        csv_path = "cves.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "cve",
                    "cvss",
                    "severity",
                    "vector",
                    "published",
                    "cpe_count",
                    "summary",
                    "cpes",
                    "vendors",
                    "products",
                ],
            )
            writer.writeheader()
            for r in results:
                r_copy = dict(r)
                # flatten lists to space-separated strings
                r_copy["cpes"] = " ".join(r_copy.get("cpes", []))
                r_copy["vendors"] = " ".join(r_copy.get("vendors", []))
                r_copy["products"] = " ".join(r_copy.get("products", []))
                writer.writerow(r_copy)

        print(f"\nSaved {len(results)} records to {csv_path}")

if __name__ == "__main__":
    main()