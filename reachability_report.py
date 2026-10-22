#!/usr/bin/env python3
"""CVE reachability report for a Sonatype Lifecycle (IQ Server) scan.

Every vulnerability marked Reachable must have evidence. With --require-evidence
the script exits 2 when evidence is missing and 1 when reachability could not be
read, so the pipeline fails until the evidence file is complete.

Writes report.html, report.csv, report.json and junit.xml (for the GitLab merge
request test widget) to --out. Standard library only: Python 3.11+ for a .toml
evidence file, 3.9+ with .json. IQ Server access uses the variables of the
Sonatype GitLab integration: NEXUS_IQ_URL, NEXUS_IQ_USERNAME, NEXUS_IQ_PASSWORD.

Exit codes: 0 report written, 1 error, 2 evidence missing (with --require-evidence).
"""

from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import html
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

REACHABLE, NOT_REACHABLE, NO_DATA = "Reachable", "Not reachable", "No data"
ORDER = {REACHABLE: 0, NO_DATA: 1, NOT_REACHABLE: 2}
TONE = {REACHABLE: "bad", NO_DATA: "warn", NOT_REACHABLE: "neutral"}
MISSING = "MISSING"

# (row key, column header) for the HTML and CSV report
COLUMNS = [
    ("vulnerability", "Vulnerability"),
    ("cvss", "CVSS"),
    ("component", "Component"),
    ("reachability", "Sonatype Reachability"),
    ("evidence", "Evidence"),
]


class IQError(Exception):
    def __init__(self, what, url, detail="", code=None):
        super().__init__(f"{what} from {url}" + (f": {detail[:300]}" if detail else ""))
        self.what = what
        self.code = code


class IQClient:
    """Minimal read-only client for the IQ Server REST API."""

    def __init__(self, base_url, username, password, cafile=None, timeout=120):
        self.base = base_url.rstrip("/")
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        self.headers = {"Authorization": f"Basic {token}", "Accept": "application/json"}
        self.context = ssl.create_default_context(cafile=cafile)
        self.timeout = timeout

    def get_json(self, path, params=None):
        url = self.base + path + ("?" + urllib.parse.urlencode(params) if params else "")
        request = urllib.request.Request(url, headers=self.headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as err:
            body = err.read().decode("utf-8", "replace")
            raise IQError(f"HTTP {err.code}", url, body, code=err.code) from None
        except OSError as err:
            raise IQError("Connection error", url, str(getattr(err, "reason", err))) from None
        except ValueError:
            raise IQError("Invalid JSON", url, "check that NEXUS_IQ_URL points to the IQ Server") from None


def fail(message):
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


def warn(message):
    print(f"WARNING: {message}", file=sys.stderr)


def quote(value):
    return urllib.parse.quote(str(value), safe="")


def as_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def read_json(path, what):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as err:
        fail(f"Cannot read {what} {path}: {err}")
    except ValueError as err:
        fail(f"{what} {path} is not valid JSON: {err}")


def purl_name_version(purl):
    name, _, version = (purl or "").split("?", 1)[0].partition("@")
    return name.lower(), version


def ident_key(identifier):
    return json.dumps(identifier, sort_keys=True) if identifier else None


def scan_identifiers(result, app_override=None, scan_override=None):
    """(application public ID, report ID, scan ID) from the IQ CLI result file."""
    app = report = None
    for key, pattern in (
        ("reportDataUrl", r"/api/v2/applications/([^/]+)/reports/([^/?#]+)"),
        ("reportHtmlUrl", r"/application/([^/]+)/report/([^/?#]+)"),
    ):
        match = re.search(pattern, str(result.get(key) or ""))
        if match:
            app, report = (urllib.parse.unquote(group) for group in match.groups())
            break
    scan = scan_override or result.get("scanId") or report
    app = app_override or app or result.get("applicationId")
    return app, report or scan, scan


def priorities_from_payload(payload):
    """Accept one API page, a list of pages or a plain list of results."""
    if isinstance(payload, list):
        results = []
        for item in payload:
            if isinstance(item, dict) and "priorities" in item:
                results.extend(priorities_from_payload(item))
            else:
                results.append(item)
        return results
    return list((payload.get("priorities") or {}).get("results") or [])


def fetch_priorities(client, app, scan, page_size):
    path = f"/api/v2/developer/priorities/{quote(app)}/{quote(scan)}"
    results = []
    for page in range(1, 1001):
        block = client.get_json(path, {"page": page, "pageSize": page_size}).get("priorities") or {}
        batch = block.get("results") or []
        results.extend(batch)
        if not batch or page >= int(block.get("pageCount") or 1):
            break
    return results


def load_priorities(client, app, scan, args, expected):
    """Return (priorities, problem). Right after a scan the API can still be empty, so retry."""
    error = None
    for attempt in range(args.retries + 1):
        try:
            found, error = fetch_priorities(client, app, scan, args.page_size), None
        except IQError as err:
            found, error = [], err
            if err.code in (401, 403):
                break
        if found or (error is None and not expected):
            return found, None
        if attempt < args.retries:
            reason = error.what if error else "no components yet"
            print(f"Priorities API: {reason}; retrying in {args.retry_delay:g}s", file=sys.stderr)
            time.sleep(args.retry_delay)
    if error is not None:
        warn(str(error))
        return [], (f"Sonatype's Priorities API is unavailable ({error.what}), so reachability could not be read "
                    "and every row shows No data. Check that the IQ user has the View IQ Elements permission and "
                    "that your license includes Sonatype Developer.")
    return [], (f"Sonatype's Priorities API returned no components although {expected} components have policy "
                "violations, so reachability may not be computed yet. Re-run the job.")


def load_evidence(path):
    """{VULN-ID: [entry, ...]} from a .toml or .json file. Keys starting with '_' are ignored."""
    if not path:
        return {}
    file = Path(path)
    if not file.is_file():
        print(f"Note: evidence file {file} not found, so the Evidence column stays empty.", file=sys.stderr)
        return {}
    text = file.read_text(encoding="utf-8")
    try:
        if file.suffix.lower() == ".toml":
            import tomllib  # Python 3.11+
            data = tomllib.loads(text)
        else:
            data = json.loads(text)
    except ModuleNotFoundError:
        fail("A .toml evidence file needs Python 3.11 or newer; use a .json file on older Python.")
    except ValueError as err:
        fail(f"Could not parse {file}: {err}")
    if not isinstance(data, dict):
        fail(f"{file} must map vulnerability IDs to evidence.")
    entries = {}
    for key, value in data.items():
        if str(key).startswith("_"):
            continue
        accepted = []
        for item in value if isinstance(value, list) else [value]:
            if isinstance(item, str):
                item = {"evidence": item}
            if not isinstance(item, dict):
                warn(f"{file}: entry for {key} is neither text nor a table; ignored.")
                continue
            if not str(item.get("evidence", "")).strip():
                warn(f"{file}: {key} has no evidence text, so it counts as missing.")
            accepted.append(item)
        entries[str(key).strip().upper()] = accepted
    return entries


def find_entry(evidence, vuln_id, purl):
    """Entry scoped to this component if one exists, else the entry without a component."""
    name, version = purl_name_version(purl)
    fallback = None
    for item in evidence.get(vuln_id.upper(), []):
        scope = str(item.get("component", "")).strip()
        if not scope:
            fallback = fallback or item
            continue
        scope_name, scope_version = purl_name_version(scope)
        if scope_name == name and (not scope_version or scope_version == version):
            return item
    return fallback


def component_label(component, priority):
    name = component.get("displayName") or priority.get("displayName")
    if name:
        return name
    coords = (component.get("componentIdentifier") or {}).get("coordinates") or {}
    if coords.get("artifactId"):
        return " : ".join(str(coords.get(k) or "") for k in ("groupId", "artifactId", "version"))
    if coords:
        return " ".join(str(v) for v in coords.values() if v)
    return component.get("packageUrl") or component.get("hash") or "unknown component"


def build_rows(raw, priorities, evidence):
    by_hash, by_ident = {}, {}
    for item in priorities:
        if item.get("componentHash"):
            by_hash[item["componentHash"]] = item
        key = ident_key(item.get("componentIdentifier"))
        if key:
            by_ident[key] = item

    rows = []
    for component in raw.get("components") or []:
        issues = (component.get("securityData") or {}).get("securityIssues") or []
        if not issues:
            continue
        priority = (by_hash.get(component.get("hash"))
                    or by_ident.get(ident_key(component.get("componentIdentifier"))) or {})
        if not priority:
            reach = NO_DATA
        elif priority.get("securityReachable") is True:
            reach = REACHABLE
        else:
            reach = NOT_REACHABLE
        purl = component.get("packageUrl") or ""
        label = component_label(component, priority)
        for issue in issues:
            vuln_id = str(issue.get("reference") or "").strip()
            text = str((find_entry(evidence, vuln_id, purl) or {}).get("evidence", "")).strip()
            rows.append({
                "vulnerability": vuln_id,
                "cvss": as_float(issue.get("severity")),
                "component": label,
                "package_url": purl,
                "reachability": reach,
                "evidence": text,
                "evidence_missing": reach == REACHABLE and not text,
                "component_vulnerability_count": len(issues),
                "advisory_url": issue.get("url") or "",
            })
    rows.sort(key=lambda r: (ORDER[r["reachability"]], not r["evidence_missing"],
                             -(r["cvss"] or 0.0), r["vulnerability"]))
    return rows


def summarize(rows):
    def count(test):
        return sum(1 for r in rows if test(r))

    return {
        "vulnerabilities": len(rows),
        "components": len({r["package_url"] or r["component"] for r in rows}),
        "reachable": count(lambda r: r["reachability"] == REACHABLE),
        "evidence_missing": count(lambda r: r["evidence_missing"]),
        "not_reachable": count(lambda r: r["reachability"] == NOT_REACHABLE),
        "no_data": count(lambda r: r["reachability"] == NO_DATA),
    }


def csv_cell(value):
    if value is None:
        return ""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value  # keep spreadsheet apps from running the text as a formula
    return value


def write_csv(rows, path, delimiter):
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh, delimiter=delimiter)
        writer.writerow([label for _, label in COLUMNS])
        for r in rows:
            values = dict(r, evidence=MISSING if r["evidence_missing"] else r["evidence"])
            writer.writerow([csv_cell(values[key]) for key, _ in COLUMNS])


def write_json(rows, summary, meta, path):
    keep = ("vulnerability", "cvss", "component", "package_url", "reachability", "evidence",
            "evidence_missing", "advisory_url")
    data = {"meta": meta, "summary": summary, "rows": [{k: r[k] for k in keep} for r in rows]}
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def write_junit(rows, path):
    """One test case per vulnerability; reachable ones without evidence fail."""
    suite = ET.Element("testsuite", name="CVE reachability evidence")
    failures = 0
    for r in rows:
        name = r["vulnerability"] + ("" if r["cvss"] is None else f" (CVSS {r['cvss']:.1f})")
        case = ET.SubElement(suite, "testcase", classname=r["component"], name=name)
        if r["evidence_missing"]:
            failures += 1
            node = ET.SubElement(case, "failure", message="Reachable per Sonatype, evidence missing")
            node.text = (f"Sonatype marks {r['component']} as reachable. Add evidence for {r['vulnerability']} "
                         "to the evidence file in a merge request.")
        elif r["evidence"]:
            ET.SubElement(case, "system-out").text = r["evidence"]
    for key, value in (("tests", len(rows)), ("failures", failures), ("errors", 0), ("skipped", 0)):
        suite.set(key, str(value))
    root = ET.Element("testsuites")
    root.append(suite)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


URL_RE = re.compile(r"https?://[^\s<>\"']+")


def linkify(text):
    """Escape text, turn http(s) URLs into links and keep line breaks."""
    out, pos = [], 0
    for match in URL_RE.finditer(text):
        url, trail = match.group(0), ""
        while url and url[-1] in ".,;:)]":
            url, trail = url[:-1], url[-1] + trail
        out.append(html.escape(text[pos:match.start()]))
        out.append(f'<a href="{html.escape(url, quote=True)}">{html.escape(url)}</a>{html.escape(trail)}')
        pos = match.end()
    out.append(html.escape(text[pos:]))
    return "".join(out).strip().replace("\n", "<br>")


CSS = """
:root{color-scheme:light dark;--bg:#ffffff;--fg:#1d2026;--muted:#5d6572;--line:#e2e5ea;--panel:#f6f7f9;--link:#1a5fb4;
--bad:#a3261d;--bad-bg:#fce8e6;--warn:#7a5200;--warn-bg:#fbf0d5;--good:#2d6a32;--good-bg:#e5f2e6;--neutral:#4d5562;--neutral-bg:#eceef2}
@media (prefers-color-scheme:dark){:root{--bg:#14161a;--fg:#e6e8ec;--muted:#9aa1ac;--line:#2b2f37;--panel:#1b1e24;--link:#8ab4f8;
--bad:#ff9b90;--bad-bg:#3a1d1a;--warn:#f0c46a;--warn-bg:#33290f;--good:#9fd0a3;--good-bg:#1a2b1c;--neutral:#b4bac4;--neutral-bg:#262a31}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1240px;margin:0 auto;padding:28px 16px 56px}
h1{font-size:22px;line-height:1.25;margin:0 0 6px}
a{color:var(--link)}
code{font:12.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.meta{color:var(--muted);margin:0 0 20px;display:flex;flex-wrap:wrap;gap:4px 16px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:0 0 16px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.card b{display:block;font-size:26px;line-height:1.2;font-variant-numeric:tabular-nums}
.card small{display:block;color:var(--muted)}
.card.bad b{color:var(--bad)}
.banner{border:1px solid;border-radius:8px;padding:10px 14px;margin:0 0 14px}
.banner p{margin:2px 0}
.banner.bad{color:var(--bad);background:var(--bad-bg);border-color:var(--bad)}
.banner.good{color:var(--good);background:var(--good-bg);border-color:var(--good)}
.banner.neutral{color:var(--neutral);background:var(--neutral-bg);border-color:var(--line)}
.banner code{color:inherit}
.notes{color:var(--muted);margin:0 0 18px;padding-left:18px}
.notes li{margin:3px 0}
.tools{display:flex;flex-wrap:wrap;gap:10px 14px;align-items:center;margin:0 0 10px}
.tools input,.tools select{padding:7px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);font:inherit}
.tools input{flex:1 1 240px;max-width:420px}
#count{color:var(--muted)}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px}
table{width:100%;border-collapse:collapse;min-width:860px}
th,td{text-align:left;vertical-align:top;padding:9px 12px;border-bottom:1px solid var(--line)}
tbody tr:last-child td{border-bottom:none}
th{background:var(--panel);font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.03em}
td:nth-child(3){min-width:230px}td:nth-child(4){min-width:170px}td:nth-child(5){min-width:320px}
tr.attn td:first-child{box-shadow:inset 3px 0 0 var(--bad)}
td.num{font-variant-numeric:tabular-nums;white-space:nowrap}
td.id{font-weight:600;white-space:nowrap}
.sub{display:block;color:var(--muted);font-size:12px;margin-top:3px}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.badge.bad{color:var(--bad);background:var(--bad-bg)}
.badge.warn{color:var(--warn);background:var(--warn-bg)}
.badge.neutral{color:var(--neutral);background:var(--neutral-bg)}
.flag{color:var(--bad);font-weight:600}
.empty{padding:28px;text-align:center;color:var(--muted)}
@media print{.tools{display:none}.wrap{overflow:visible;border:none}table{min-width:0}}
"""

JS = """
const q=document.getElementById('q'),view=document.getElementById('view'),count=document.getElementById('count');
const rows=[...document.querySelectorAll('tbody tr[data-reach]')];
const match={all:()=>true,reachable:r=>r.dataset.reach==='Reachable',missing:r=>r.dataset.missing==='1',
notreachable:r=>r.dataset.reach==='Not reachable',nodata:r=>r.dataset.reach==='No data'};
function apply(){const t=q.value.trim().toLowerCase(),f=match[view.value]||match.all;let shown=0;
rows.forEach(r=>{const ok=f(r)&&(!t||r.textContent.toLowerCase().includes(t));r.hidden=!ok;if(ok)shown++;});
count.textContent=shown+' of '+rows.length+' shown';}
q.addEventListener('input',apply);view.addEventListener('change',apply);apply();
"""


def write_html(rows, summary, meta, path):
    e = html.escape

    def link(url, text):
        if url and re.match(r"https?://", str(url)):
            return f'<a href="{e(str(url), quote=True)}">{e(str(text))}</a>'
        return e(str(text))

    head = [f"<span>Application <b>{e(meta['application'] or '-')}</b></span>",
            f"<span>Scan <code>{e(meta['scan_id'] or '-')}</code></span>",
            f"<span>Generated {e(meta['generated_at'])}</span>"]
    if meta.get("commit"):
        on_ref = f" on {e(meta['ref'])}" if meta.get("ref") else ""
        head.append(f"<span>Commit <code>{e(meta['commit'])}</code>{on_ref}</span>")
    if meta.get("policy_action"):
        head.append(f"<span>Sonatype policy action <b>{e(meta['policy_action'])}</b></span>")
    for url, text in ((meta.get("iq_report_url"), "Sonatype report"), (meta.get("pipeline_url"), "Pipeline")):
        if url:
            head.append(f"<span>{link(url, text)}</span>")

    s = summary
    cards = [
        ("Vulnerabilities", s["vulnerabilities"], f"on {s['components']} components", False),
        ("Reachable", s["reachable"], "marked by Sonatype", False),
        ("Evidence missing", s["evidence_missing"], "reachable, no evidence yet", s["evidence_missing"] > 0),
        ("Not reachable", s["not_reachable"], "no call path found", False),
        ("No data", s["no_data"], "no Sonatype result", False),
    ]
    cards_html = "".join(
        f'<div class="card{" bad" if alert else ""}"><small>{e(title)}</small><b>{value}</b><small>{e(hint)}</small></div>'
        for title, value, hint, alert in cards)

    evidence_file = e(meta.get("evidence_file") or "the evidence file")
    missing = s["evidence_missing"]
    if meta.get("problems"):
        tone, message = "bad", "".join(f"<p>{e(p)}</p>" for p in meta["problems"])
    elif missing:
        what = "vulnerability has" if missing == 1 else "vulnerabilities have"
        consequence = ("; the pipeline fails until every reachable vulnerability has evidence"
                       if meta.get("evidence_required") else "")
        tone = "bad"
        message = (f"<p><b>{missing} reachable {what} no evidence.</b> Add "
                   f"{'it' if missing == 1 else 'them'} to <code>{evidence_file}</code> in a merge request"
                   f"{consequence}.</p>")
    elif s["reachable"]:
        tone = "good"
        message = f"<p>All {s['reachable']} reachable vulnerabilities have evidence.</p>"
    else:
        tone, message = "neutral", "<p>Sonatype marked no vulnerabilities as reachable.</p>"
    banner = f'<div class="banner {tone}">{message}</div>'

    notes = (
        '<ul class="notes">'
        "<li><b>Sonatype Reachability</b> is set per component: every vulnerability on a reachable component "
        "is shown as Reachable, so each one needs its own evidence.</li>"
        "<li><b>Not reachable</b> means Sonatype found no call path from your code. It is not proof: "
        "reflection, native code and classes missing from the scan can hide one. <b>No data</b> means "
        "Sonatype returned no reachability for the component, usually because it has no policy violation.</li>"
        f"<li><b>Evidence</b> comes from <code>{evidence_file}</code> and is required for every Reachable "
        "vulnerability.</li></ul>")

    body = []
    for r in rows:
        cvss = "" if r["cvss"] is None else f"{r['cvss']:.1f}"
        attn = ' class="attn"' if r["evidence_missing"] else ""
        shared = ""
        if r["reachability"] != NO_DATA and r["component_vulnerability_count"] > 1:
            shared = (f'<span class="sub">component-level result, shared by '
                      f'{r["component_vulnerability_count"]} vulnerabilities</span>')
        if r["evidence_missing"]:
            evidence = '<span class="flag">Missing</span><span class="sub">required for reachable vulnerabilities</span>'
        else:
            evidence = linkify(r["evidence"])
        body.append(
            f'<tr{attn} data-reach="{e(r["reachability"])}" data-missing="{1 if r["evidence_missing"] else 0}">'
            f'<td class="id">{link(r["advisory_url"], r["vulnerability"] or "?")}</td>'
            f'<td class="num">{cvss}</td>'
            f'<td>{e(r["component"])}</td>'
            f'<td><span class="badge {TONE[r["reachability"]]}">{e(r["reachability"])}</span>{shared}</td>'
            f"<td>{evidence}</td></tr>")
    if not body:
        body.append(f'<tr><td colspan="{len(COLUMNS)}" class="empty">No vulnerabilities in this scan.</td></tr>')

    header = "".join(f"<th>{e(label)}</th>" for _, label in COLUMNS)
    title = f"CVE reachability · {meta['application'] or 'application'}"
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)}</title><style>{CSS}</style></head>
<body><main>
<h1>{e(title)}</h1>
<p class="meta">{''.join(head)}</p>
<div class="cards">{cards_html}</div>
{banner}{notes}
<div class="tools">
<input id="q" type="search" placeholder="Filter by CVE, component, evidence…" aria-label="Filter rows">
<select id="view" aria-label="Rows to show"><option value="all">All vulnerabilities</option>
<option value="missing">Evidence missing</option><option value="reachable">Reachable</option>
<option value="notreachable">Not reachable</option><option value="nodata">No data</option></select>
<span id="count"></span></div>
<div class="wrap"><table>
<thead><tr>{header}</tr></thead>
<tbody>{''.join(body)}</tbody></table></div>
</main><script>{JS}</script></body></html>
"""
    path.write_text(page, encoding="utf-8")


def toml_key(vuln_id):
    return vuln_id if re.fullmatch(r"[A-Za-z0-9_-]+", vuln_id) else json.dumps(vuln_id)


def print_summary(rows, summary, out, evidence_file):
    s = summary
    print(f"CVE reachability report: {s['vulnerabilities']} vulnerabilities on {s['components']} components")
    print(f"  Reachable {s['reachable']} (evidence missing {s['evidence_missing']}) | "
          f"not reachable {s['not_reachable']} | no data {s['no_data']}")
    print(f"  Written to {out}/: report.html, report.csv, report.json, junit.xml")
    missing = {}
    for r in rows:
        if r["evidence_missing"]:
            missing.setdefault(r["vulnerability"], []).append(r["component"])
    if missing:
        print(f"\nReachable vulnerabilities without evidence. Add these to {evidence_file or 'the evidence file'}"
              " and fill in the evidence:\n")
        for vuln_id, components in missing.items():
            print(f"[{toml_key(vuln_id)}]  # {', '.join(components)}")
            print('evidence = ""\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description="Per-CVE reachability report for a Sonatype Lifecycle scan.")
    parser.add_argument("--result", default="scan-result.json",
                        help="IQ CLI result file written with --result-file (default: scan-result.json)")
    parser.add_argument("--server-url", default=os.environ.get("NEXUS_IQ_URL"),
                        help="IQ Server URL (default: $NEXUS_IQ_URL)")
    parser.add_argument("--app-id", help="application public ID (default: from the result file)")
    parser.add_argument("--scan-id", help="scan ID (default: from the result file)")
    parser.add_argument("--evidence-file", default="security/cve-evidence.toml",
                        help="evidence per vulnerability, .toml or .json (default: security/cve-evidence.toml)")
    parser.add_argument("--out", default="reachability-report", help="output directory")
    parser.add_argument("--require-evidence", action="store_true",
                        help="exit 2 if a Reachable vulnerability has no evidence, 1 if reachability could not be read")
    parser.add_argument("--ca-bundle", help="CA bundle for an IQ Server with an internal certificate")
    parser.add_argument("--csv-delimiter", default=",",
                        help='CSV delimiter, for example ";" for Excel in decimal-comma locales')
    parser.add_argument("--page-size", type=int, default=100, help="Priorities API page size (default: 100)")
    parser.add_argument("--retries", type=int, default=3,
                        help="retries while the Priorities API has no data yet (default: 3)")
    parser.add_argument("--retry-delay", type=float, default=10.0, help="seconds between retries (default: 10)")
    parser.add_argument("--raw-file", help="read the raw report from a file instead of the API")
    parser.add_argument("--priorities-file", help="read Priorities JSON from a file instead of the API")
    args = parser.parse_args(argv)
    if len(args.csv_delimiter) != 1:
        fail("--csv-delimiter must be a single character")

    offline = bool(args.raw_file and args.priorities_file)
    result = {}
    if Path(args.result).is_file():
        result = read_json(args.result, "Result file")
    elif not offline:
        fail(f"Result file {args.result} not found. Run the Sonatype evaluation with --result-file first.")
    app, report, scan = scan_identifiers(result, args.app_id, args.scan_id)

    client = None
    if not offline:
        user, password = os.environ.get("NEXUS_IQ_USERNAME"), os.environ.get("NEXUS_IQ_PASSWORD")
        missing = [name for name, value in (("NEXUS_IQ_URL (or --server-url)", args.server_url),
                                            ("NEXUS_IQ_USERNAME", user), ("NEXUS_IQ_PASSWORD", password))
                   if not value]
        if missing:
            fail("Missing " + ", ".join(missing))
        if not (app and scan):
            fail("No application or scan ID in the result file; pass --app-id and --scan-id.")
        client = IQClient(args.server_url, user, password, cafile=args.ca_bundle)

    if args.raw_file:
        raw = read_json(args.raw_file, "Raw report file")
    else:
        try:
            raw = client.get_json(f"/api/v2/applications/{quote(app)}/reports/{quote(report)}/raw")
        except IQError as err:
            fail(f"Could not read the Sonatype raw report: {err}")
    if not isinstance(raw, dict):
        fail("The raw report has an unexpected format (expected a JSON object with 'components').")

    problems = []
    expected = int((result.get("policyEvaluationResult") or {}).get("affectedComponentCount") or 0)
    if args.priorities_file:
        priorities = priorities_from_payload(read_json(args.priorities_file, "Priorities file"))
    else:
        priorities, problem = load_priorities(client, app, scan, args, expected)
        if problem:
            problems.append(problem)

    rows = build_rows(raw, priorities, load_evidence(args.evidence_file))
    summary = summarize(rows)
    env = os.environ
    meta = {
        "application": app or "",
        "scan_id": scan or "",
        "iq_report_url": result.get("reportHtmlUrl") or "",
        "policy_action": result.get("policyAction") or "",
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "evidence_file": args.evidence_file or "",
        "evidence_required": args.require_evidence,
        "ref": env.get("CI_COMMIT_REF_NAME", ""),
        "commit": env.get("CI_COMMIT_SHORT_SHA", ""),
        "pipeline_url": env.get("CI_PIPELINE_URL", ""),
        "problems": problems,
    }

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    write_csv(rows, out / "report.csv", args.csv_delimiter)
    write_json(rows, summary, meta, out / "report.json")
    write_junit(rows, out / "junit.xml")
    write_html(rows, summary, meta, out / "report.html")
    print_summary(rows, summary, out, args.evidence_file)
    for problem in problems:
        warn(problem)

    if args.require_evidence:
        if problems:
            print("ERROR: Sonatype reachability could not be read, so the evidence requirement cannot be checked.",
                  file=sys.stderr)
            return 1
        if summary["evidence_missing"]:
            print(f"EVIDENCE MISSING: {summary['evidence_missing']} reachable vulnerabilities have no evidence in "
                  f"{args.evidence_file or 'the evidence file'}.", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
