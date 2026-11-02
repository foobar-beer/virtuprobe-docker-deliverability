#!/usr/bin/env python3
"""
Witness that the library's authentication audit fails each fixture domain for the stated reason.

    python3 tools/witness-audit.py [--api http://127.0.0.1:10101] [--chain PATH]

verify-lab.py proves the lab answers what the README says. This proves the other half: that the
"Deliverability: Authentication audit" chain from the Email Deliverability library, run in a real
VirtuProbe against this lab, passes good.mail.test and fails every broken domain on exactly the
assertions its fixture exists to break and on no others.

WHY EACH ASSERTION RUNS ON ITS OWN
----------------------------------
The chain stops at its first failed assertion. Against broken.mail.test that is the duplicate SPF
record, so a plain run never reaches the revoked DKIM key or the missing MX and cannot say whether
those checks work. So every ASSERT is run in its own slice: all of the chain's lookups, then that one
assertion. A slice that passes or fails is that assertion's verdict on that domain, independent of
the order the chain happens to check things in.

WHAT IT COMPARES AGAINST
------------------------
EXPECTED below is written from the zone files, from what each fixture says it breaks. It is not taken
from a run. A cell that disagrees is a finding about the chain or about the lab. The output says
which assertion and which domain. A slice whose failing step is a lookup rather than the assertion
is reported as an ERROR, because "the DNS step broke" must never read as "the check failed".

Every variable the chain reads is passed on the run, resolver included. The library has no way to
ship default values with a chain, so a slice run without them would query a host literally named
{{resolver}}, find nothing and fail every assertion, good.mail.test included. That was the first run
of this tool. It is the reason the all-PASS column for good.mail.test is the control to read first.

It needs the lab up (verify-lab.py first) and VirtuProbe on --api. It imports one scratch chain per
slice and deletes it straight after, also on a failed run. Stdlib only.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CHAIN = os.path.join(HERE, "..", "..", "virtuprobe-library-deliverability",
                             "deliverability", "chains", "authentication-audit.json")
SCRATCH_PREFIX = "zz witness-audit "

# Assertion step names, as they read in the chain.
SPF_EXISTS = "SPF record exists"
SPF_ONE = "Only one SPF record, because two is a permerror"
SPF_NOT_PLUS = "SPF is not permissive"
SPF_ENDS = "SPF ends in a fail or softfail"
SPF_LOOKUPS = "SPF top record has at most ten DNS-lookup mechanisms"
DMARC_EXISTS = "DMARC record exists"
DMARC_WELL_FORMED = "DMARC record is well formed"
DMARC_ENFORCES = "DMARC actually enforces"
DMARC_REPORTS = "DMARC reports somewhere"
DKIM_EXISTS = "DKIM selector exists"
DKIM_NOT_REVOKED = "DKIM key is not revoked"
MTA_STS = "MTA-STS is published"
HAS_MX = "The domain has an MX"

ALL = [SPF_EXISTS, SPF_ONE, SPF_NOT_PLUS, SPF_ENDS, SPF_LOOKUPS, DMARC_EXISTS, DMARC_WELL_FORMED, DMARC_ENFORCES,
       DMARC_REPORTS, DKIM_EXISTS, DKIM_NOT_REVOKED, MTA_STS, HAS_MX]

# domain -> (variables, the assertions that MUST fail; every other assertion must pass)
EXPECTED = {
    # Everything correct.
    "good.mail.test": ({"dkim_selector": "sel1"}, set()),
    # Present and not enforcing: DMARC p=none with no rua, no MTA-STS. Its selector is weak1.
    # Its SPF names eleven include: lookups, one over the RFC 7208 limit.
    "weak.mail.test": ({"dkim_selector": "weak1"}, {SPF_LOOKUPS, DMARC_ENFORCES, DMARC_REPORTS, MTA_STS}),
    # Two SPF records, revoked DKIM key, DMARC with p=bogus and a rua that is not a URI, no MX.
    "broken.mail.test": ({"dkim_selector": "sel1"},
                         {SPF_ONE, DMARC_WELL_FORMED, DMARC_ENFORCES, DMARC_REPORTS, DKIM_NOT_REVOKED, HAS_MX}),
    # Vendor tokens in TXT and no SPF; no DMARC, no DKIM, no MTA-STS either, but it has an MX.
    "nospf.mail.test": ({"dkim_selector": "sel1"},
                        {SPF_EXISTS, SPF_ENDS, DMARC_EXISTS, DMARC_WELL_FORMED, DMARC_ENFORCES, DMARC_REPORTS,
                         DKIM_EXISTS, DKIM_NOT_REVOKED, MTA_STS}),
    # SPF +all; no DMARC, no DKIM, no MTA-STS; has an MX.
    "spfall.mail.test": ({"dkim_selector": "sel1"},
                         {SPF_NOT_PLUS, SPF_ENDS, DMARC_EXISTS, DMARC_WELL_FORMED, DMARC_ENFORCES, DMARC_REPORTS,
                          DKIM_EXISTS, DKIM_NOT_REVOKED, MTA_STS}),
}

LIMITS = [
    "SPF lookups nested inside an include: the chain counts the top record only. No fixture nests past the limit.",
    "MTA-STS policy fetch: broken.mail.test publishes _mta-sts with no policy file behind it; the chain checks the TXT only.",
]


def req(api, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(api + path, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=120) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]


def slices(chain):
    steps = chain["data"]["steps"]
    lookups = [s for s in steps if s.get("type") not in ("ASSERT", "PRINT")]
    asserts = [s for s in steps if s.get("type") == "ASSERT"]
    for a in asserts:
        yield a["name"], lookups + [a]


def run_slice(api, name, steps, variables):
    """Returns ('PASS'|'FAIL'|'ERROR', detail). Deletes the scratch chain whatever happens."""
    export = {"vpVersion": 1, "type": "chain", "name": SCRATCH_PREFIX + name, "description": "", "tags": [],
              "data": {"name": SCRATCH_PREFIX + name, "steps": steps}}
    status, created = req(api, "POST", "/data/exchange/chain/import", export)
    if status >= 400 or not isinstance(created, dict) or "id" not in created:
        return "ERROR", f"import refused: {status} {created}"
    cid = created["id"]
    try:
        status, res = req(api, "POST", f"/data/chain/{cid}/run", {"variables": variables})
        if status >= 400 or not isinstance(res, dict):
            return "ERROR", f"run refused: {status} {res}"
        results = res.get("stepResults") or []
        summary = res.get("assertionSummary") or {}
        if res.get("success"):
            if summary.get("total", 0) != 1:
                return "ERROR", f"passed with {summary.get('total')} assertions evaluated, expected 1"
            return "PASS", ""
        # Which step failed: the last result is the step that stopped the run.
        failed_at = len(results) - 1
        if failed_at != len(steps) - 1:
            return "ERROR", f"stopped at step {failed_at + 1} ({steps[failed_at].get('name')}), a lookup, not the assertion"
        return "FAIL", ""
    finally:
        # History first: deleting a chain does not delete its runs. They would otherwise sit in
        # the Dashboard's recent runs and pass rate under a chain that no longer exists.
        req(api, "DELETE", f"/data/chain/{cid}/history")
        req(api, "DELETE", f"/data/chain/{cid}")


def sweep(api):
    status, chains = req(api, "GET", "/data/chain/")
    if status == 200 and isinstance(chains, list):
        for c in chains:
            if str(c.get("name", "")).startswith(SCRATCH_PREFIX):
                req(api, "DELETE", f"/data/chain/{c['id']}/history")
                req(api, "DELETE", f"/data/chain/{c['id']}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://127.0.0.1:10101")
    ap.add_argument("--chain", default=DEFAULT_CHAIN)
    args = ap.parse_args()

    chain = json.load(open(args.chain))
    names = [n for n, _ in slices(chain)]
    missing = [n for n in ALL if n not in names]
    unknown = [n for n in names if n not in ALL]
    if missing or unknown:
        print(f"Chain and expectations disagree. In EXPECTED but not the chain: {missing}. "
              f"In the chain but not EXPECTED: {unknown}.")
        return 1

    status, _ = req(args.api, "GET", "/health/check")
    if status != 200:
        print(f"INCONCLUSIVE: VirtuProbe not answering on {args.api} ({status})")
        return 2
    sweep(args.api)

    cells, wrong, errors = 0, [], []
    width = max(len(n) for n in names)
    print(f"{'':{width}}  " + "  ".join(d.split('.')[0][:7].ljust(7) for d in EXPECTED))
    by_name = dict(slices(chain))
    for name in names:
        row = []
        for domain, (extra, must_fail) in EXPECTED.items():
            variables = {"resolver": "127.0.0.1", "resolver_port": "11053", "domain": domain, **extra}
            verdict, detail = run_slice(args.api, name, by_name[name], variables)
            cells += 1
            want = "FAIL" if name in must_fail else "PASS"
            mark = verdict if verdict == want else f"{verdict}!"
            if verdict == "ERROR":
                errors.append(f"{domain} / {name}: {detail}")
            elif verdict != want:
                wrong.append(f"{domain} / {name}: expected {want}, got {verdict}")
            row.append(mark.ljust(7))
        print(f"{name:{width}}  " + "  ".join(row))

    print(f"\n{cells} cells run ({len(names)} assertions x {len(EXPECTED)} domains), "
          f"{len(wrong)} wrong, {len(errors)} errors.")
    for w in wrong:
        print("  WRONG  " + w)
    for e in errors:
        print("  ERROR  " + e)
    print("\nNot covered by this chain, so not witnessed here:")
    for l in LIMITS:
        print("  - " + l)
    if cells == 0:
        return 2
    return 0 if not wrong and not errors else 1


if __name__ == "__main__":
    sys.exit(main())
