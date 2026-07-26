#!/usr/bin/env python3
"""
phantom-probe — decide whether a GraphQL mutation response is a usable
authorisation oracle, before you spend a session assuming it is.

The test is a differential, not a signature. It sends the same mutation with

  * a structurally impossible object id  (Address:0)
  * a negative id                        (Address:-1)
  * a non-base64 string                  ("phantom-probe-...")
  * optionally, a real foreign id you supply with --foreign-id

If every one of those comes back the same, the response carries zero
authorisation information: you cannot tell "denied" from "no such row" from
"deleted successfully". Stop confirming IDOR from mutation responses on this API
and go measure state in the victim's own session instead.

    ./phantom-probe.py -u https://target/graphql -m deleteAddress \
        -H 'Authorization: Bearer <token>'

    ./phantom-probe.py -u http://127.0.0.1:8099/graphql -m deleteAddress \
        -H 'Authorization: Bearer alice-token' --foreign-id QWRkcmVzczoyMDAx

Standard library only. Read-only by intent: it never sends an id that can name a
real row unless you pass --foreign-id yourself.

Background: https://github.com/pablodlz/writeups/blob/main/web/graphql-phantom-success.md
Lab to try it against: https://github.com/pablodlz/graphql-authz-lab
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request

TIMEOUT = 15

# Wording a resolver uses when it genuinely rejects. Presence of any of these
# means the response DOES distinguish cases — which is the good outcome.
REJECTION = re.compile(
    r"not found|does not exist|no such|forbidden|unauthori[sz]ed|permission|"
    r"denied|invalid id|cannot query field|unknown argument",
    re.I,
)


def gid(type_name: str, raw: str) -> str:
    return base64.b64encode(f"{type_name}:{raw}".encode()).decode()


def normalise(body: str) -> str:
    """Strip values that legitimately vary between identical requests, so two
    responses that differ only by a trace id still compare equal."""
    body = re.sub(r'"(traceId|requestId|x-request-id|timestamp|took|extensions)"\s*:\s*("[^"]*"|\d+|\{[^}]*\})',
                  r'"\1":"<n>"', body, flags=re.I)
    body = re.sub(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "<uuid>", body, flags=re.I)
    return body.strip()


def post(url: str, headers: dict[str, str], query: str) -> tuple[int, str]:
    payload = json.dumps({"query": query}).encode()
    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as res:
            return res.status, res.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"  ! request failed: {e}", file=sys.stderr)
        return 0, ""


def build(mutation: str, field: str, object_id: str) -> str:
    inner = f"{field} {{ detail }}" if field else "__typename"
    return f'mutation {{ {mutation}(id: "{object_id}") {{ {inner} }} }}'


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Differential test for GraphQL mutation phantom success.",
        epilog="Authorised testing only.",
    )
    ap.add_argument("-u", "--url", required=True, help="GraphQL endpoint")
    ap.add_argument("-m", "--mutation", required=True, help="mutation name, e.g. deleteAddress")
    ap.add_argument("-t", "--type", default="Address", help="Relay type name (default: Address)")
    ap.add_argument("-f", "--field", default="error", help="error field in the payload (default: error)")
    ap.add_argument("-H", "--header", action="append", default=[],
                    help="extra header, repeatable: -H 'Authorization: Bearer x'")
    ap.add_argument("--foreign-id", help="a real id belonging to another account (you supply it knowingly)")
    args = ap.parse_args()

    headers: dict[str, str] = {}
    for h in args.header:
        name, _, value = h.partition(":")
        if not value:
            print(f"bad header (expected 'Name: value'): {h}", file=sys.stderr)
            return 2
        headers[name.strip()] = value.strip()

    probes = [
        ("impossible id  (Type:0)", gid(args.type, "0")),
        ("negative id    (Type:-1)", gid(args.type, "-1")),
        ("non-base64 garbage", "phantom-probe-0000"),
    ]
    if args.foreign_id:
        probes.append(("foreign id (user-supplied)", args.foreign_id))

    print(f"endpoint : {args.url}")
    print(f"mutation : {args.mutation}(id:) -> {args.field} {{ detail }}\n")

    results = []
    for label, object_id in probes:
        status, body = post(args.url, headers, build(args.mutation, args.field, object_id))
        norm = normalise(body)
        digest = hashlib.sha256(f"{status}|{norm}".encode()).hexdigest()[:12]
        rejected = bool(REJECTION.search(body))
        results.append({"label": label, "status": status, "digest": digest,
                        "rejected": rejected, "body": body})
        flag = "rejects" if rejected else "accepts"
        print(f"  [{status}] {digest}  {flag:8}  {label}")
        print(f"        {body[:150]}")

    live = [r for r in results if r["status"]]
    if not live:
        print("\nno responses - check the URL and auth.", file=sys.stderr)
        return 2

    digests = {r["digest"] for r in live}
    any_rejection = any(r["rejected"] for r in live)

    print()
    if len(digests) == 1 and not any_rejection:
        print("VERDICT: phantom success.")
        print("  Every probe - including ids that cannot name a real row - returned an")
        print("  identical, non-rejecting response. This mutation is NOT an authorisation")
        print("  oracle. Do not report an IDOR from these responses.")
        print("  Confirm state changes with a second read in the victim's own session.")
        print("  As a finding on its own this is low severity: the API misreports")
        print("  whether anything happened (rows_affected never checked).")
        return 1

    if len(digests) == 1 and any_rejection:
        print("VERDICT: consistent rejection.")
        print("  All probes were rejected the same way. The resolver distinguishes cases;")
        print("  the response is a usable oracle. Carry on with real ids.")
        return 0

    print(f"VERDICT: responses differ ({len(digests)} distinct).")
    print("  The endpoint discriminates between these inputs, so the response does carry")
    print("  information. Diff the bodies above - whatever varies is your oracle, and it")
    print("  may also be an enumeration primitive worth reporting on its own.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
