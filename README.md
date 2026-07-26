# arsenal

Detection and tooling that came out of my own bug bounty work. Every item here exists because I
needed it on a real target, not because the category looked good on a profile.

The through-line is **oracle discipline**: most of this answers *"is the signal I'm looking at
actually telling me what I think it is?"* — which is where false-positive reports come from, and
where a session gets burned.

| | |
| --- | --- |
| [`nuclei/`](nuclei/) | templates for classes I couldn't find upstream |
| [`wordlists/`](wordlists/) | lists built from requests I actually sent, with provenance |
| [`scripts/`](scripts/) | small standalone tools, standard library only |
| [`burp/`](burp/) | Burp passive scan check (Montoya API) |
| [`caido/`](caido/) | Caido plugin, same detection, unit-tested |

Companion repos: [**writeups**](https://github.com/pablodlz/writeups) for the research,
[**graphql-authz-lab**](https://github.com/pablodlz/graphql-authz-lab) for a target to test
against, [**subdomain-takeover-poc**](https://github.com/pablodlz/subdomain-takeover-poc) for
dangling-DNS findings.

---

## `scripts/phantom-probe.py`

Decides whether a GraphQL mutation response is a usable authorisation oracle, **before** you
spend a session assuming it is. It sends the same mutation with an impossible id, a negative id
and non-base64 garbage, then compares normalised responses.

```bash
./scripts/phantom-probe.py -u https://target/graphql -m deleteAddress \
    -H 'Authorization: Bearer <token>'
```

```
  [200] 10e8e2f71733  accepts   impossible id  (Type:0)
  [200] 10e8e2f71733  accepts   negative id    (Type:-1)
  [200] 10e8e2f71733  accepts   non-base64 garbage

VERDICT: phantom success.
  This mutation is NOT an authorisation oracle. Do not report an IDOR
  from these responses.
```

Exit `1` on phantom success, `0` otherwise, so it drops into a pipeline. Read-only by intent: it
never sends an id that can name a real row unless you pass `--foreign-id` yourself.

## `nuclei/graphql-phantom-success.yaml`

Two stages: confirm a live GraphQL endpoint via `{__typename}` (works with introspection
disabled), then send a mutation with an id that cannot exist and match on a success payload with
an empty error slot.

```bash
nuclei -t nuclei/graphql-phantom-success.yaml -u https://target \
       -var mutation=deleteAddress -var field=error
```

Severity `info` on purpose. The value is reconnaissance — it tells you the whole API is a bad
oracle, which redirects a session — not a bounty on its own.

## `wordlists/`

| file | what it is |
| --- | --- |
| [`auth-bypass-headers.txt`](wordlists/auth-bypass-headers.txt) | ~60 headers backends trust as identity, tenancy or privilege assertions. The first 20 were sent live during one authorisation investigation; none worked, which is exactly why the list is worth publishing. |
| [`graphql-authz-mutations.txt`](wordlists/graphql-authz-mutations.txt) | privileged mutation names for schemas with introspection disabled, plus the error taxonomy that turns guesses into a schema map. |
| [`graphql-endpoints.txt`](wordlists/graphql-endpoints.txt) | ~70 paths where a second, less-protected GraphQL endpoint hides. |

**Not** forks of SecLists. Each file documents where its entries came from. Where a target's own
product name would appear I use `<vendor>` and `<Object>` placeholders, since those namespaces are
first-party and have to be substituted per target.

## `burp/` — passive scan check

Montoya API. Flags a GraphQL mutation whose response is a success payload with an empty error
slot, and the issue text tells you the next step (re-send with an impossible id and diff).

```bash
cd burp && gradle extensionJar     # -> build/libs/arsenal-phantom-success-0.1.0.jar
```

Deliberately **passive only**. The active version would fire state-changing mutations, and a
scanner must not do that unprompted — `phantom-probe.py` is the deliberate version.

## `caido/` — plugin

Same detection. The logic is in [`caido/src/detect.js`](caido/src/detect.js), separate from the
SDK binding so it can be tested without Caido:

```bash
cd caido && npm test     # 17 tests
```

Fixtures are real response shapes captured from `graphql-authz-lab` in both modes, so the tests
pin behaviour that actually exists rather than what I imagined.

---

## Verification status

Being explicit about what I have and haven't run, because "it compiles on my machine" is not a
claim worth making vaguely:

| component | status |
| --- | --- |
| `scripts/phantom-probe.py` | **Executed** against `graphql-authz-lab` in both modes and against an unknown mutation. All three verdicts and exit codes confirmed. |
| `caido/src/detect.js` | **17/17 unit tests passing** on Node 24. |
| `graphql-authz-lab` fixtures | **Executed** — the phantom response and the `--fixed` behaviour are both reproduced. |
| `nuclei/graphql-phantom-success.yaml` | **YAML-validated**, matchers reviewed against the lab's real responses. **Not** executed by `nuclei` itself — no binary on my current machine. Treat the matcher tuning as unproven until you run it. |
| `burp/` | **Not compiled.** No JDK on my current machine. The Montoya imports and `ScanCheck` contract are written against the 2025.x API and reviewed by hand, but expect to fix a signature on first build. |

## Licence

[MIT](LICENSE). Authorised testing only — a permissive licence is not authorization.
