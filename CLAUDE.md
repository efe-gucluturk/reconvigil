# ReconVigil — Engineering Standards

ReconVigil is an Attack Surface Management / web recon engine. It sends traffic to
third-party infrastructure, so **safety rules are part of the product**. Every change must
preserve them; tests in `tests/` enforce them.

## Layout
- `src/reconvigil/security/scope.py` — scope validation + SSRF DNS guard (single source of truth)
- `src/reconvigil/security/safe_http.py` — guarded transport/fetcher (scope, SSRF, size cap, timeouts)
- `src/reconvigil/recon/dns_recon.py` — CT + brute-force discovery, DNS records, email posture, takeover
- `src/reconvigil/recon/web_prober.py` — HTTP/TLS probing, header grading, exposed paths
- `src/reconvigil/rules/*.yaml` — takeover fingerprints and exposed-path rules (data, not code)
- `src/reconvigil/storage/state_db.py` — SQLite snapshots + attack-surface drift
- `src/reconvigil/scanner.py` — pipeline; `src/reconvigil/cli.py` — Typer CLI
- `src/reconvigil/reporters/` — terminal/JSON/Markdown/HTML renderers

## Mandatory security invariants
1. **Strict scope.** Only the target root domain and its subdomains (`target.com`, `*.target.com`)
   may be contacted. Matching is on label boundaries (`evil-target.com` and
   `target.com.evil.com` are OUT of scope). Validate with `TargetScope` before *every* request,
   including every redirect hop. Never follow a redirect to an out-of-scope host.
2. **SSRF / DNS-rebinding guard.** `--block-private-ips` is ON by default. Resolve A/AAAA before
   connecting; block `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
   `169.254.0.0/16`, plus loopback/link-local/CGNAT/reserved/multicast and IPv6 equivalents
   (incl. IPv4-mapped). If *any* returned address is blocked, the host is blocked. The validated IP
   is pinned for the connection (URL rewritten to the IP, `Host` + SNI preserved) so DNS cannot
   change between check and use. Cloud metadata IPs stay blocked even with `--allow-private`.
   `--allow-private` is for local lab testing only.
3. **Bounded concurrency.** All fan-out goes through `asyncio.Semaphore`s with explicit limits;
   no unbounded `gather` over attacker-influenced lists (cap candidate counts too).
4. **Strict timeouts.** Separate connect/read timeouts plus a total per-request deadline
   (anti-tarpit). No request without a timeout.
5. **1 MB streaming body cap.** Responses are read via `read_capped` (stream, stop at
   `max_body`, flag `truncated`). Never use `response.read()`/`.text`/`.json()` on unbounded
   streams. The only documented exception is the crt.sh JSON fetch, which uses a larger but still
   bounded cap (`CT_MAX_BYTES`).
6. **No dangerous primitives.** No `eval`, `exec`, `pickle`, `marshal`, `shell=True`,
   `os.system`, or dynamic imports of untrusted input. YAML only via `yaml.safe_load`.
7. **Parameterized SQL only.** Never build SQL with f-strings/concatenation.
8. **No secret retention.** Evidence for exposed secrets (`.env`) records key *names* only,
   never values.
9. **No env proxies.** HTTP clients use `trust_env=False` so ambient proxy vars cannot bypass guards.
10. **Untrusted input everywhere.** DNS answers, HTTP bodies/headers, CT data, wordlists and rule
    files are untrusted; validate with strict pydantic models.

11. **Reports escape everything.** Target-controlled strings (titles, banners, CNAMEs, TLS fields,
    URLs, evidence) go through `reporters.clean()` plus the renderer's own escaping
    (`html.escape`, Markdown escaping, Rich `Text`). HTML reports load no external resources and
    use a hash-pinned CSP. Any new report field must be escaped and covered by the XSS tests.
12. **Safe CLI paths.** `--db`, `--output`, `--wordlist` are validated (no control chars, parent
    must exist, never overwrite a non-SQLite file or the DB). CLI exit codes: 0 clean, 1 findings
    at/above `--fail-on`, 2 scope/input error.

## Engineering standards
- Python 3.12+, `src/` layout, full type hints, pydantic v2 strict models (`strict=True`,
  `extra="forbid"`).
- Tests are 100% offline: `httpx.MockTransport`, local `asyncio` servers on 127.0.0.1, and fake
  DNS/TLS resolvers. Never add a test that touches the internet.
- Every new finding rule needs: severity, CWE ID, remediation, and a positive + negative test
  (false-positive suppression matters as much as detection).

## Required checks (must all pass with 0 errors)
```
ruff check .
bandit -r src/ -c pyproject.toml
pytest -v
```
