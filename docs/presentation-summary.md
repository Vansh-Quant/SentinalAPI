# SentinelAPI — Presentation Summary

## What it is (one sentence)

SentinelAPI is a **zero-trust API vulnerability scanner**: you give it an OpenAPI 3.x specification and test credentials for a running API, and it actively probes that API to prove whether one authenticated user can access another user's objects (**BOLA/IDOR**) or whether responses leak sensitive properties beyond the documented contract (**BOPLA**) — then delivers evidence-backed findings, reproducible PoC commands, a scored dashboard, an attack-surface graph, and an executive report.

---

## 1. The problem it solves

Two of the OWASP API Top 10 risks are authorization failures, and almost no tool tests them automatically:

| Risk | Plain meaning | Real-world example |
|---|---|---|
| **BOLA** (Broken Object Level Authorization) | "Can Alice read *Bob's* data by changing an ID in the URL?" | Change `/orders/101` to `/orders/102` and the server shows you someone else's order |
| **BOPLA** (Broken Object Property Level Authorization) | "Does the API return fields the user should never see?" | A user profile response that includes `password_hash` or `internal_notes` |

Traditional scanners test for *technical* flaws (SQLi, XSS). SentinelAPI targets **authorization logic** — the class of bug that caused the biggest real-world API breaches.

**Its differentiator:** it doesn't just warn — it **proves** the flaw with a captured HTTP exchange (baseline vs attack request/response) and a ready-to-run curl PoC.

---

## 2. How a scan works (the flow to narrate)

```
Browser (frontend/app.js)
   │  1. Sign in (JWT) → create project → upload OpenAPI spec
   │  2. Provide 2 test identities (user_a, user_b) + target URL
   ▼
FastAPI backend (backend/app/main.py, api/scans.py)
   │  3. Validates ownership, spec, and the TARGET itself
   ▼
Scan Manager (services/scan_manager.py)
   │  4. Zero-Trust gate: target must resolve to a private/loopback IP
   │  5. Queues the scan, streams progress over WebSocket
   ▼
Scanner Engine (scanner/service.py)
   │  6. Logs in as BOTH identities against the live target
   │  7. Runs BOLA + BOPLA tests (details below)
   │  8. Returns findings + full HTTP evidence
   ▼
Persistence (Finding + Evidence rows, services/security_sanitizer.py)
   │  9. Secrets redacted before storage; WS "finding" events pushed live
   ▼
Dashboard / Finding Explorer / PoC / Report (frontend views)
```

Everything the audience sees in the UI was fetched from a real scan that really hit the target API.

---

## 3. What it actually detects

### BOLA — active cross-identity testing

1. **Log in as Alice** and **as Bob** (identities from the scan form).
2. **Ownership harvest:** as each identity, call list endpoints (`/orders`, `/profile`) and record *which object IDs each identity legitimately sees* → Alice={101,103}, Bob={102,104}.
3. **Cross-identity attack:** request Bob's object ID **while authenticated as Alice**.
4. **Verdict:** if the attack returns HTTP 2xx **and** the response body contains Bob's object — confirmed BOLA.
5. Both directions are tested (Alice→Bob and Bob→Alice), with baseline (own object) vs attack (foreign object) requests captured side-by-side.

Evidence stored per finding: baseline request/response, attack request/response, the cross-identity object ID, and the owner identity.

### BOPLA — contract vs reality

1. Read the OpenAPI spec's **declared response schema** for each endpoint (what the API *promises* to return).
2. Call the endpoint as a real identity and capture what it **actually** returns.
3. Sensitive-property list (passwords, tokens, keys, notes, payment data…) ∩ (returned) − (documented) = **exposure**.
4. Finding names the exact leaked properties — e.g. `password_hash`, `internal_notes`.

This is deliberately **schema-aware**: a field documented in the spec is treated as intended; only *undocumented sensitive* fields are flagged — cutting false positives.

### Bounded execution (safety)

The scanner is not an attack cannon: every scan has a hard budget (requests + wall-clock). If cut short, verified findings gathered so far are kept and a notice is attached.

---

## 4. Live results from the demo scan (the numbers to show)

Target: the bundled intentionally-vulnerable sandbox, spec with 6 endpoints:

| Metric | Value |
|---|---|
| Endpoints discovered | 6 |
| Tests executed | 21 |
| Findings | **5** (4× BOLA HIGH, 1× BOPLA HIGH) |
| Security score | **25/100** (deterministic: 100 − 15×5 HIGH) |
| Scan duration | ~0.4s |

Findings found in the live demo:
- BOLA on `/orders/{order_id}` — both directions: Alice reads Bob's orders 102/104, Bob reads Alice's 101/103
- BOLA on `/users/{user_id}` — both directions: full profile of any user, no ownership check
- BOPLA on `/users` — response leaks `password_hash` + `internal_notes`, undocumented in the spec

**Equally important — what it did NOT flag (false-positive controls):**
- `/orders` (list) returns only the caller's orders → no BOLA finding
- `/profile` returns only own data → no BOLA finding
- `/products` returns only public fields → no BOPLA finding

---

## 5. Feature tour (what to click, in order)

1. **Landing page** — product intro, "Start Security Scan" / "View Demo".
2. **Auth** — register/sign in; JWT stored client-side; every API call authenticated; **each user sees only their own projects/scans/findings** (404, not 403, so existence isn't leaked).
3. **Scan Configuration** — upload OpenAPI 3.x (JSON/YAML), set target, provide sandbox identities; the form states the Zero-Trust policy.
4. **Live Testing** — real-time progress (polling + authenticated WebSocket), live finding counter, Cancel button for queued/running scans.
5. **Security Overview** — security score ring, severity donut, tests completed, endpoints.
6. **Network Graph (Attack Surface)** — all discovered endpoints as nodes, color-coded by risk (red=critical, amber=high, yellow=medium incl. "no auth declared", teal=safe), plus related-findings counts.
7. **Finding Explorer** — filter by severity/status/text; every finding links to evidence.
8. **Investigation** — full description, impact, remediation, captured evidence JSON, status workflow (open → in_review → mitigated → resolved / false_positive).
9. **Proof of Concept** — the reproducible curl command for the finding.
10. **AI Explanation** — plain-language "what happened / why it matters / how to fix".
11. **Security Report** — executive summary, severity counts, recommendations, **client-side PDF download**, share link.

---

## 6. The Zero-Trust target policy (a key talking point)

A scanner that accepts arbitrary URLs is itself an attack tool. SentinelAPI enforces the sandbox-only policy at **three layers**:

1. **At queue time** — target hostname must be in the allowlist (localhost/private ranges/configured sandbox host).
2. **DNS reality check** — the hostname must *resolve* to private/loopback/link-local addresses, defeating tricks like `10.0.0.1.evil.com`.
3. **At execution time** — re-validated again immediately before the scanner fires, and redirects are disabled everywhere so a scan can never be bounced to a public host.

Try scanning `https://any-public-site.com` → rejected with a clear reason, and the scan is marked failed with that reason recorded.

---

## 7. Architecture in one slide

```
Frontend (single-page app: app.js + styles.css, served by the backend)
   │ REST + authenticated WebSocket (/ws/scans/{id})
   ▼
FastAPI Backend (JWT auth, ownership checks, upload validation)
   │ Scan Manager (lifecycle: queued → running → completed/failed/cancelled)
   │ Zero-Trust target validation (twice + no redirects)
   ▼
Scanner Engine (separate FastAPI service, isolated)
   │ BOLA engine: dual-identity ownership harvest + cross-identity probes
   │ BOPLA engine: declared schema vs observed response diff
   │ Budget: request/time caps
   ▼
Intentionally Vulnerable Sandbox (the demo target, 3 identities, in-memory data)
   ▼
PostgreSQL (prod) / SQLite (dev) — users, projects, scans, endpoints,
findings, evidence, scan events; secrets redacted at write AND read
```

---

## 8. Honest limitations (preempts tough questions)

- **Coverage heuristics:** object-ID testing focuses on parameters named like `*_id`/`user*`/`order*`; exotic naming is silently skipped today.
- **Ownership is inferred from the target's own responses**, not from an external authorization source — a completely locked-down API (no list endpoints) gives the scanner nothing to cross-test, and a leaky list endpoint can distort the map. This is the product's known architectural frontier (a declarative ownership map / IdP integration is the roadmap item).
- **BOPLA = "sensitive-looking + undocumented"**, not a per-role property policy; role-differential testing (admin vs user see different fields) is future work.
- **Demo-grade sandbox:** intentionally vulnerable, in-memory, three fixed identities.
- Findings from the no-engine fallback are heuristic; the primary path (external scanner engine) performs the active tests described above.

---

## 9. One-paragraph elevator pitch

> SentinelAPI is a zero-trust platform that proves API authorization flaws instead of guessing. Feed it an OpenAPI spec and two test accounts, and it actively attacks your API the way a real attacker would — logging in as two identities, swapping object IDs, and comparing what comes back — to confirm Broken Object Level Authorization and sensitive-data exposure with captured evidence and one-line repro commands. Results stream live to a scored dashboard, an attack-surface graph, and an executive report, while a strict sandbox-only policy guarantees the tool can never be pointed at systems you don't own.
