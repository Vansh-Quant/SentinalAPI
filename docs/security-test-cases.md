# SentinelAPI — Draft Security Test Cases

> Status: Draft v0.1
> Purpose: Define the initial security test cases for the SentinelAPI scanner and sandbox.
> Scope: Authorized/sandboxed APIs only.

## 1. BOLA / Broken Object Level Authorization

### TC-BOLA-001 — Cross-user object access
- **Target:** Object endpoint such as `GET /orders/{id}`
- **Precondition:** User A and User B exist; each owns a different object.
- **Steps:**
  1. Authenticate as User A.
  2. Request an object owned by User A.
  3. Identify an object owned by User B.
  4. Request User B's object while remaining authenticated as User A.
  5. Compare the baseline and manipulated responses.
- **Expected vulnerable result:** User A receives User B's protected object.
- **Expected secure result:** Access is denied or the object is not disclosed.
- **Evidence:** Identity, object IDs, requests, status codes, response bodies/diffs, ownership mapping.

### TC-BOLA-002 — Read access through alternate identifier
- **Target:** Endpoint using an object identifier.
- **Precondition:** The API exposes an alternate identifier such as UUID, reference number, or nested object ID.
- **Steps:** Replace the identifier while keeping the same authenticated identity.
- **Expected vulnerable result:** Unauthorized object is returned.
- **Expected secure result:** Authorization prevents access.
- **Evidence:** Original identifier, mutated identifier, identity, responses.

### TC-BOLA-003 — False-positive control
- **Target:** Secure object endpoint.
- **Steps:** Perform the same cross-object mutation against an endpoint with correct authorization.
- **Expected result:** SentinelAPI does not report BOLA.
- **Purpose:** Validate authorization-aware verification.

## 2. BOPLA / Broken Object Property Level Authorization

### TC-BOPLA-001 — Sensitive property exposure
- **Target:** User/profile endpoint.
- **Precondition:** API schema identifies expected response properties.
- **Steps:**
  1. Request the resource.
  2. Compare returned properties with the expected/public schema.
  3. Identify suspicious sensitive properties.
  4. Verify whether those properties are authorized for the requesting identity.
- **Expected vulnerable result:** Unauthorized sensitive properties are returned.
- **Expected secure result:** Sensitive properties are omitted or appropriately authorized.
- **Evidence:** Expected properties, observed properties, sensitive-field classification, response.

### TC-BOPLA-002 — Property-level authorization difference
- **Target:** Endpoint returning different fields for different roles.
- **Steps:** Compare responses for two authorized identities/roles.
- **Expected result:** Restricted properties are only present for identities permitted to receive them.

### TC-BOPLA-003 — False-positive control
- **Target:** Endpoint intentionally returning public profile fields.
- **Expected result:** Public fields are not incorrectly classified as sensitive exposure.

## 3. Authentication / Identity

### TC-AUTH-001 — Missing authentication
- Request a protected endpoint without credentials.
- **Expected result:** Request is rejected.

### TC-AUTH-002 — Invalid token
- Request a protected endpoint using an invalid/expired token.
- **Expected result:** Request is rejected.

### TC-AUTH-003 — Identity isolation
- Verify that User A and User B receive distinct identity contexts.
- **Expected result:** Scanner can reliably associate requests with the correct test identity.

## 4. Request / Response Verification

### TC-VERIFY-001 — Baseline vs attack comparison
- Record a legitimate request and response.
- Execute the mutated request.
- Compare status, headers, body structure, object identity, and relevant fields.
- **Expected result:** Finding requires meaningful evidence rather than a single heuristic.

### TC-VERIFY-002 — Duplicate finding control
- Repeat the same security test.
- **Expected result:** Equivalent evidence is grouped into one logical finding.

### TC-VERIFY-003 — Unexpected response handling
- Return malformed, empty, delayed, or unexpected responses from the sandbox.
- **Expected result:** Scanner handles the condition safely without crashing and records the test outcome.

## 5. PoC Generation

### TC-POC-001 — Reproducible BOLA request
- Generate a reproduction request from a confirmed BOLA finding.
- **Expected result:** PoC contains the endpoint, method, relevant authentication context, manipulated identifier, and expected evidence.

### TC-POC-002 — Evidence consistency
- Compare the PoC with the request that produced the confirmed finding.
- **Expected result:** PoC reproduces the same security condition.

## 6. Scan Lifecycle

### TC-SCAN-001 — Valid OpenAPI scan
- Submit a valid OpenAPI specification.
- **Expected result:** Scan is created and progresses through parsing, discovery, testing, verification, and completion.

### TC-SCAN-002 — Invalid OpenAPI specification
- Submit malformed or unsupported API specification.
- **Expected result:** Scan fails gracefully with a useful error.

### TC-SCAN-003 — Scan progress
- Observe a running scan.
- **Expected result:** Backend receives deterministic progress/state updates.

## 7. Safety / Scope

### TC-SAFE-001 — Authorized target restriction
- Scanner receives only explicitly configured sandbox/authorized target information.
- **Expected result:** Scanner does not discover or probe unrelated targets.

### TC-SAFE-002 — Controlled request execution
- Apply request limits, timeouts, and controlled concurrency.
- **Expected result:** Scanner remains bounded and does not become an uncontrolled attack tool.

## 8. Ground Truth Matrix

| Test Case | Sandbox State | Expected SentinelAPI Result |
|---|---|---|
| TC-BOLA-001 | Vulnerable | BOLA detected |
| TC-BOLA-003 | Secure | No BOLA finding |
| TC-BOPLA-001 | Vulnerable | BOPLA/data exposure finding |
| TC-BOPLA-003 | Secure | No false positive |
| TC-AUTH-001 | Protected | Authentication failure |
| TC-AUTH-002 | Protected | Authentication failure |
| TC-VERIFY-001 | Controlled | Evidence generated |
| TC-POC-001 | Confirmed finding | Reproducible PoC |
| TC-SCAN-001 | Valid spec | Scan completes |
| TC-SCAN-002 | Invalid spec | Graceful failure |
| TC-SAFE-001 | Authorized sandbox | No out-of-scope probing |

## 9. Initial MVP Priority

1. TC-BOLA-001
2. TC-BOLA-003
3. TC-VERIFY-001
4. TC-POC-001
5. TC-BOPLA-001
6. TC-BOPLA-003
7. TC-AUTH-001 / TC-AUTH-002
8. TC-SCAN-001 / TC-SCAN-002
9. TC-SAFE-001 / TC-SAFE-002

> This is a draft test-case specification. Cases should be expanded as the scanner implementation and sandbox API are finalized.
