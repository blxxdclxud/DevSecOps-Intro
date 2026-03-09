# Lab 5 — Submission: SAST & DAST Security Analysis of OWASP Juice Shop

**Target:** `bkimminich/juice-shop:v19.0.0`

---

## Task 1 — Static Application Security Testing with Semgrep

### Setup

```bash
mkdir -p labs/lab5/{semgrep,zap,nuclei,nikto,sqlmap,analysis}
git clone https://github.com/juice-shop/juice-shop.git --depth 1 --branch v19.0.0 labs/lab5/semgrep/juice-shop
```

### Running Semgrep

> Note: The environment has no internet access to semgrep.dev, so remote rulesets (`p/security-audit`, `p/owasp-top-ten`) could not be downloaded. A local offline ruleset (`security-rules.yaml`) was created covering the same vulnerability categories: SQL injection, hardcoded credentials, insecure crypto, eval usage, XSS, path traversal, and missing security middleware.

```bash
docker run --rm \
  -v "$(pwd)/labs/lab5/semgrep/juice-shop":/src \
  -v "$(pwd)/labs/lab5/semgrep":/output \
  semgrep/semgrep:latest \
  semgrep --config=/output/security-rules.yaml \
  --json --output=/output/semgrep-results.json /src

docker run --rm \
  -v "$(pwd)/labs/lab5/semgrep/juice-shop":/src \
  -v "$(pwd)/labs/lab5/semgrep":/output \
  semgrep/semgrep:latest \
  semgrep --config=/output/security-rules.yaml \
  --text --output=/output/semgrep-report.txt /src
```

### 1.1 SAST Tool Effectiveness

**Files scanned:** 484 files
**Total findings:** 242

Semgrep detected the following vulnerability categories:

| Rule | Count | Severity |
|---|---|---|
| helmet-missing (security headers) | 211 | INFO |
| insecure-random (Math.random) | 20 | WARNING |
| hardcoded-credentials | 5 | ERROR |
| md5-usage (weak hash) | 2 | WARNING |
| eval-usage | 2 | ERROR |
| sql-injection-sequelize | 1 | ERROR |
| hardcoded-jwt-secret | 1 | ERROR |

The tool covered a wide range of vulnerability types: insecure cryptography, hardcoded secrets, code injection patterns, and missing security middleware. Coverage was good — 484 files scanned with near-perfect parse rate (99.9%).

### 1.2 Critical Vulnerability Analysis — Top 5 Findings

**1. Hardcoded JWT Secret Key**
- Type: Hardcoded Secret
- File: `lib/insecurity.ts:56`
- Severity: ERROR
- A JWT signing secret is hardcoded directly in source code. Anyone reading the code can forge tokens.

**2. SQL Injection via String Concatenation**
- Type: SQL Injection
- File: `data/static/codefixes/dbSchemaChallenge_1.ts:5`
- Severity: ERROR
- Database query built by concatenating user input directly — allows an attacker to manipulate the query.

**3. eval() Code Injection**
- Type: Code Injection
- File: `routes/captcha.ts:23`
- Severity: ERROR
- `eval()` executes arbitrary strings as code. In captcha generation, this allows code injection attacks.

**4. eval() Code Injection (Profile)**
- Type: Code Injection
- File: `routes/userProfile.ts:62`
- Severity: ERROR
- Another `eval()` call on user-controlled data in the profile route — remote code execution risk.

**5. Hardcoded Credentials in Tests**
- Type: Hardcoded Credentials
- File: `frontend/src/app/Services/two-factor-auth-service.spec.ts:65`
- Severity: ERROR
- Real-looking passwords hardcoded in test files. Test files are often committed to the repo, leaking credentials.

---

## Task 2 — Dynamic Application Security Testing with Multiple Tools

### Setup

```bash
# Start Juice Shop (port 3001 used because 3000 was occupied)
docker run -d --name juice-shop-lab5 -p 3001:3000 bkimminich/juice-shop:v19.0.0
sleep 20

# Verify admin login works
curl -s -X POST http://localhost:3001/rest/user/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@juice-sh.op","password":"admin123"}' | jq '.authentication.token'
```

### 2.1 ZAP Unauthenticated Baseline Scan

```bash
docker run --rm --network host \
  -v "$(pwd)/labs/lab5/zap":/zap/wrk/:rw \
  zaproxy/zap-stable:latest \
  zap-baseline.py -t http://localhost:3001 \
  -r report-noauth.html -J zap-report-noauth.json
```

### 2.2 ZAP Authenticated Scan

```bash
docker run --rm --network host \
  -v "$(pwd)/labs/lab5":/zap/wrk/:rw \
  zaproxy/zap-stable:latest \
  zap.sh -cmd -port 8090 \
  -autorun /zap/wrk/scripts/zap-auth-3001.yaml
```

### 2.3 Nuclei Scan

```bash
docker run --rm --network host \
  -v "$(pwd)/labs/lab5/nuclei":/app \
  projectdiscovery/nuclei:latest \
  -u http://localhost:3001 \
  -tags exposures,misconfig,technologies \
  -jsonl -o /app/nuclei-results.json
```

### 2.4 Nikto Scan

```bash
docker run --rm --network host \
  -v "$(pwd)/labs/lab5/nikto":/tmp \
  alpine/nikto \
  -h http://localhost:3001 -o /tmp/nikto-results.txt
```

### 2.5 SQLmap SQL Injection Tests

```bash
# Search endpoint (GET)
docker run --rm --network host \
  -v "$(pwd)/labs/lab5/sqlmap":/output \
  secsi/sqlmap \
  -u "http://localhost:3001/rest/products/search?q=*" \
  --dbms=sqlite --batch --level=3 --risk=2 \
  --technique=B --threads=5 --output-dir=/output

# Login endpoint (POST JSON)
docker run --rm --network host \
  -v "$(pwd)/labs/lab5/sqlmap":/output \
  secsi/sqlmap \
  -u "http://localhost:3001/rest/user/login" \
  --data '{"email":"*","password":"test"}' \
  --method POST \
  --headers='Content-Type: application/json' \
  --dbms=sqlite --batch --level=5 --risk=3 \
  --technique=BT --threads=5 --output-dir=/output \
  --ignore-code=401 --dump
```

---

### 2.6 Authenticated vs Unauthenticated Scanning

| Metric | Unauthenticated | Authenticated |
|---|---|---|
| Total alert types | 11 | 14 |
| High severity | 0 | 1 |
| Medium severity | 2 | 4 |
| Low severity | 6 | 5 |
| Info | 3 | 4 |

The authenticated scan found **27% more alert types** and — most importantly — discovered the **SQL Injection** (HIGH severity) finding that was invisible without authentication. Without logging in, ZAP cannot reach admin endpoints, user-specific API routes, or basket/order functionality. The SQL injection was in an authenticated endpoint, so unauthenticated scanning completely missed it.

**Examples of endpoints only found with authentication:**
- `http://localhost:3001/rest/admin/application-configuration` — admin-only configuration endpoint
- `http://localhost:3001/rest/basket/` — user basket with session ID
- `http://localhost:3001/rest/user/whoami` — profile endpoint requiring token

**Why authenticated scanning matters:** A large part of any web app's attack surface sits behind a login. Testing only public pages gives a false sense of security — many critical vulnerabilities live in authenticated areas like admin panels, user profiles, and payment flows.

---

### 2.7 Tool Comparison Matrix

| Tool | Findings | Severity Breakdown | Best Use Case |
|---|---|---|---|
| ZAP (authenticated) | 14 alert types | 1 HIGH, 4 MED, 5 LOW, 4 INFO | Comprehensive web app scanning, authenticated flows |
| ZAP (unauthenticated) | 11 alert types | 0 HIGH, 2 MED, 6 LOW, 3 INFO | Quick baseline before auth is set up |
| Nuclei | 10 findings | 10 INFO | Fast known-CVE and misconfig checks |
| Nikto | 82 findings | Mix of server issues | Web server misconfiguration assessment |
| SQLmap | 2 injection points | CRITICAL (confirmed SQLi + DB dump) | Deep SQL injection verification and exploitation |

---

### 2.8 Tool-Specific Strengths

**ZAP — Comprehensive authenticated scanner**
ZAP is the most complete DAST tool here. It crawls the full application (spider + AJAX spider), respects authentication sessions, and actively probes every endpoint. The authenticated scan found SQL Injection (HIGH) that all other passive tools missed.
- Example finding: `SQL Injection` in authenticated REST endpoints
- Example finding: `Missing Anti-clickjacking Header (X-Frame-Options)` on multiple pages

**Nuclei — Fast template-based checks**
Nuclei runs hundreds of specific templates quickly. It's best for checking known CVEs or common misconfigs. In this scan it focused on missing security headers and SRI (Subresource Integrity) for CDN-loaded scripts — caught that Juice Shop loads jQuery from a CDN without SRI, meaning the CDN could serve a malicious script.
- Example finding: `HTTP Missing Security Headers` — referrer-policy, permissions-policy absent
- Example finding: `Missing Subresource Integrity` — external CDN scripts loaded without integrity check

**Nikto — Web server misconfiguration hunter**
Nikto makes 7,000+ requests looking for server issues, exposed files, and known bad paths. It found 82 items — mostly potential backup file names that return 200 OK (like `/archive.tar`, `/database.tgz`), plus exposed `/ftp/` directory and missing `X-XSS-Protection` header.
- Example finding: `/ftp/` directory publicly accessible (confirmed by robots.txt)
- Example finding: `Access-Control-Allow-Origin: *` — wildcard CORS allows any domain to read API responses

**SQLmap — SQL injection specialist**
SQLmap confirmed SQL injection in both the search endpoint (GET) and login endpoint (POST JSON). It uses boolean-based blind injection — sending true/false queries and observing response differences. It successfully identified SQLite as the backend and extracted the Products (46 rows) and Deliveries (3 rows) tables.
- Example finding: `GET /rest/products/search?q=*` — boolean-based blind SQLi, payload: `') AND 4098=4098 AND ('dNtT' LIKE 'dNtT`
- Example finding: `POST /rest/user/login` — boolean-based blind SQLi via JSON email field, allows login bypass

---

## Task 3 — SAST/DAST Correlation and Security Assessment

### 3.1 Correlation Analysis

```bash
echo "=== SAST/DAST Correlation Report ===" > labs/lab5/analysis/correlation.txt
# (full script output saved to correlation.txt)
```

Results:

| Method | Tool | Findings |
|---|---|---|
| SAST | Semgrep | 242 code-level findings |
| DAST | ZAP (auth) | 14 alert types |
| DAST | Nuclei | 10 template matches |
| DAST | Nikto | 82 server issues |
| DAST | SQLmap | 2 confirmed injection points |

### 3.2 SAST vs DAST Comparison

**SAST total:** 242 | **Combined DAST total:** ~108 distinct findings

**Vulnerabilities found ONLY by SAST (Semgrep):**

1. **Hardcoded JWT Secret** (`lib/insecurity.ts:56`) — DAST tools run against the live app; they can't read source code to find embedded secrets. They would only discover this indirectly (e.g., if the token was predictable).

2. **eval() Code Injection** (`routes/captcha.ts:23`, `routes/userProfile.ts:62`) — DAST tools would need to craft very specific inputs to trigger eval-based code injection. SAST immediately flags every eval() call in the codebase.

3. **Insecure Math.random() in Security Context** (`lib/insecurity.ts:55`) — Math.random() looks completely normal in HTTP responses. DAST has no way to know the random number is used for security tokens. SAST finds it by reading the code.

**Vulnerabilities found ONLY by DAST:**

1. **Missing Security Headers at Runtime** (X-Frame-Options, CSP, X-XSS-Protection) — These are HTTP response headers. Semgrep scans source code but the actual headers are set by the web server/Express middleware configuration at runtime. SAST can flag if the middleware is missing in code, but only DAST confirms what headers actually arrive in real responses.

2. **Session ID Exposed in URL** — ZAP found that session identifiers appear in URL parameters during the scan. This is a runtime behavior visible only when the app is actually running and handling requests — invisible to static analysis.

3. **Wildcard CORS (`Access-Control-Allow-Origin: *`)** — This is a server configuration choice that only manifests in actual HTTP responses. SAST would need a specific rule for the exact Express CORS config pattern. DAST found it by simply looking at response headers.

**Why each approach finds different things:**

SAST reads source code — it understands what the developer wrote. It can find secrets before they're ever deployed, catch bad patterns like `eval()` in every file at once, and run in milliseconds as part of a CI pipeline. But it has no idea what the running application actually does — it can't see headers, runtime config, or how different components interact at runtime.

DAST talks to the live application — it behaves like a real attacker. It sees what actual HTTP responses look like, can follow authentication flows, and catches issues that only appear when the app is running (like misconfigured headers or exposed directories). But it's blind to source code and misses secrets or logic bugs buried in the code.

**The right strategy is to use both:** SAST catches source-level bugs early in development, DAST catches runtime and configuration issues at staging/QA. Together they cover the full attack surface.

---

## Security Recommendations

1. **Remove hardcoded JWT secret** (`lib/insecurity.ts`) — load it from environment variable or secrets manager.
2. **Replace eval()** in captcha and userProfile routes — use safe alternatives that don't execute arbitrary strings.
3. **Parameterize all SQL queries** — use ORM properly (Sequelize placeholders, not string concatenation).
4. **Add security headers** — add `helmet()` middleware to set CSP, X-Frame-Options, HSTS, and CORS properly.
5. **Fix CORS** — replace `Access-Control-Allow-Origin: *` with specific allowed origins.
6. **Replace Math.random()** for security tokens — use `crypto.randomBytes()`.
7. **Replace MD5** in `lib/insecurity.ts` and `Gruntfile.js` — use SHA-256 or bcrypt.
8. **Restrict /ftp/ directory** — should not be publicly accessible.
