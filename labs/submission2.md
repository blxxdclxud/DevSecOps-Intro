# Lab 2 — Threat Modeling with Threagile

## Task 1 — Threagile Baseline Model

### 1.1 Generating the Baseline

I created the output directories and ran Threagile using the provided model:

```bash
mkdir -p labs/lab2/baseline labs/lab2/secure

docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.yaml \
  -output /app/work/labs/lab2/baseline \
  -generate-risks-excel=false -generate-tags-excel=false
```

### 1.2 Generated Outputs

After running, the `labs/lab2/baseline/` folder contains:

| File | Description |
|---|---|
| `report.pdf` | Full PDF threat model report |
| `data-flow-diagram.png` | Data flow diagram |
| `data-asset-diagram.png` | Data asset diagram |
| `risks.json` | All identified risks in JSON |
| `stats.json` | Risk statistics summary |
| `technical-assets.json` | Technical assets details |

Overall stats from baseline:
- **Elevated**: 4 risks
- **Medium**: 14 risks
- **Low**: 5 risks
- **Total**: 23 risks

### 1.3 Risk Analysis — Top 5 Risks

#### Ranking Methodology

I used composite scores to rank risks. The formula is:

**Composite Score = Severity × 100 + Likelihood × 10 + Impact**

Where:
- Severity: critical=5, elevated=4, high=3, medium=2, low=1
- Likelihood: very-likely=4, likely=3, possible=2, unlikely=1
- Impact: high=3, medium=2, low=1

#### Top 5 Risks Table

| # | Risk | Category | Severity | Likelihood | Impact | Asset | Score |
|---|---|---|---|---|---|---|---:|
| 1 | Unencrypted Communication (Direct to App) | unencrypted-communication | elevated | likely | high | user-browser | 433 |
| 2 | Unencrypted Communication (Proxy to App) | unencrypted-communication | elevated | likely | medium | reverse-proxy | 432 |
| 3 | Missing Authentication (Proxy to App) | missing-authentication | elevated | likely | medium | juice-shop | 432 |
| 4 | Cross-Site Scripting (XSS) | cross-site-scripting | elevated | likely | medium | juice-shop | 432 |
| 5 | Cross-Site Request Forgery (CSRF) | cross-site-request-forgery | medium | very-likely | low | juice-shop | 241 |

#### Score Calculations

1. **Unencrypted Communication (Direct to App)**: 4×100 + 3×10 + 3 = **433**
2. **Unencrypted Communication (Proxy to App)**: 4×100 + 3×10 + 2 = **432**
3. **Missing Authentication (Proxy to App)**: 4×100 + 3×10 + 2 = **432**
4. **Cross-Site Scripting (XSS)**: 4×100 + 3×10 + 2 = **432**
5. **Cross-Site Request Forgery (CSRF)**: 2×100 + 4×10 + 1 = **241**

#### Analysis of Critical Security Concerns

The biggest risk is **unencrypted communication**. The direct connection from the browser to Juice Shop uses plain HTTP. This means anyone on the network can sniff passwords, session tokens, and personal data. This is the #1 priority to fix.

The **missing authentication** between the reverse proxy and the app is also dangerous. If someone bypasses the proxy and connects directly to port 3000, there is no authentication check at the app level.

**XSS** is a well-known Juice Shop vulnerability. Since it is a deliberately vulnerable app, cross-site scripting is expected, but in a real setup this would allow attackers to steal session cookies.

**CSRF** is rated "very-likely" because the app does not have proper anti-CSRF tokens. An attacker could trick a logged-in user into performing actions they did not intend.

### Baseline Diagrams

The generated diagrams are located at:
- `labs/lab2/baseline/data-flow-diagram.png`
- `labs/lab2/baseline/data-asset-diagram.png`

---

## Task 2 — HTTPS Variant & Risk Comparison

### 2.1 Creating the Secure Model

I copied the baseline model and made three changes:

```bash
cp labs/lab2/threagile-model.yaml labs/lab2/threagile-model.secure.yaml
```

Changes made in `threagile-model.secure.yaml`:

| What Changed | Before | After |
|---|---|---|
| User Browser → Direct to App: protocol | `http` | `https` |
| Reverse Proxy → To App: protocol | `http` | `https` |
| Persistent Storage: encryption | `none` | `transparent` |

These changes simulate adding HTTPS encryption to all communication links and enabling disk encryption on the storage volume.

### 2.2 Generating the Secure Variant

```bash
docker run --rm -v "$(pwd)":/app/work threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.secure.yaml \
  -output /app/work/labs/lab2/secure \
  -generate-risks-excel=false -generate-tags-excel=false
```

Secure variant stats:
- **Elevated**: 2 risks (was 4)
- **Medium**: 13 risks (was 14)
- **Low**: 5 risks (same)
- **Total**: 20 risks (was 23)

### 2.3 Risk Category Delta Table

Generated using the provided `jq` command:

```bash
jq -n \
  --slurpfile b labs/lab2/baseline/risks.json \
  --slurpfile s labs/lab2/secure/risks.json '
def tally(x):
(x | group_by(.category) | map({ (.[0].category): length }) | add) // {};
(tally($b[0])) as $B |
(tally($s[0])) as $S |
(($B + $S) | keys | sort) as $cats |
[
"| Category | Baseline | Secure | Δ |",
"|---|---:|---:|---:|"
] + (
$cats | map(
"| " + . + " | " +
(($B[.] // 0) | tostring) + " | " +
(($S[.] // 0) | tostring) + " | " +
(((($S[.] // 0) - ($B[.] // 0))) | tostring) + " |"
)
) | .[]'
```

**Result:**

| Category | Baseline | Secure | Δ |
|---|---:|---:|---:|
| container-baseimage-backdooring | 1 | 1 | 0 |
| cross-site-request-forgery | 2 | 2 | 0 |
| cross-site-scripting | 1 | 1 | 0 |
| missing-authentication | 1 | 1 | 0 |
| missing-authentication-second-factor | 2 | 2 | 0 |
| missing-build-infrastructure | 1 | 1 | 0 |
| missing-hardening | 2 | 2 | 0 |
| missing-identity-store | 1 | 1 | 0 |
| missing-vault | 1 | 1 | 0 |
| missing-waf | 1 | 1 | 0 |
| server-side-request-forgery | 2 | 2 | 0 |
| unencrypted-asset | 2 | 1 | -1 |
| unencrypted-communication | 2 | 0 | -2 |
| unnecessary-data-transfer | 2 | 2 | 0 |
| unnecessary-technical-asset | 2 | 2 | 0 |

### Delta Run Explanation

#### What I Changed

1. **Direct to App protocol → HTTPS**: The browser-to-app connection now uses encrypted HTTPS instead of plain HTTP.
2. **Reverse Proxy to App protocol → HTTPS**: The internal proxy-to-app link is also encrypted now.
3. **Persistent Storage encryption → transparent**: The storage volume now has disk-level encryption enabled.

#### What Happened to the Risks

- **unencrypted-communication**: Went from 2 risks to 0 (Δ = -2). Both unencrypted communication risks disappeared because we switched both HTTP links to HTTPS. This removed our top 2 highest-scoring risks (scores 433 and 432).

- **unencrypted-asset**: Went from 2 risks to 1 (Δ = -1). The Persistent Storage "unencrypted asset" risk was removed because we enabled transparent encryption. However, the Juice Shop Application itself is still flagged as unencrypted (encryption: none), so 1 risk remains.

- **All other categories**: No change (Δ = 0). This makes sense because switching to HTTPS and encrypting storage does not fix things like missing WAF, XSS, CSRF, or SSRF. Those require different controls (input validation, tokens, firewalls, etc.).

#### Why These Changes Reduced Risks

Switching to HTTPS protects data in transit. Anyone sniffing the network can no longer read passwords, tokens, or personal data. This is the single most effective security improvement for this architecture.

Enabling storage encryption protects data at rest. If the host machine is stolen or the disk is accessed by an unauthorized person, the data is unreadable without the encryption key.

Together, these 3 changes eliminated 3 out of 23 baseline risks (13% reduction), and specifically removed the two highest-scoring risks in the entire model.

### Diagram Comparison

The secure variant diagrams are in `labs/lab2/secure/`. The main visible difference is that the communication links between User Browser → Juice Shop and Reverse Proxy → Juice Shop now show as encrypted (HTTPS) connections in the data flow diagram, compared to the unencrypted (HTTP) links in the baseline.

Secure diagrams location:
- `labs/lab2/secure/data-flow-diagram.png`
- `labs/lab2/secure/data-asset-diagram.png`
