# Lab 4 — Submission: SBOM Generation & Software Composition Analysis

**Target:** `bkimminich/juice-shop:v19.0.0`

---

## Task 1 — SBOM Generation with Syft and Trivy

### Setup

```bash
mkdir -p labs/lab4/{syft,trivy,comparison,analysis}
docker pull anchore/syft:latest
docker pull aquasec/trivy:latest
docker pull anchore/grype:latest
```

### Syft SBOM Generation

```bash
# Native JSON
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp anchore/syft:latest \
  bkimminich/juice-shop:v19.0.0 -o syft-json=/tmp/labs/lab4/syft/juice-shop-syft-native.json

# Table format
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp anchore/syft:latest \
  bkimminich/juice-shop:v19.0.0 -o table=/tmp/labs/lab4/syft/juice-shop-syft-table.txt

# License extraction
jq -r '.artifacts[] | select((.licenses | length) > 0) | [.name, .version, (.licenses | map(.value) | join(", "))] | join(" | ")' \
  labs/lab4/syft/juice-shop-syft-native.json > labs/lab4/syft/juice-shop-licenses.txt
```

### Trivy SBOM Generation

> Note: the default Trivy DB mirror (`mirror.gcr.io`) was blocked in this environment. Used `--scanners license` for package listing (no vuln DB needed), and `TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db:2` for vulnerability scans later.

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp aquasec/trivy:latest image \
  --format json --output /tmp/labs/lab4/trivy/juice-shop-trivy-detailed.json \
  --list-all-pkgs --scanners license bkimminich/juice-shop:v19.0.0

docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp aquasec/trivy:latest image \
  --format table --output /tmp/labs/lab4/trivy/juice-shop-trivy-table.txt \
  --list-all-pkgs --scanners license bkimminich/juice-shop:v19.0.0
```

### SBOM Analysis

#### Package Type Distribution

```bash
echo "=== SBOM Component Analysis ===" > labs/lab4/analysis/sbom-analysis.txt
jq -r '.artifacts[] | .type' labs/lab4/syft/juice-shop-syft-native.json | sort | uniq -c >> labs/lab4/analysis/sbom-analysis.txt
jq -r '.Results[] as $r | $r.Packages[]? | "\($r.Target) - \(.Type // "unknown")"' \
  labs/lab4/trivy/juice-shop-trivy-detailed.json | sort | uniq -c >> labs/lab4/analysis/sbom-analysis.txt
```

| Package Type | Syft | Trivy |
|---|---|---|
| npm / Node.js | 1128 | 1125 |
| deb (OS packages) | 10 | 10 |
| binary | 1 | 0 |
| **Total** | **1139** | **1135** |

#### Dependency Discovery Analysis

Both tools detected 1126 packages in common. Syft found 13 packages Trivy missed; Trivy found 9 Syft missed. Syft's output is richer — it includes CPEs, file paths, and layer info per package. Trivy's JSON is simpler but easier to parse for basic use.

#### License Discovery Analysis

```bash
jq -r '.artifacts[]? | .licenses[]? | .value' \
  labs/lab4/syft/juice-shop-syft-native.json | sort | uniq -c >> labs/lab4/analysis/sbom-analysis.txt
jq -r '.Results[] | select(.Class // "" | contains("lang-pkgs")) | .Packages[]? | select(.Licenses != null) | .Licenses[]?' \
  labs/lab4/trivy/juice-shop-trivy-detailed.json | sort | uniq -c >> labs/lab4/analysis/sbom-analysis.txt
```

| Metric | Syft | Trivy |
|---|---|---|
| Unique license types | 32 | 28 |
| Most common | MIT (890) | MIT |
| OS package licenses | Yes | Yes |
| npm package licenses | Yes | Yes |

Syft found more unique types because it preserves SPDX compound expressions like `(MIT OR Apache-2.0)` as-is. Trivy normalizes them, so some are merged.

---

## Task 2 — Software Composition Analysis with Grype and Trivy

### SCA with Grype

Grype's DB was unreachable inside Docker (DNS issue). Workaround: downloaded DB on host and imported into a Docker volume.

```bash
# Download and import DB
curl -L -o /tmp/grype-db/vulnerability-db.tar.zst \
  "https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.4_2026-02-10T16:34:20Z_1772173649.tar.zst"
docker volume create grype-db-vol
docker run --rm -v /tmp/grype-db/vulnerability-db.tar.zst:/vuln.tar.zst \
  -v grype-db-vol:/.cache/grype anchore/grype:latest db import /vuln.tar.zst

# Scan Syft SBOM
docker run --rm -v "$(pwd)":/tmp -v grype-db-vol:/.cache/grype \
  anchore/grype:latest sbom:/tmp/labs/lab4/syft/juice-shop-syft-native.json \
  -o json > labs/lab4/syft/grype-vuln-results.json

docker run --rm -v "$(pwd)":/tmp -v grype-db-vol:/.cache/grype \
  anchore/grype:latest sbom:/tmp/labs/lab4/syft/juice-shop-syft-native.json \
  -o table --file /tmp/labs/lab4/syft/grype-vuln-table.txt
```

### SCA with Trivy

```bash
# Vulnerability scan
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp -v /tmp/trivy-cache:/root/.cache/trivy \
  -e TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db:2 \
  aquasec/trivy:latest image \
  --format json --output /tmp/labs/lab4/trivy/trivy-vuln-detailed.json \
  bkimminich/juice-shop:v19.0.0

# Secrets scan
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp -v /tmp/trivy-cache:/root/.cache/trivy \
  -e TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db:2 \
  aquasec/trivy:latest image --scanners secret --format table \
  --output /tmp/labs/lab4/trivy/trivy-secrets.txt bkimminich/juice-shop:v19.0.0

# License scan
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp -v /tmp/trivy-cache:/root/.cache/trivy \
  -e TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db:2 \
  aquasec/trivy:latest image --scanners license --format json \
  --output /tmp/labs/lab4/trivy/trivy-licenses.json bkimminich/juice-shop:v19.0.0
```

### Vulnerability Analysis

```bash
echo "=== Vulnerability Analysis ===" > labs/lab4/analysis/vulnerability-analysis.txt
jq -r '.matches[]? | .vulnerability.severity' labs/lab4/syft/grype-vuln-results.json | sort | uniq -c >> labs/lab4/analysis/vulnerability-analysis.txt
jq -r '.Results[]?.Vulnerabilities[]? | .Severity' labs/lab4/trivy/trivy-vuln-detailed.json | sort | uniq -c >> labs/lab4/analysis/vulnerability-analysis.txt
```

#### SCA Tool Comparison — Vulnerability Detection

| Severity | Grype | Trivy |
|---|---|---|
| Critical | 11 | 10 |
| High | 86 | 81 |
| Medium | 32 | 34 |
| Low | 3 | 18 |
| Negligible | 12 | — |
| **Total** | **144** | **143** |

Both tools found nearly the same count. Grype uses a "Negligible" severity level that Trivy doesn't have, which explains the low-severity difference.

#### Top 5 Critical Vulnerabilities

| CVE | Package | CVSS | Issue |
|---|---|---|---|
| CVE-2023-32314 | vm2@3.9.17 | 10.0 | Sandbox escape, arbitrary code execution |
| CVE-2023-37466 | vm2@3.9.17 | 10.0 | Promise handler bypass, sandbox escape |
| CVE-2023-37903 | vm2@3.9.17 | 10.0 | Custom inspect function, sandbox escape |
| CVE-2015-9235 | jsonwebtoken@0.1.0/0.4.0 | 9.8 | JWT signature verification bypass |
| CVE-2025-15467 | libssl3@3.0.17-1 | 9.8 | OpenSSL RCE via malformed CMS message |

**Remediation:**
- `vm2` — abandoned library, remove it and replace with `isolated-vm`
- `jsonwebtoken@0.1.0/0.4.0` — upgrade to `9.x`
- `libssl3` — update base OS image
- `crypto-js@3.3.0` — upgrade to `4.2.0+`
- `lodash@2.4.2` — upgrade to `4.17.21+`

#### License Compliance Assessment

Most packages (890+) use **MIT**, which is safe for any use. Licenses that need attention:

- **GPL/LGPL** (GPL-1, GPL-2, GPL-3, LGPL-2.1, LGPL-3.0) — copyleft, may require releasing source code if linked. Legal review needed.
- **MPL-2.0** (2 packages) — file-level copyleft, modified files must be published.
- **Artistic** (5 packages) — permissive but has usage conditions.

| Tool | Unique License Types |
|---|---|
| Syft | 32 |
| Trivy | 28 |

#### Secrets Scanning Results

Trivy found **4 files with embedded RSA private keys**:

| File | Secret Type |
|---|---|
| `/juice-shop/build/lib/insecurity.js` | RSA Private Key |
| `/juice-shop/frontend/src/app/app.guard.spec.ts` | RSA Private Key |
| `/juice-shop/frontend/src/app/last-login-ip/last-login-ip.component.spec.ts` | RSA Private Key |
| `/juice-shop/lib/insecurity.ts` | RSA Private Key |

These are intentional in Juice Shop (it's a training app). In a real project, this would be a critical incident — keys must be rotated immediately and moved to a secrets manager.

---

## Task 3 — Toolchain Comparison: Syft+Grype vs Trivy All-in-One

### Accuracy and Coverage Analysis

```bash
# Package comparison
jq -r '.artifacts[] | "\(.name)@\(.version)"' labs/lab4/syft/juice-shop-syft-native.json | sort > labs/lab4/comparison/syft-packages.txt
jq -r '.Results[]?.Packages[]? | "\(.Name)@\(.Version)"' labs/lab4/trivy/juice-shop-trivy-detailed.json | sort > labs/lab4/comparison/trivy-packages.txt
comm -12 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt > labs/lab4/comparison/common-packages.txt
comm -23 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt > labs/lab4/comparison/syft-only.txt
comm -13 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt > labs/lab4/comparison/trivy-only.txt

# CVE comparison
jq -r '.matches[]? | .vulnerability.id' labs/lab4/syft/grype-vuln-results.json | sort | uniq > labs/lab4/comparison/grype-cves.txt
jq -r '.Results[]?.Vulnerabilities[]? | .VulnerabilityID' labs/lab4/trivy/trivy-vuln-detailed.json | sort | uniq > labs/lab4/comparison/trivy-cves.txt
```

#### Package Detection

| Metric | Count |
|---|---|
| Detected by both | 1126 |
| Syft only | 13 |
| Trivy only | 9 |
| Total Syft | 1139 |
| Total Trivy | 1135 |

98%+ overlap. Syft uniquely detected the `node` binary; Trivy skips it.

#### CVE Detection

| Metric | Count |
|---|---|
| Grype CVEs | 93 |
| Trivy CVEs | 91 |
| In common | 26 |

The low ID overlap (26) is because Grype uses GHSA IDs (GitHub advisories) while Trivy uses CVE IDs. They often cover the same vulnerability under different identifiers — for example, `GHSA-c7hr-j4mj-j2w6` (Grype) and `CVE-2015-9235` (Trivy) are both the same jsonwebtoken bypass. Actual content overlap is much higher than 26.

### Tool Strengths and Weaknesses

| Feature | Syft + Grype | Trivy |
|---|---|---|
| SBOM detail | High (CPEs, layers, file paths) | Medium |
| SBOM formats | SPDX, CycloneDX, native JSON | SPDX, CycloneDX, JSON |
| Vuln database | GitHub Advisory DB (GHSA) | NVD, OSV, RedHat, etc. |
| Secrets scanning | No | Yes |
| Misconfig scanning | No | Yes (Dockerfile, k8s, etc.) |
| Setup complexity | Two tools | One tool |
| CI/CD setup | More steps, more flexible | Simple, one command |

**Syft+Grype:** Better SBOM quality. Good when SBOM is a deliverable (compliance, customers). The SBOM is generated once and can be re-scanned later by any tool. Grype catches advisories that CVE databases sometimes miss.

**Trivy:** One tool does everything — vuln scanning, secrets, licenses, misconfigs. Much simpler to set up and maintain. Best for teams that want fast, wide coverage without managing multiple tools.

### Use Case Recommendations

**Use Syft+Grype when:**
- You need high-quality SBOMs for compliance (e.g., NTIA, executive order requirements)
- SBOM is a deliverable to customers
- You want to decouple SBOM generation from scanning and store SBOMs as artifacts

**Use Trivy when:**
- You want one tool for everything
- You need secrets and misconfig scanning alongside vuln scanning
- Simplicity and quick setup matter more than SBOM detail

### Integration Considerations

**CI/CD:** Trivy is simpler — one command, native SARIF output for GitHub Advanced Security and GitLab. Syft+Grype needs two pipeline steps but the SBOM artifact can be saved and audited separately.

**DB updates:** Trivy auto-pulls its DB via OCI. Grype also auto-updates but requires external DNS to `grype.anchore.io` — this can fail in restricted environments (as seen in this lab, where a manual volume mount workaround was needed). In production, teams often run a local DB mirror for both tools.

**Conclusion:** For a small team, Trivy is the pragmatic choice. For compliance-heavy organizations that need SBOM as an artifact, use Syft+Grype. Running both is also valid — Trivy for CI gating, Syft for SBOM generation.
