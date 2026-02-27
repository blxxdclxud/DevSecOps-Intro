# Lab 4 — Submission: SBOM Generation & Software Composition Analysis

## Task 1 — SBOM Generation with Syft and Trivy

### Setup

Pulled required Docker images:

```bash
docker pull anchore/syft:latest
docker pull aquasec/trivy:latest
docker pull anchore/grype:latest
```

Target: `bkimminich/juice-shop:v19.0.0`

---

### 1.2: Syft SBOM Generation

Generated native JSON and table formats:

```bash
# Native JSON (most detailed)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp anchore/syft:latest \
  bkimminich/juice-shop:v19.0.0 -o syft-json=/tmp/labs/lab4/syft/juice-shop-syft-native.json

# Human-readable table
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp anchore/syft:latest \
  bkimminich/juice-shop:v19.0.0 -o table=/tmp/labs/lab4/syft/juice-shop-syft-table.txt
```

Output: `juice-shop-syft-native.json` (3.6 MB), `juice-shop-syft-table.txt` (82 KB, 1002 lines)

License extraction:

```bash
jq -r '.artifacts[] | select((.licenses | length) > 0) | [.name, .version, (.licenses | map(.value) | join(", "))] | join(" | ")' \
  labs/lab4/syft/juice-shop-syft-native.json > labs/lab4/syft/juice-shop-licenses.txt
```

---

### 1.3: Trivy SBOM Generation

The default Trivy vulnerability DB mirror (`mirror.gcr.io`) was unreachable from inside containers. For SBOM/package listing, used `--scanners license` which doesn't require the vulnerability DB:

```bash
# Package list with license info (no vuln DB needed)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp aquasec/trivy:latest image \
  --format json --output /tmp/labs/lab4/trivy/juice-shop-trivy-detailed.json \
  --list-all-pkgs --scanners license bkimminich/juice-shop:v19.0.0

# Human-readable table
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp aquasec/trivy:latest image \
  --format table --output /tmp/labs/lab4/trivy/juice-shop-trivy-table.txt \
  --list-all-pkgs --scanners license bkimminich/juice-shop:v19.0.0
```

Output: `juice-shop-trivy-detailed.json` (1.0 MB), `juice-shop-trivy-table.txt` (1.3 MB)

---

### 1.4: SBOM Analysis

#### Package Type Distribution

| Package Type | Syft | Trivy |
|---|---|---|
| npm / Node.js | 1128 | 1125 |
| deb (OS packages) | 10 | 10 |
| binary | 1 | 0 |
| **Total** | **1139** | **1135** |

SBOM analysis script:

```bash
echo "=== SBOM Component Analysis ===" > labs/lab4/analysis/sbom-analysis.txt
jq -r '.artifacts[] | .type' labs/lab4/syft/juice-shop-syft-native.json | sort | uniq -c >> labs/lab4/analysis/sbom-analysis.txt
jq -r '.Results[] as $result | $result.Packages[]? | "\($result.Target) - \(.Type // "unknown")"' \
  labs/lab4/trivy/juice-shop-trivy-detailed.json | sort | uniq -c >> labs/lab4/analysis/sbom-analysis.txt
```

#### Dependency Discovery Analysis

Both tools found almost the same packages (1126 in common). Syft found 13 unique packages that Trivy missed, and Trivy found 9 that Syft missed. The difference is small — Syft detected one extra binary (`node` runtime) while Trivy skipped it. Both tools read the same `package.json` files inside the container layers.

Syft gives richer metadata per package: CPEs, file paths, layer information, and more granular dependency data in its native JSON format. Trivy's JSON is simpler and easier to parse but has less per-package detail.

#### License Discovery Analysis

| Metric | Syft | Trivy |
|---|---|---|
| Unique license types found | 32 | 28 |
| Top license | MIT (890 packages) | MIT |
| License data for OS pkgs | Yes | Yes |
| License data for npm pkgs | Yes | Yes |

Syft found more unique license types (32 vs 28) because it reads SPDX expressions from package.json more carefully. Both tools agree that MIT is overwhelmingly dominant. Syft also captures complex expressions like `(MIT OR Apache-2.0)` as a single value, while Trivy normalizes them.

Top licenses from Syft:
- MIT: 890 occurrences
- ISC: 143 occurrences
- BSD-3-Clause: 16 occurrences
- Apache-2.0: 15 occurrences
- BSD-2-Clause: 12 occurrences

---

## Task 2 — Software Composition Analysis with Grype and Trivy

### 2.1: SCA with Grype

The Grype vulnerability database was not reachable inside Docker containers (DNS resolution failed for `grype.anchore.io`). Fixed by downloading the DB on the host and mounting it:

```bash
# Download DB on host (accessible from host machine)
curl -L -o /tmp/grype-db/vulnerability-db.tar.zst \
  "https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.4_2026-02-10T16:34:20Z_1772173649.tar.zst"

# Create persistent volume and import DB
docker volume create grype-db-vol
docker run --rm \
  -v /tmp/grype-db/vulnerability-db.tar.zst:/vuln.tar.zst \
  -v grype-db-vol:/.cache/grype \
  anchore/grype:latest db import /vuln.tar.zst

# Create config to disable auto-update (DB already imported)
cat > /tmp/grype-config.yaml << 'EOF'
db:
  auto-update: false
  validate-age: false
  require-update-check: false
  validate-by-hash-on-start: false
EOF

# Scan using the Syft-generated SBOM
docker run --rm -v "$(pwd)":/tmp \
  -v grype-db-vol:/.cache/grype \
  -v /tmp/grype-config.yaml:/.grype.yaml \
  anchore/grype:latest \
  -c /.grype.yaml \
  sbom:/tmp/labs/lab4/syft/juice-shop-syft-native.json \
  -o json 2>/dev/null > labs/lab4/syft/grype-vuln-results.json

# Human-readable table
docker run --rm -v "$(pwd)":/tmp \
  -v grype-db-vol:/.cache/grype \
  -v /tmp/grype-config.yaml:/.grype.yaml \
  anchore/grype:latest \
  -c /.grype.yaml \
  sbom:/tmp/labs/lab4/syft/juice-shop-syft-native.json \
  -o table --file /tmp/labs/lab4/syft/grype-vuln-table.txt 2>/dev/null
```

### 2.2: SCA with Trivy

Similarly, the default Trivy mirror was blocked. Used `ghcr.io/aquasecurity/trivy-db:2` as the DB source (accessible via `TRIVY_DB_REPOSITORY` env variable):

```bash
# Full vulnerability scan
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp \
  -v /tmp/trivy-cache:/root/.cache/trivy \
  -e TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db:2 \
  aquasec/trivy:latest image \
  --format json --output /tmp/labs/lab4/trivy/trivy-vuln-detailed.json \
  bkimminich/juice-shop:v19.0.0

# Secrets scanning
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp \
  -v /tmp/trivy-cache:/root/.cache/trivy \
  -e TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db:2 \
  aquasec/trivy:latest image \
  --scanners secret --format table \
  --output /tmp/labs/lab4/trivy/trivy-secrets.txt \
  bkimminich/juice-shop:v19.0.0

# License compliance scanning
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/tmp \
  -v /tmp/trivy-cache:/root/.cache/trivy \
  -e TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db:2 \
  aquasec/trivy:latest image \
  --scanners license --format json \
  --output /tmp/labs/lab4/trivy/trivy-licenses.json \
  bkimminich/juice-shop:v19.0.0
```

### 2.3: Vulnerability Analysis

Vulnerability count script:

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
| Negligible | 12 | 0 |
| **Total** | **144** | **143** |

Both tools found almost the same number of vulnerabilities. The difference is in how they classify low-severity issues — Grype uses a "Negligible" bucket that Trivy doesn't have.

#### Top 5 Critical Vulnerabilities

| CVE / Advisory | Package | CVSS | Description |
|---|---|---|---|
| CVE-2023-32314 | vm2@3.9.17 | 10.0 | Sandbox escape — attacker can run arbitrary code outside the VM |
| CVE-2023-37466 | vm2@3.9.17 | 10.0 | Promise handler bypass allows full sandbox escape |
| CVE-2023-37903 | vm2@3.9.17 | 10.0 | Custom inspect function allows sandbox escape |
| CVE-2015-9235 | jsonwebtoken@0.1.0 / 0.4.0 | 9.8 | JWT verification bypass — token signature not properly validated |
| CVE-2025-15467 | libssl3@3.0.17-1 | 9.8 | OpenSSL RCE via malicious CMS/EnvelopedData message |

**Remediation:**
- `vm2` is an abandoned project with many critical sandbox escapes. Remove it entirely and use a safer alternative like `isolated-vm`.
- `jsonwebtoken@0.1.0` and `0.4.0` are extremely old (2013). Upgrade to `jsonwebtoken@9.x`.
- `libssl3` is a system package — update the base image to get the patched OpenSSL version.
- `crypto-js@3.3.0` — upgrade to `4.2.0+` which uses proper PBKDF2 iteration counts.
- `lodash@2.4.2` — upgrade to `4.17.21+` for prototype pollution fix.

#### License Compliance Assessment

| Tool | Unique Licenses Found |
|---|---|
| Syft | 32 |
| Trivy | 28 |

Licenses that require attention in a commercial product:

- **GPL/LGPL variants** — Syft found GPL-1, GPL-2, GPL-3, LGPL-2.1, LGPL-3.0. These have copyleft requirements. If Juice Shop code links with GPL libraries, the product code may need to be open-sourced. Need legal review.
- **MPL-2.0** (2 packages) — File-level copyleft. Modifications to MPL-licensed files must be released.
- **Artistic** (5 packages) — Generally permissive but has some conditions.

Most packages (890+) use **MIT** which is permissive and safe for commercial use.

#### Secrets Scanning Results

Trivy found **4 files containing secrets** (RSA private keys):

| File | Type |
|---|---|
| `/juice-shop/build/lib/insecurity.js` | RSA Private Key |
| `/juice-shop/frontend/src/app/app.guard.spec.ts` | RSA Private Key |
| `/juice-shop/frontend/src/app/last-login-ip/last-login-ip.component.spec.ts` | RSA Private Key |
| `/juice-shop/lib/insecurity.ts` | RSA Private Key |

These are intentional in Juice Shop (it's a deliberately insecure app for training), but in a real project, embedding private keys in source code would be a serious security incident. They would need to be rotated immediately and moved to a secrets manager.

---

## Task 3 — Toolchain Comparison: Syft+Grype vs Trivy All-in-One

### 3.1: Accuracy and Coverage Analysis

Package comparison script:

```bash
# Extract packages
jq -r '.artifacts[] | "\(.name)@\(.version)"' labs/lab4/syft/juice-shop-syft-native.json | sort > labs/lab4/comparison/syft-packages.txt
jq -r '.Results[]?.Packages[]? | "\(.Name)@\(.Version)"' labs/lab4/trivy/juice-shop-trivy-detailed.json | sort > labs/lab4/comparison/trivy-packages.txt

# Compare
comm -12 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt > labs/lab4/comparison/common-packages.txt
comm -23 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt > labs/lab4/comparison/syft-only.txt
comm -13 labs/lab4/comparison/syft-packages.txt labs/lab4/comparison/trivy-packages.txt > labs/lab4/comparison/trivy-only.txt

# CVE comparison
jq -r '.matches[]? | .vulnerability.id' labs/lab4/syft/grype-vuln-results.json | sort | uniq > labs/lab4/comparison/grype-cves.txt
jq -r '.Results[]?.Vulnerabilities[]? | .VulnerabilityID' labs/lab4/trivy/trivy-vuln-detailed.json | sort | uniq > labs/lab4/comparison/trivy-cves.txt
```

#### Package Detection Results

| Metric | Count |
|---|---|
| Packages detected by both | 1126 |
| Packages only in Syft | 13 |
| Packages only in Trivy | 9 |
| Total Syft packages | 1139 |
| Total Trivy packages | 1135 |

#### CVE Detection Results

| Metric | Count |
|---|---|
| CVEs found by Grype | 93 |
| CVEs found by Trivy | 91 |
| CVEs found by both | 26 |
| CVEs only in Grype | 67 |
| CVEs only in Trivy | 65 |

The low overlap in CVE IDs (26 out of ~160 unique) is because Grype uses GitHub Security Advisories (GHSA IDs) while Trivy uses CVE IDs from the NVD/OSV databases. When looking at the same vulnerabilities, they often report the same issue under different IDs. For example, `GHSA-c7hr-j4mj-j2w6` in Grype is the same as `CVE-2015-9235` in Trivy — both are about jsonwebtoken verification bypass. The overlap is actually much higher than the raw numbers suggest.

### Accuracy Analysis

Both tools achieved nearly identical package detection (98%+ overlap). The small difference (13 Syft-only, 9 Trivy-only) comes from:
- Syft detects the `node` binary as a separate package; Trivy doesn't
- Some npm packages have slightly different version strings parsed by each tool
- Trivy normalizes certain package names differently

### Tool Strengths and Weaknesses

| Feature | Syft + Grype | Trivy All-in-One |
|---|---|---|
| SBOM quality | Very detailed (CPEs, file paths, layers) | Good but simpler |
| SBOM formats | SPDX, CycloneDX, Syft native | SPDX, CycloneDX, JSON |
| Vuln data source | GitHub Advisory Database | NVD, OSV, RedHat, etc. |
| License scanning | Good (via Syft) | Good (built-in) |
| Secrets scanning | No built-in (separate tool needed) | Yes, built-in |
| Misconfig scanning | No | Yes (Dockerfile, k8s, etc.) |
| Setup complexity | Two tools, more steps | One tool for everything |
| DB update method | Separate DB download | Automatic OCI artifact pull |
| Output flexibility | Very high (many formats per tool) | High |
| CI/CD integration | Flexible (decouple SBOM + scan) | Simple (one command) |

**Syft+Grype strengths:** SBOM quality is better. Syft's native JSON format has more metadata. The SBOM can be generated once and reused with Grype later, or shared with other tools. Grype's advisory database focuses on ecosystem-specific advisories which can catch issues CVE databases miss.

**Trivy strengths:** One tool for everything — vuln scanning, secrets, licenses, misconfiguration. Much easier for a team that wants a single scanner. Built-in secrets scanning is very useful and not available in Syft/Grype. Trivy is also faster to set up in CI/CD because there's only one tool to configure.

**Syft+Grype weaknesses:** No secrets scanning, no misconfig scanning. Two tools to maintain and update. More complex pipeline setup.

**Trivy weaknesses:** Less detailed SBOM metadata. Slightly lower package detection in some edge cases. The all-in-one nature means you can't easily swap just one part.

### Use Case Recommendations

**Use Syft+Grype when:**
- You need high-quality SBOMs to share with customers or for compliance (e.g., NTIA SBOM requirements)
- You already have separate secrets scanning tools (HashiCorp Vault, git-secrets, etc.)
- Your pipeline needs to generate an SBOM once and scan it multiple times with different tools
- You want to cross-reference findings across multiple databases

**Use Trivy all-in-one when:**
- You want the simplest possible setup — one tool, one command
- You need secrets scanning alongside vulnerability scanning
- You're scanning Dockerfiles or Kubernetes manifests for misconfigurations too
- Your team is small and maintenance overhead matters more than maximum detail

### Integration Considerations

**CI/CD:** Trivy wins for simplicity. A single `trivy image --format sarif` step integrates directly with GitHub Advanced Security, GitLab Security Dashboard, and most SIEM tools. Syft+Grype requires two steps but the SBOM artifact from Syft can be stored as a pipeline artifact and audited independently.

**Automation:** Both tools work well in GitHub Actions and GitLab CI. Trivy has official GitHub Actions. Syft and Grype both have Docker images suitable for containerized CI/CD.

**Operational overhead:** Trivy's database auto-updates via OCI registry. Grype's database also auto-updates but can fail in restricted network environments (as seen in this lab). Syft doesn't need a database.

**In restricted network environments** (like this lab): Both tools need special handling. Grype DB was downloaded on the host and mounted. Trivy's mirror was overridden with `TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db:2`. In production, teams often run a local Trivy DB mirror or a Grype DB mirror inside their network.

**Conclusion:** For a small team with standard CI/CD, Trivy is the pragmatic choice — one tool, less complexity. For organizations with compliance requirements needing high-quality SBOMs, or where the SBOM is a deliverable (e.g., for customers), the Syft+Grype combination produces better output. Running both in parallel is also a valid approach — use Trivy for fast CI gating and Syft+Grype for SBOM generation.
