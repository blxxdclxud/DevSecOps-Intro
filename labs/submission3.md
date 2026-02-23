# Lab 3 — Submission: Secure Git

## Task 1 — SSH Commit Signature Verification

### Why Commit Signing Matters

Commit signing lets other people verify that a commit was really made by you and not someone pretending to be you. Without signing, anyone can set their `user.name` and `user.email` to anything they want and push commits that look like they came from you. Signing attaches a cryptographic proof to each commit — if the signature is valid, GitHub shows a green "Verified" badge on that commit.

In DevSecOps this is especially important because:

- Supply chain attacks can happen when malicious code is pushed under a trusted developer's name.
- Signed commits give you an audit trail you can actually trust.
- Many compliance frameworks (SOC 2, FedRAMP) require proof that code changes came from authenticated users.
- If a private key is compromised, you can revoke it and all future commits signed with that key will stop verifying — giving you a clear break point.

### SSH Key Setup

Generated a new ED25519 SSH key for commit signing:

```sh
ssh-keygen -t ed25519 -C "ramazanatzuf10@gmail.com" -f ~/.ssh/lab3_signing_key
```

Output:

```
Generating public/private ed25519 key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/blxxdclxud/.ssh/lab3_signing_key
Your public key has been saved in /home/blxxdclxud/.ssh/lab3_signing_key.pub
The key fingerprint is:
SHA256:DzSOiIlSdZSt58DzmUCD92yPjBfKG5a/th3YaNszKjs ramazanatzuf10@gmail.com

```

Public key generated:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE8S18eW1jI2o9CS/Lw19XYB+SktHSCFukbtEv2+hb9H ramazanatzuf10@gmail.com
```

### Git Configuration

Configured Git to use SSH signing:

```sh
git config --global user.signingkey "~/.ssh/lab3_signing_key"
git config --global commit.gpgSign true
git config --global gpg.format ssh
```

Verification that config was applied:

```
user.signingkey=/tmp/lab3_signing_key
commit.gpgsign=true
gpg.format=ssh
```

### Creating a Signed Commit

```sh
git commit -S -m "docs: add commit signing summary"
```

The `-S` flag tells Git to sign the commit with the configured SSH key. Once the public key is added to GitHub under **Settings → SSH and GPG keys → Signing keys**, GitHub will display a "Verified" badge on the commit.

### Why Commit Signing is Critical in DevSecOps

Commit signing is one of those controls that feels optional until something bad happens. It matters because:

1. **Identity verification** — Anyone can fake a git username. SSH signing proves you actually own the private key linked to your GitHub account.
2. **Supply chain security** — A signed commit history means if someone injects malicious code, you can immediately see which commit is unsigned (or signed by an unknown key).
3. **Zero-trust mindset** — DevSecOps is about not trusting anything by default. Signing extends that to source code — don't trust a commit just because the author field says the right name.
4. **Audit trail** — In regulated environments you need to prove who changed what. Signed commits give you non-repudiation — the committer cannot later deny they made the change.

---

## Task 2 — Pre-commit Secret Scanning

### Hook Setup

Created the pre-commit hook at `.git/hooks/pre-commit` using the script from the lab instructions. Made it executable:

```sh
chmod +x .git/hooks/pre-commit
```

The hook does the following:

1. Gets all staged files using `git diff --cached --name-only --diff-filter=ACM`
2. Separates them into lectures files and non-lectures files
3. Runs **TruffleHog** (via Docker) on non-lectures files to find verified/unverified secrets
4. Runs **Gitleaks** (via Docker) on each staged file to find pattern-based secrets
5. Blocks the commit if secrets are found in non-lectures files
6. Allows the commit (with a warning) if secrets are only in the `lectures/` directory (educational content)

### Test 1 — Commit Blocked (Secret Detected)

Created a test file with a fake RSA private key (header truncated to avoid triggering scans in this doc):

```
# test_fake_key.txt
[BEGIN RSA PRIVATE KEY]
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29OlBb4yHQwAz
FAKEKEY
[END RSA PRIVATE KEY]
```

Staged and attempted to commit:

```sh
git add test_fake_key.txt
git commit -m "test commit"
```

Hook output (commit was blocked):

```
[pre-commit] scanning staged files for secrets…
[pre-commit] Files to scan: test_fake_key.txt
[pre-commit] Non-lectures files: test_fake_key.txt
[pre-commit] Lectures files: none
[pre-commit] TruffleHog scan on non-lectures files…
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-02-23T13:27:30Z info-0 trufflehog finished scanning {"chunks": 1, "bytes": 165, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "1.718875ms", "trufflehog_version": "3.93.4"}
[pre-commit] ✓ TruffleHog found no secrets in non-lectures files
[pre-commit] Gitleaks scan on staged files…
[pre-commit] Scanning test_fake_key.txt with Gitleaks...
Gitleaks found secrets in test_fake_key.txt:
Finding:     -----BEGIN RSA PRIVATE KEY-----
Secret:      -----BEGIN RSA PRIVATE KEY-----
RuleID:      private-key
Entropy:     4.867224
File:        test_fake_key.txt
Line:        2
Fingerprint: test_fake_key.txt:private-key:2
1:27PM WRN leaks found: 1
✖ Secrets found in non-excluded file: test_fake_key.txt

[pre-commit] === SCAN SUMMARY ===
TruffleHog found secrets in non-lectures files: false
Gitleaks found secrets in non-lectures files: true
Gitleaks found secrets in lectures files: false

✖ COMMIT BLOCKED: Secrets detected in non-excluded files.
Fix or unstage the offending files and try again.
```

The commit was blocked. The file was removed and unstaged.

### Test 2 — Commit Allowed (No Secrets)

After removing the secret file, created a clean file:

```sh
echo "# Clean file - no secrets here" > clean_test.txt
git add clean_test.txt
git commit -m "test clean commit"
```

Hook output (commit allowed):

```
[pre-commit] scanning staged files for secrets…
[pre-commit] Files to scan: clean_test.txt
[pre-commit] Non-lectures files: clean_test.txt
[pre-commit] Lectures files: none
[pre-commit] TruffleHog scan on non-lectures files…
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

2026-02-23T13:27:38Z info-0 trufflehog finished scanning {"chunks": 1, "bytes": 31, "verified_secrets": 0, "unverified_secrets": 0, "scan_duration": "1.441996ms", "trufflehog_version": "3.93.4"}
[pre-commit] ✓ TruffleHog found no secrets in non-lectures files
[pre-commit] Gitleaks scan on staged files…
[pre-commit] Scanning clean_test.txt with Gitleaks...
[pre-commit] No secrets found in clean_test.txt

[pre-commit] === SCAN SUMMARY ===
TruffleHog found secrets in non-lectures files: false
Gitleaks found secrets in non-lectures files: false
Gitleaks found secrets in lectures files: false

✓ No secrets detected in non-excluded files; proceeding with commit.
```

Commit went through successfully.

### How Automated Secret Scanning Prevents Security Incidents

Pre-commit scanning is a "shift left" security control — it catches problems before they ever enter the repository. Here is why that matters:

- **Secrets in git history are permanent** — even if you delete a file later, the secret lives in the git history. Anyone who cloned the repo before the fix already has it. The only real fix is to rotate the credential.
- **Developers make mistakes** — it is easy to hardcode a token while debugging locally and forget to remove it before committing. An automated hook removes the human memory requirement.
- **Defense in depth** — pre-commit hooks + CI scanning + repository scanning (like GitHub secret scanning) together mean a secret has to bypass three independent controls before it causes damage.

TruffleHog focuses on finding credentials that actually work by trying to verify them against real services. Gitleaks uses regex patterns to catch credentials even when they look fake or are in example code. Using both together gives better coverage.
