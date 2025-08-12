# Enforcing Approved Base Images in CI/CD Pipelines

## Purpose
To ensure every container build in our organization starts from a trusted, secure base image, and that all changes to these definitions are tracked, reviewed, and auditable.

---

###  Why This Matters

Base images form the foundation of every container. Using unapproved or vulnerable base images introduces risk across the software supply chain, even before your application code is touched.

**Risks include:**
- ❗ Vulnerable or outdated packages
- ❗ Malicious or backdoored community images
- ❗ Compliance violations
- ❗ Build instability or drift
- ❗ Reputational or financial loss due to supply chain attacks

---

### Why We Use Git for Enforcement

All changes to container build files (like Dockerfile or Containerfile) must go through Git and a pull request (PR). Here’s why:

#### ✅ Auditability

Git gives us a complete history of every change, who changed what, when, and why. This is critical for security investigations and compliance audits.

#### ✅ Accountability

Every change must go through a PR. This ensures that no one bypasses controls, and that there’s a clear reviewer/approver trail.

#### ✅ Review Workflow

PRs allow security and platform teams to review changes before they’re merged, especially base image updates, which have widespread impact.

#### ✅ Reproducibility

Centralized and version-controlled Dockerfiles make builds reproducible, enabling consistent environments across CI, staging, and production.

#### ✅ Change Governance

With Git, we can enforce approvals and automated checks before changes are allowed, and we can even require security sign-off for sensitive image layers.

> **Bottom Line:** Any change to a base image must be intentional, reviewed, and traceable. Git is the system of record that makes this possible.

---

### Policy Summary
- All container builds must use base images from an approved internal registry
- Any change to Dockerfile, Containerfile, or similar must be made via Pull Request
- The CI pipeline validates that only trusted base images are used
- Any use of unapproved base images results in a pipeline failure and PR rejection

---

### Approved Base Image Sources

Base images must start with one of the following trusted prefixes (set via env variable):
- `quay.myorg.com/approved/`
- `quay.anotherorg.com/trusted/`
- (This list is maintained by the platform team)

These images are:
- ✅ Scanned regularly for CVEs
- ✅ Signed and stored in a secure registry
- ✅ Built using minimal, hardened, and trusted sources

---

### How CI Validates Dockerfiles

We use [Conftest](https://www.conftest.dev/) to enforce base image policy in CI. Conftest parses Dockerfiles and applies a Rego policy to ensure only approved base images are used.

**Rego policy:** `conftest/base-image-approval.rego`

**Example Dockerfile:** `conftest/Dockerfile`

**CI validation logic**
```sh
conftest test conftest/Dockerfile --policy conftest/base-image-approval.rego
```
- If all base images are approved, the PR passes and may be merged.
- If any unapproved image is found, the pipeline fails and blocks the PR.

#### Full policy: `conftest/base-image-approval.rego`

---

### Example GitHub Actions Check

```yaml
jobs:
  base-image-check:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      - name: Check base images
        run: |
          for file in $(find . -type f \( -iname "Dockerfile*" -o -iname "Containerfile*" \)); do
            conftest test "$file" --policy conftest/base-image-approval.rego;
          done
```

---

### PR Review Enforcement

We use the following Git protections:
- 🔐 PRs are required for any file changes
- 🔐 CODEOWNERS enforce mandatory review for Dockerfiles
- 🔐 Status checks (like base image validation) must pass
- 🔐 No direct pushes to main are allowed

---

### 🧪 Testing Locally

To test your changes before pushing:

```sh
conftest test conftest/Dockerfile --policy conftest/base-image-approval.rego
```
