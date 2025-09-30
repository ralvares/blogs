# Enforcing Approved Base Images in the Inner Loop

## Purpose
To ensure every container build in our organization starts from a trusted, secure base image, with violations caught early in the development process. By shifting security left to the inner loop (developer workstations and pre-commit hooks), we provide instant feedback, prevent wasted CI/CD cycles, reduce costs, and avoid delays in PR reviews.

---

### Why This Matters

Every containerized workload starts with a base image. If the base is untrusted or vulnerable, all downstream workloads inherit that risk—creating a cascading supply chain vulnerability. Unapproved base images can introduce:

**Risks include:**
- Vulnerable, outdated packages
- Malicious or backdoored community images
- Compliance violations
- Build instability or drift
- Reputational or financial loss due to supply chain attacks

Inner loop enforcement catches these issues locally, before they waste time and resources in CI/CD pipelines or block PRs.

---

### Why Inner Loop Enforcement

Traditional approaches rely on CI/CD pipelines to validate base images, but this creates delays: developers push code, wait for CI to run, then fix issues and repeat. This wastes compute resources, slows iteration, and frustrates teams.

**Shift-left security** moves validation to the developer's workstation:
- **Instant feedback:** Catch violations before committing code.
- **Reduced waste:** No failed CI builds or blocked PRs from base image issues.
- **Cost savings:** Less cloud compute spent on invalid pipelines.
- **Faster iteration:** Developers fix problems immediately, not after waiting for CI.

By enforcing policies in the inner loop, we strengthen supply chain resilience without slowing down development.

---

### Policy Summary
- All container builds must use base images from an approved internal registry.
- Base image validation occurs locally via pre-commit hooks before commits.
- The same Rego policy is reused in CI/CD as a final safety net.
- Any use of unapproved base images is blocked at commit time, preventing non-compliant changes from entering the repository.

---

### Approved Base Image Sources

Base images must start with one of the following trusted prefixes. These prefixes are set via CI/CD environment variables and maintained by the platform team:
- `quay.myorg.com/approved/`
- `quay.anotherorg.com/trusted/`

These images are:
- Scanned regularly for CVEs
- Signed and stored in a secure registry
- Built using minimal, hardened, and trusted sources

---

### Pre-Commit Hooks for Base Image Validation

We use Git pre-commit hooks with [Conftest](https://www.conftest.dev/) and the [pre-commit framework](https://pre-commit.com/) to enforce base image policies locally. This blocks commits with unapproved base images, providing immediate feedback.

**Rego policy:** `conftest/base-image-approval.rego` (can be centralized in a shared repo or tool for reuse across projects)

**Example Dockerfile:** `conftest/Dockerfile`

#### Setting Up Pre-Commit Hooks

1. Install pre-commit:
   ```sh
   pip install pre-commit
   ```

2. Create a `.pre-commit-config.yaml` in your repository:
   ```yaml
   repos:
     - repo: local
       hooks:
         - id: conftest-base-image-check
           name: Check base images with Conftest
           entry: conftest test --policy conftest/base-image-approval.rego
           language: system
           files: ^Dockerfile.*|^Containerfile.*
           pass_filenames: true
   ```

   > **Note:** Update the `entry` path if the policy is centralized (e.g., via git submodule or URL).

3. Install the hooks:
   ```sh
   pre-commit install
   ```

Now, every commit will run the Conftest check on Dockerfiles. If violations are found, the commit is blocked.

#### Full policy: `conftest/base-image-approval.rego`

---

### Testing Locally (Without Hooks)

To test changes manually before committing:

```sh
conftest test conftest/Dockerfile --policy conftest/base-image-approval.rego
```

> **Note:** Adjust the policy path if it's in a shared location.

This ensures developers can validate locally and catch issues early.

---

### CI/CD as Outer Loop Safety Net

While inner loop enforcement is primary, CI/CD pipelines provide a secondary check to catch any edge cases or bypassed validations.

**CI validation logic**
```sh
conftest test conftest/Dockerfile --policy conftest/base-image-approval.rego
```
> **Note:** Use the centralized policy path if applicable.

- If all base images are approved, the PR passes.
- If violations are found, the pipeline fails and blocks the PR.

#### Example GitHub Actions Check

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

> **Note:** Update to the centralized policy path.

---

### PR Review Enforcement

We use Git protections to ensure governance:
- PRs are required for any file changes
- CODEOWNERS enforce mandatory review for Dockerfiles
- Status checks (like base image validation) must pass
- No direct pushes to main are allowed

Together, these protections ensure no unreviewed or non-compliant base image ever reaches production.

---

### Auditability and Governance

All changes to container build files (like Dockerfile or Containerfile) must go through Git and a pull request (PR). Git provides:
- Complete history of changes, who made them, when, and why.
- Accountability through PR reviews and approvals.
- Reproducibility with version-controlled Dockerfiles.

> **Bottom Line:** Enforcing base image policies in the inner loop shifts security left, catches violations instantly, and strengthens supply chain resilience without slowing developers down. The same portable Rego policy works locally and in CI/CD, creating a seamless, efficient workflow.
