# Kubernetes & Container Security Compliance Guide (End-User Focus)

Practical guidance for structuring and evidencing container/Kubernetes security controls with **Red Hat Advanced Cluster Security (RHACS / StackRox)** and **OpenShift**. This is *enablement material* (not a formal attestation) and must be paired with organizational policies, procedures, and broader platform controls.

---
## 0. How to Use & Scope
This guide normalizes overlapping framework language into actionable security “themes”. For each theme you get: intent, risk, platform + RHACS capabilities, key actions, and incremental evidence. Use the quick reference + appendices to translate into specific control IDs.

### Covered vs External Responsibilities
| Category | RHACS Primary | RHACS Partial (Evidence Component) | External / Platform (Document Separately) |
|----------|---------------|------------------------------------|-------------------------------------------|
| Image / Supply Chain Policy | Scan, policy gate, risk scoring | SBOM association, signature policy tie‑in | Signing infra, build provenance chain (Cosign/Sigstore, pipeline attestation) |
| Runtime Detection & Response | Process / network anomaly, policy enforcement | Alert forwarding / correlation | Full SIEM correlation, SOAR workflows, WAF/RASP |
| Vulnerability Management | Prioritization, fixable metrics, gating | SLA tracking exports | Patch orchestration, inventory governance (CMDB) |
| Access / RBAC Hygiene | Visibility, cluster-admin minimization check | Mapping service accounts to namespace scope | Enterprise IAM (MFA, SSO session controls, PAM) |
| Network Segmentation | NetworkPolicy coverage analytics | Flow visualization for validation | East/West deep inspection, service mesh mTLS policy authority |
| Secrets Exposure | Secret-in-env detection | Partial detection of embedded credentials | Enterprise vault, key lifecycle management |
| Logging / Evidence | Policy + violation export, compliance summaries | Supplemental security event stream | Immutable log store, retention, anti‑tamper, TRA artifacts |

*Clarification (SBOM & Signature Scope – concise):* With a Signature Integration, RHACS verifies Cosign signatures (public key / cert / keyless) and, if enabled, Rekor transparency log inclusion on discovery and periodic (~4h) re-checks, and can block unverified images ("Not verified by trusted image signers"). It does **not** generate or sign SBOMs, manage long‑term keys / Fulcio roots, or build full SLSA / in‑toto provenance beyond the configured signature + optional Rekor check. Pipelines (RHTAP + RHTAS) supply SBOM + attestation + key lifecycle; RHACS enforces signed & pinned images and exports verification evidence.

### Baseline Evidence Pattern (Applies Unless Theme Lists “Additional Evidence”)
Unless a theme explicitly lists “Additional Evidence”, capture this baseline set:
1. Current (date-stamped) compliance report excerpt for relevant checks
2. Policy configuration snapshot (JSON export or signed Git version)
3. Sample (sanitized) prior violation + its remediation closure proof
4. External SIEM log / ticket reference linking alert → action
5. Change history (Git / ticket ID) for material control adjustments

### Enforcement Failure Modes & Resilience (Consolidated)
Understanding how controls behave under partial failure prevents silent coverage gaps. The table below summarizes typical failure / degradation scenarios and recommended guardrails.

| Stage / Function | Component(s) | Potential Failure / Condition | Typical Default Behavior | Risk | Recommended Control / Setting | Monitoring Signal |
|------------------|-------------|--------------------------------|---------------------------|------|-------------------------------|-------------------|
| Build / CI Policy Evaluation | CI plugin / API call to Central | Central/API unreachable, latency, auth error | Pipeline step fails (hard fail) or is skipped (if not enforced) | Unsanctioned image proceeds | Fail pipeline on evaluation error (treat as deny) | CI job logs; alert on evaluation error count >0 |
| Image Scanning | Scanner deployment / external scanner integration | Scanner pod crash, version drift, registry credential failure | Image marked unscanned / stale scan retained | Blind to new CVEs | Alert if any deployed image lacks a scan < N hours old | Compliance “unscanned images” delta |
| Admission Enforcement (Deploy Stage) | RHACS validating webhook + OpenShift admission chain | Webhook timeout / DNS / cert expiry | Kubernetes fail-open by default unless failurePolicy=Fail | Risky deploy allowed | Set failurePolicy=Fail for critical policies (e.g., unsigned image, critical CVE) | Admission controller error rate metric |
| Admission Ordering | Multiple controllers (SCC, PodSecurity, Gatekeeper/Kyverno, RHACS) | Conflicting deny reasons / mutation ordering | Inconsistent error surfaced to user | Mis-triage & bypass attempts | Define ownership matrix; avoid duplicate rules across controllers | Admission audit logs; compare rejection sources |
| Runtime Collection | Sensor / Collector DaemonSet | Pod eviction / version mismatch / network partition | Gaps in runtime events; policies still appear “configured” | Undetected runtime anomaly / incident | Monitor collector heartbeat & connected nodes; alert on <100% coverage | Heartbeat metric; node coverage dashboard |
| Notifier Delivery | Slack / PagerDuty / SIEM forwarding | Credential rotation, endpoint outage | Alerts buffered or dropped; silent failure | Delayed response, lost evidence | Health check synthetic alert daily; alert on notifier error backlog | Notifier failure counter |
| Vulnerability Export / Reports | Scheduled job / API script | Script error / auth token expired | Missing daily evidence artifact | Evidence gap for audit period | Store hash chain; alert on missing date in sequence | Object store listing gap detection |
| Logging Pipeline | Forwarder / SIEM ingestion | Buffer full, parse errors, TLS failure | Partial ingest; some events lost | Incomplete forensic trail | Enable pipeline failure alert (PCI 4.0) | SIEM ingestion error dashboard |
| Policy Exception Expiry | Exception register | Exception passes expiry unnoticed | Control gap persists | Risk acceptance indefinite | Automated job flags exceptions past due date | Daily exception aging report |

> Principle: Treat *inability to evaluate* the same as *deny* for critical gates; fail-closed where business impact is acceptable, fail-open only with compensating detection and explicit, time-bound exception.

### Capability Boundaries & Disclaimers
RHACS provides *container & Kubernetes workload* focused security evidence. It does **not**:
- Replace host OS / kernel hardening (CIS benchmark, kernel module integrity, eBPF constraint outside sensor scope)
- Enforce file-level FIM (File Integrity Monitoring) for host paths
- Provide full WAF, RASP, or API schema validation (pair with ingress/WAF layer)
- Manage IAM / MFA / SSO life-cycle (external IdP / IAM system authoritative)
- Offer data-at-rest encryption or key lifecycle management (delegate to platform KMS / vault)
- Guarantee retention / immutability (external WORM/object-lock store required)

Where such controls appear in mapping tables, RHACS contributes *partial* (P) evidence only (telemetry, detection triggers, or gating context) and relies on external systems for full compliance.

### Enforcement Modes & Fallback Nuances
Add these context notes anywhere you operationalize policies so expectations stay realistic (see also the Enforcement Failure Modes & Resilience table above for consolidated behavior references):
- **Progressive Enforcement:** Most teams start high-impact policies (privileged container, unsigned image, critical CVE) in “alert / warn (no block)” mode for 1–2 sprints before switching to enforce. Document the promotion decision (date, risk rationale) for audit.
- **Admission vs Sensor Fallback:** RHACS admission webhook can time out (network, DNS, cert expiry). If `failurePolicy=Ignore` (fail-open) the deploy may proceed; sensor-side (“deploy-time”) enforcement may still catch some conditions but timing differs. Critical policies should usually set `failurePolicy=Fail` + alert on webhook error rate.
- **Hard vs Soft Actions:** Some runtime policies use “scale-to-zero” or alert-only actions—these are *soft* responses compared to an admission block. Mark each policy with its action class in your policy register.
- **Break-Glass / Exceptions:** Temporary allowance (e.g., adding a dangerous capability) must reference an exception ID and expiry. Avoid ad‑hoc manual toggles; prefer Git-based changes.
- **Latency & Race Windows:** A very rapid deploy after image push may momentarily lack latest scan results; mitigate by scanning in CI (pre-push) and failing build on unacceptable issues.
- **Version / Feature Gating:** Some advanced enforcement (e.g., signature policy integration, specific runtime kill actions) depends on cluster + RHACS version parity; annotate policies with minimum version where relevant.

> Tag policy YAML (or JSON export) with labels: `enforcementPhase=warn|block`, `criticality=high|medium|low`, `failurePolicy=Fail|Ignore` for clarity.

### Multi-Controller Policy Interplay (Brief Note)
If you run multiple admission / policy controllers (e.g., SCC / PodSecurity, RHACS admission webhook, Gatekeeper/Kyverno, Sigstore verification), document for each enforced rule WHICH controller is authoritative. Undocumented overlap creates:
- Confusing or duplicated deny messages
- Race conditions / ordering ambiguity (different failurePolicy settings)
- Hidden gaps (assumed “other controller” covers it)

Minimal recommended doc set (kept in Git): controller inventory, per-control owner, failurePolicy, deny message prefix convention, change approval process. Remove redundant enforcement—prefer one authoritative source and treat others as visibility only.

### Policy Bypass / Exception Audit Requirements
All bypasses or temporary relaxations must produce *auditable artifacts*:
1. **Exception Register Entry:** ID, control/policy name, rationale, risk rating, approver, creation date, expiry date.
2. **Mechanism:** Prefer Git-managed policy change (PR includes exception metadata) over ad-hoc UI toggles.
3. **Annotations (Optional):** If using Kubernetes annotations to tag exceptioned workloads (pattern `security.exception/<policy-id>=<exception-id>`), log and export these in inventory reports.
4. **Expiry Enforcement:** Scheduled job checks for past-due exceptions; generate alert + auto-create ticket for review.
5. **Evidence:** Retain original denied manifest (redacted if needed) + post-remediation manifest proving closure.

### External Control Register (Summary)
Controls marked (E) in mappings require explicit tracking. Maintain a register (sample in Appendix E) with: Control Domain, External Owner/System, Evidence Artifact Type, Review Cadence, Last Verified Date. Link each external domain to authoritative documentation (e.g., SOC2 policies, platform hardening guides). This prevents “silent gaps” where a dependency was assumed but never evidenced.

Key External Domains (illustrative): Host OS Hardening, Kernel Patching, Node CIS Benchmark, IAM & MFA, Key Management (KMS/Vault), Data Encryption (at rest / in transit), WAF / API Gateway, SAST/DAST, License Compliance & Legal Review, Backup & DR, Log Retention / WORM, SIEM Correlation Rules, Secrets Lifecycle (rotation), Incident Runbooks, Targeted Risk Analyses (PCI 4.0 Customized Approaches), Data Masking / Tokenization.

> Action: Add an *External Owner* column to internal audit prep spreadsheets; absence of a named owner flags a governance risk.

### Reading Order Recommendation
Review Themes 1–9 in sequence for operational rollout; use Section 11 (Control Mapping Quick Reference) for framework control ID cross-references, and Appendices for detailed per-framework translation.

---
## 1. Image Provenance & Supply Chain Integrity (Build & Trust)
**Representative Control Families:** NIST CM‑2 / CM‑6 / RA‑5; NIST 800‑190 4.1.x; PCI DSS 3.2.1 & 4.0 Requirement 6; HIPAA 164.308(a)(1), 164.312(c)(1).

### Intent
Assure only approved, scanned, signed, minimal, immutable images from trusted sources reach deploy.

### Risk (If Ignored)
Tampered or vulnerable images deliver exploitable components early; signature gaps reduce provenance confidence; drift invites silent privilege or dependency expansion.

### RHACS Levers
- Image & component scanning; CVE severity & fixability classification
- Policy gating (e.g., disallow unsigned images, disallowed registries, fixable critical CVEs)
- Detection of risky config in manifests (privileged, root user, mutable FS) *before* deploy
- Report assertion: “All deployed images have scanner + registry coverage”

### OpenShift / Platform Levers
- Signature & attestation verification (Cosign/Sigstore admission integration)
- ImageContentSourcePolicy for controlled registry mirrors
- Build pipeline isolation + SBOM generation via Red Hat Trusted Application Pipeline (RHTAP) + GitOps deployment pinning by digest

> Sigstore / ClusterImagePolicy Precondition: Ensure keys, root-of-trust configuration, and any required MachineConfig or operator enablement are completed; signature verification is **not** implicitly active. Document the signing key custody & rotation process.

### Key Actions
1. Inventory registries → integrate all in RHACS; block unknown registries.
2. Enforce “no :latest tag” & digest pinning (policy + manifest review).
3. Require signatures/attestations for high-risk namespaces (progressively roll out).
4. Enable and enforce policies for disallowed critical CVEs & unsigned images.
5. Generate SBOM at build; store artifact + hash. RHACS does not *generate* SBOMs; external pipeline tooling (e.g., Red Hat Trusted Application Pipeline) should create & sign them. Current RHACS correlation is vulnerability-centric—treat SBOM retention + attestation verification as an external control.
6. Track mean time from image build → deploy for provenance freshness metric.

### Additional Evidence
- Signed SBOM artifact (hash + timestamp)
- Example signature verification admission log (success + rejection)
 - Exception (if any) showing controlled temporary fallback from block→warn with expiry
 - (If applicable) Secure coding pipeline evidence (SAST/DAST report hash) for public-facing apps (PCI 6.3.2)
 - (If applicable) Secure coding pipeline evidence (SAST/DAST report hash) for public-facing apps (PCI Req 6 secure software development expectations)

---
## 2. Baseline Configuration & Drift Control
**Representative Controls:** NIST CM‑2 / CM‑3 / CM‑6; PCI Req 2 (2.2–2.2.5, 2.3, 2.4); NIST 800‑190 hardening subset; HIPAA 164.308(a)(1)(ii)(D).

### Intent
Codify & continuously enforce hardened deployment settings; surface deviations quickly.

### RHACS Levers
- Deploy-stage misconfiguration policies (privileged, host mounts, escalation, absent limits)
- “Unresolved deploy violations” feed for live drift awareness

### OpenShift Levers
- SCC & Pod Security profiles (restrict privilege + capabilities)
- Admission controllers enforcing resource limits & forbidding host networking

### Key Actions
1. Map internal hardening standard → RHACS policy set (clone, label, commit to Git).
2. Enforce (initially warn, then block) top 5 riskiest misconfigs.
3. Daily triage of new high/critical deploy violations (≤24h closure goal).
4. Quarterly review: prune obsolete custom policies & document rationale changes.

### Additional Evidence
- Drift metrics: count of high-severity misconfigs over trailing 30 days (trend downward)

---
## 3. Least Privilege & RBAC Governance
**Representative Controls:** NIST AC‑2 / AC‑3 / AC‑6 / CM‑5; PCI Req 7 (7.1–7.2.3); HIPAA 164.308(a)(4), 164.312(a)(1)(i–iv).

### Intent
Restrict administrative & broad-impact permissions; ensure explicit approvals & periodic review.

### RHACS Levers
- RBAC visualization; detection of multiple cluster‑admin subjects
- Policies detecting privilege escalation vectors at container runtime

### OpenShift Levers
- Granular ClusterRoles + namespace RoleBindings; group-based binding strategy
- SCC layering to enforce default non‑privileged runtime contexts

### Key Actions
1. Consolidate cluster-admin to one group; remove direct USER bindings.
2. Quarterly RBAC diff review (export → compare → sign-off in ticket).
3. Enforce policy on privilege escalation (no additional capabilities, disallow escalate). 
4. Service account scope minimization: restrict * verbs & delete wildcards.

### Additional Evidence
- Signed RBAC diff report (before/after) for quarterly review cycle

---
## 4. Network Segmentation & Boundary Protection
**Representative Controls:** NIST SC‑7 (+ variants); PCI Req 1; HIPAA 164.312(e); NIST 800‑190 isolation.

### Intent
Enforce explicit ingress/egress flows; deny-by-default to limit lateral movement.

### RHACS Levers
- Coverage checks: deployments missing ingress and/or egress NetworkPolicies
- Network graph to validate allowed vs observed flows (lateral movement visualization)
- Suggested NetworkPolicy generation from current observed traffic (candidate baseline)
- Post-deployment drift detection: unexpected new connections after baseline

### OpenShift Levers
- NetworkPolicy: Primary L3/L4 segmentation primitive inside the cluster
- Namespaces: Provide administrative scoping only — no isolation unless combined with NetworkPolicy
- Service Mesh (optional): Adds mTLS identity and L7 authorization policies (external to RHACS)
- Multus: Enables secondary network interfaces; traffic on those interfaces bypasses primary cluster NetworkPolicy controls
- User Defined Networks (UDN): Extends OVN-Kubernetes to support multiple logical networks:
	- A UDN may serve as the alternate primary network for a namespace (only one primary) or as a secondary attachment
	- Backends can be:
		- localnet – VLAN-backed segment bridging into physical infrastructure
		- Overlay (L2/L3 VRF) – logical networks isolated from other overlays
		- Routed L3 fabric segment
	- Security stance: treat each UDN as a separate security zone. Maintain an inventory of workloads per UDN, define ACL/firewall policies, and document all cross-UDN flows as explicit “inter-zone” rules.

### Key Actions
1. Apply a deny-all ingress + deny-all egress NetworkPolicy in every namespace.
2. Use RHACS to generate candidate NetworkPolicies from current traffic; review, tighten selectors, store in Git, and only then apply.
3. Simulate coverage and policy changes before enforcing; record approvals as evidence.
4. Flag and document any use of hostNetwork, hostPID, or hostIPC.
5. Weekly: measure % of workloads with both ingress and egress policies (target = 100%).

> Segmentation Clarification & Governance: Namespaces alone do not isolate traffic. True segmentation begins only when NetworkPolicies (or service mesh authz rules) explicitly deny by default and allow required flows. Multus and UDN attachments create parallel paths outside the default pod network—treat each as its own security zone. For every Multus secondary network or UDN logical network, create an External Control Register row (owner, firewall/ACL policy scope, change approval workflow, review cadence). A missing owner constitutes a segmentation compliance gap.

> Policy Generation Caveat: RHACS policies are based on observed traffic. Cold-start or low-traffic services may omit legitimate flows. Stage in warn-only mode, monitor denied traffic alerts, then promote. Periodically regenerate and diff to detect real architecture changes vs anomalous lateral communication.

### Segmentation Scope & Limitations
Kubernetes NetworkPolicies operate at L3/L4 (namespace/pod/port). They do not:
- Inspect payloads or enforce application protocol semantics
- Provide DPI / IDS / IPS capabilities
- Perform data classification / DLP

Use:
- Service Mesh for L7 identity + mTLS authorization
- IDS/IPS or eBPF platforms for deep packet east-west threat detection

Document each extended control (owner + evidence) in the External Control Register (Appendix E).

### Additional Evidence
- NetworkPolicy coverage percentage over time (e.g., last 8 weeks)
- Sample generated NetworkPolicy YAML + review ticket approval + before/after coverage diff
- Example drift detection alert showing unexpected new connection

### Workload Classification & Node Placement ("Compute Zones")
When multiple data sensitivity or regulatory classifications (e.g., Public, Internal, Confidential, Restricted / PCI in-scope / PHI) must coexist on a single cluster, NetworkPolicies alone do not mitigate all residual risks (kernel escape, side-channel, noisy neighbor, forensic contamination). Introduce explicit compute zones that combine node-level segregation, scheduling constraints, and policy enforcement. Treat unapproved co-residency as a violation.

Key Elements:
1. Taxonomy: Publish ordered classification levels with examples + handling rules.
2. Node Segmentation: Label & taint nodes per zone (`classification=restricted`, taint `classification=restricted:NoSchedule`).
3. Scheduling Controls: Require pod label `data-classification=<level>` AND nodeSelector / affinity matching that label; higher classification pods tolerate only their zone taint.
4. Admission / Policy Guardrails: RHACS deploy-time custom policy (or Gatekeeper/Kyverno – choose one authoritative) to enforce presence & consistency of classification labels, forbid privileged/hostNetwork in high zones.
5. Namespace Strategy: Separate namespaces per classification (e.g., `apps-restricted`) plus deny-all ingress/egress; only explicit inter-zone NetworkPolicies allowed (justify each exception).
6. Differential Enforcement: Stricter runtime actions (block vs alert) and shorter vuln SLAs for higher zones (e.g., Critical fix ≤48h for restricted, ≤7d baseline elsewhere).
7. Secrets Handling: Enforce external vault references; block plain env secrets in restricted zone.
8. Drift Detection: Daily job enumerates pods where `data-classification` label mismatches node label; zero tolerance—auto ticket.
9. Residual Risk Register: Document shared kernel exposure & trigger conditions for migrating a zone to its own cluster (e.g., inability to meet accelerated patch SLA, regulatory mandate).
10. Exception Workflow: Temporary co-residency requires exception ID, risk rationale, expiry, and approval (tracked in Exception Register).

Example RHACS Policy Concept (pseudocode):
```
IF namespace matches /(apps-confidential|apps-restricted)/ THEN
	require label data-classification present AND
	require node selector key classification == data-classification label AND
	forbid privileged OR hostNetwork=true for data-classification in (restricted)
VIOLATION if any condition fails
```
(Store actual JSON export in Git; reference commit hash in evidence.)

Additional Evidence for Compute Zones:
- Node label & taint inventory export (hash + timestamp)
- RHACS classification enforcement policy export
- Daily drift report (pod↔node classification mismatch) with uninterrupted date chain
- Inter-zone flow matrix (approved NetworkPolicy exceptions) + ticket links
- Vulnerability SLA matrix per zone + sample accelerated remediation proof
- Exception register entries (if any) governing temporary deviations

Escalate to Separate Clusters When:
- Regulatory / contractual requirement for isolation beyond logical segmentation
- Inability to consistently meet hardened SLA / patch cadence for shared nodes
- Frequent contention or noisy neighbor undermining zone guarantees

Document the decision criteria so auditors see a rational progression plan from single-cluster multi-zone to multi-cluster architecture if/when triggers occur.

---
## 5. Resource Governance & Availability
**Representative Controls:** NIST SC‑6; PCI (least functionality linkage 2.2.5); HIPAA continuity considerations.

### Intent
Prevent noisy-neighbor risk & resource exhaustion through enforced CPU/memory boundaries.

### RHACS Levers
- Policies: missing resource limits / requests

### OpenShift Levers
- LimitRange + ResourceQuota for namespaces

### Key Actions
1. Enforce policy requiring both CPU & memory limits.
2. Add namespace quotas aligned to capacity planning assumptions.
3. Alert on deployments lacking limits >24h after introduction.

### Additional Evidence
- Namespace quota report + variance to actual usage

---
## 6. Vulnerability Remediation Lifecycle (Fix & Prove Closure)
**Representative Controls:** NIST RA‑5; PCI Req 6 (risk-based remediation, coding flaws); NIST 800‑190 4.1.4 / 4.1.6 / 4.1.14; HIPAA 164.308(a)(1), 164.312(c)(1).

### Intent
Quickly identify and block the riskiest (fixable) vulnerabilities and prove you are rebuilding images instead of letting risk age out.

### RHACS Capabilities (Focus Only)
- Continuous image & component scanning (all connected registries)
- Policy gating: block deploy/build if image has fixable Critical (and later High) CVEs
- Severity + fixable filtering & age views; exportable reports / API
- Notifier-driven alert when a vulnerability breaches SLA

### OpenShift / Pipeline Capabilities
- Automated image rebuild on updated base image
- GitOps promotion restricted to images that passed RHACS policy (digest pinning)

### Simple Action Pattern
1. Publish a minimal SLA (Critical 7 days, High 30 days). Medium/Low = track only.
2. Enforce: block new images with fixable Critical CVEs; warn on High (plan date to move High → block).
3. Daily export a vulnerability summary (keep last 30 days + hashes for integrity) – optional but useful.
4. Rebuild & redeploy images failing policy; verify new digest shows “no fixable Critical”.
5. Track two metrics: (a) % fixable Critical within SLA (aim ≥95%), (b) Median days to fix Critical (TTRc) trending down.

### Evidence (Lightweight)
- Policy export (showing Critical=block)
- Sample blocked deployment (log or RHACS violation) with timestamp
- 30‑day vulnerability summary snippet (counts new/fixed/remaining Critical)

### Notes
- RHACS enforces & measures; it does not patch—your pipeline rebuilds.
- Any accepted exception must have an expiry (see Exception Register section).

---
## 7. Runtime Threat Detection & Automated Response
**Representative Controls:** NIST SI‑4 / IR‑4(5) / IR‑5 / IR‑6(1); PCI Req 10 (logging & review enhancements in 4.0); HIPAA 164.308(a)(6), 164.312(b).

### Intent
Detect anomalous or malicious runtime activity and (optionally) apply automated containment.

### RHACS Levers
- Runtime process & network baseline anomalies, exec into container, crypto miner patterns
- Policy actions (scale-to-zero / block / alert) + notifier integrations

### Detection (Simple View)
RHACS does two things:
1. Baseline: learns normal processes / connections; anything new is flagged (new ≠ automatically bad, just unexpected).
2. Prebuilt risky patterns: detects obvious attacker / abuse behaviors (crypto miner names, curl|wget pipe to shell, package manager installs, reverse shell hints, privilege escalation attempts).

Not in scope: deep packet inspection, syscall tracing, full lateral movement analysis. Use other tools for those (list them as external controls).
> Caveat: RHACS uses kernel instrumentation (eBPF-based collection) to observe process executions and network connections, but its detection logic operates at the process/command + connection abstraction layer (baseline anomalies, known risky patterns) rather than exposing arbitrary raw syscall sequence rule authoring or deep packet payload inspection.

### OpenShift / Platform Levers
- Cluster audit logs for correlated identity context
- Network isolation reducing noise + containment domain

### Key Actions
1. Enable top critical runtime policies; attach at least one high-urgency notifier.
2. Test alert → ticket workflow end-to-end (document timing metrics).
3. Consider selective enforcement for high-confidence miner / privilege escalation.
4. Quarterly tune false positives (measure alert precision & drop noise >20%).

### Additional Evidence
- Alert precision metric (true positive / total high severity alerts) over last 30 days

---
## 8. Secrets & Sensitive Data Exposure Prevention
**Representative Controls:** NIST SI‑7; PCI Req 3 (selected); HIPAA 164.312(a)(1), 164.312(c)(1), 164.312(d).

### Intent
Prevent embedding or accidental leakage of secrets inside images or environment variables.

### RHACS Levers
- Secret pattern detection in env vars / config
- Deploy/build-stage blocking policy for explicit secret strings

### OpenShift / Platform Levers
- External secret operators (vault integration) & sealed secrets
- Encrypted storage for secret data at rest (platform managed)

### Key Actions
1. Enable secret-in-env detection; whitelist benign tokens.
2. Enforce policy for high-sensitivity keys (e.g., private keys) at deploy.
3. Migrate static credentials to external vault references; remove from Git.

### Detection Limitations
Secret pattern detection is heuristic/string-pattern based. It may *miss*:
- Encrypted or base64-obfuscated sensitive blobs masquerading as benign strings
- Secrets stored inside binary layers or compressed archives
- Proprietary token formats not matching default regexes

Additional Caveat: RHACS does **not** analyze the cryptographic strength, rotation interval, or entropy of values stored inside Kubernetes Secret objects; weak or long-lived keys must be governed by external secret management and rotation processes.
Explicit Out-of-Scope: Entropy assessment, key age tracking, automatic rotation enforcement, and revocation workflows all sit outside RHACS; treat these as External Control Register entries (Secrets Lifecycle & Rotation).

Do **not** rely on this as primary control—treat it as a compensating “last line” safety net. Primary controls: external vault, short-lived credentials, automated rotation.

### Additional Evidence
- Reduction count of secrets flagged in last 90 days

---
## 9. Logging, Reporting & Continuous Evidence
**Representative Controls:** PCI Req 10 (3.2.1 & 4.0 evolutions), NIST SI‑4 / IR‑5 / IR‑6(1) / AU‑6 / AU‑12; HIPAA 164.312(b), 164.308(a)(1)(ii)(D).

### Intent
Maintain immutable, correlated, reviewable evidence of control operation & exceptions.

### RHACS Levers
- Scheduled compliance & policy exports
- Alert forwarding to SIEM / ticketing

### OpenShift / Platform Levers
- External SIEM pipeline, log integrity (hash/WORM), retention policy enforcement
- Time sync (NTP/chrony) for consistent event ordering

### Key Actions
1. Nightly compliance export (hash + store in immutable bucket).
2. Forward policy + runtime alerts to SIEM; alert on pipeline failures.
3. Implement log integrity verification (hash chain / object lock). 
4. Quarterly Targeted Risk Analysis (TRA) if deviating from default review cadence.

### Additional Evidence
- Log pipeline health check report + failure alert test case
 - Admission webhook availability SLO report (ties to enforcement reliability)
 - Statement/evidence of external immutable storage (object lock / WORM) since in-cluster logging stacks are not inherently immutable
 - Explicit PCI 4.0 note: In-cluster logging solutions lack immutability guarantees; PCI DSS requires external WORM or object-lock storage for retention & tamper resistance—export object-lock policy + sample hash chain.

---
## 10. Quick Start Checklist
| Objective | Action (Do This) | Proof to Capture (Simple Evidence) |
|-----------|------------------|------------------------------------|
| Full scan coverage | Add all registries & enable RHACS scanner; rescan running images | Screenshot/export: 0 unscanned running images |
| Baseline config enforced | Turn on core misconfig policies (privileged, host mount, run as root, no limits) in enforce mode | Policy export showing Enforced=true + zero critical deploy violations |
| Vulnerability gate active | Enforce block on fixable Critical CVEs (warn on High initially) | Blocked deployment log + policy JSON (Critical=block) |
| Runtime visibility working | Verify collector healthy; enable 2–3 runtime policies; trigger safe test event | Runtime alert + notifier delivery record |
| Network segmentation started | Apply namespace default deny (ingress & egress) + first allow rules | NetworkPolicy manifests + coverage screenshot |
| RBAC hygiene | Reduce cluster-admin to one group; remove direct user bindings | Before/after clusterrolebinding diff (only one group) |
| Secret leak prevention | Enable secret-in-env detection; fix flagged env vars | Before/after secret violation count trend (→0) |
| Evidence automation | Schedule nightly compliance export & forward alerts/logs to SIEM | Stored report (hash noted) + SIEM entry with RHACS alert |

Note: Each row maps to detailed sections below. Non-experts can ignore framework/control IDs; auditors can use the Control Mapping table.

---
## 11. Control Mapping Quick Reference
| Theme | Representative Control IDs (See Appendices for granular) |
|-------|----------------------------------------------------------|
| 1 Image Provenance & Supply Chain | NIST CM‑2 / CM‑6 / RA‑5; NIST 800‑190 4.1.x; PCI Req 6; HIPAA 164.308(a)(1), 164.312(c)(1) |
| 2 Baseline Config & Drift | NIST CM‑2 / CM‑3 / CM‑6; PCI Req 2; NIST 800‑190 hardening; HIPAA 164.308(a)(1)(ii)(D) |
| 3 Least Privilege & RBAC | NIST AC‑2 / AC‑3 / AC‑6 / CM‑5; PCI Req 7; HIPAA 164.308(a)(4), 164.312(a)(1) |
| 4 Network Segmentation | NIST SC‑7; PCI Req 1; HIPAA 164.312(e) |
| 5 Resource Governance | NIST SC‑6 (availability); PCI 2.2.5 (linkage); HIPAA continuity (interpretive) |
| 6 Vulnerability Lifecycle | NIST RA‑5; PCI Req 6; NIST 800‑190 4.1.4 / 4.1.6 / 4.1.14; HIPAA 164.308(a)(1) |
| 7 Runtime Detection & Response | NIST SI‑4 / IR‑4(5) / IR‑5 / IR‑6(1); PCI Req 10; HIPAA 164.308(a)(6), 164.312(b) |
| 8 Secrets Protection | NIST SI‑7; PCI Req 3 (selected); HIPAA 164.312(a)(1), (c)(1), (d) |
| 9 Logging & Evidence | NIST IR‑6(1) / SI‑4 / AU‑6 / AU‑12; PCI Req 10; HIPAA 164.312(b), 164.308(a)(1)(ii)(D) |

Coverage Legend: (C) Covered (core technical control in RHACS) / (P) Partial (evidence component only) / (E) External (must document elsewhere). Appendices mark each sub‑requirement accordingly.

> Nuance: “C” denotes the *core technical aspect* is enforceable/observable in RHACS assuming prerequisite configuration (e.g., admission webhook enabled, collector healthy). A temporary downgrade (policy in warn mode, webhook fail-open) should be treated as a *time-bound exception* and tracked. Reclassify to “P” if sustainable enforcement is not yet in place.

---
## Appendix A – PCI DSS Detailed Mapping (Req 2, 6, 7, 10 + 4.0 Delta)
Each row includes a coverage tag.

Note: PCI DSS 4.0 renumbered and reworded several v3.2.1 sub-requirements (notably within Requirements 6 and 10). To avoid accidental mis-citation, 4.0 secure software development / code review / WAF language is referenced at the Requirement level ("PCI Req 6") unless a QSA-validated paragraph ID is explicitly documented internally. Use a separate assessor-pack appendix for precise decimal mappings.

### A.1 Requirement 2 & 6
| PCI Sub‑Req | Theme | Summary | Coverage | Notes |
|-------------|-------|---------|----------|-------|
| 2.2 / 2.2.1–2.2.5 | 2 | Secure config, least functionality | C | Policies + SCC synergy |
| 2.3 | 2 / 9 | Secure non‑console admin | P | Detection custom; rely on TLS & bastion |
| 2.4 | 1 | Component inventory | P | Registry+scanner coverage; CMDB external |
| 6.1 | 6 | Identify vulns | C | Continuous image scanning |
| 6.2 | 6 | Timely patch | P | Enforceable, but patch action external |
| 6.3 / 6.3.1 | 1 | Secure dev & remove test data | P | Build eval + secret detection |
| Req 6 (4.0 secure software dev) | 1 / External | Secure software development & code review / WAF expectations (generalized) | P | See Theme 1 caveats (generalized): RHACS gates risky deploy configs; full secure coding (SAST/DAST, dependency & IaC scanning) via RHTAP/AppSec pipeline (export scan reports + hash) |
| 6.4 / 6.4.1 / 6.4.2 | 2 / 3 / 6 | Change control, env & duty separation | P | Evidence of violations + RBAC; process external |
| 6.5.x | 1 / 6 | Coding vulns | P | Library CVEs; need SAST/DAST |
| 6.6 | 7 / 9 | Web app protection | P | Runtime anomaly ≠ WAF |

### A.2 Requirement 7
| Sub‑Req | Theme | Focus | Coverage | Notes |
|---------|-------|-------|----------|-------|
| 7.1–7.1.4 | 3 | Need-to-know, role definition, approvals | P | RBAC evidence; approval workflow external |
| 7.2 / 7.2.1–7.2.3 | 3 / 4 | Access system & default deny | C/P | RBAC + NetworkPolicies; default deny proven via coverage |

### A.3 Requirement 10
| Sub‑Req (3.2.1 / 4.0) | Theme | Focus | Coverage | Notes |
|------------------------|-------|-------|----------|-------|
| 10.1 / 10.2.x / 10.3.x | 7 / 9 | Event linkage, capture & detail | P | RHACS security events only |
| 10.5.x | 9 | Protect log integrity | P | External SIEM WORM required |
| 10.6 | 9 | Daily review | P | Dashboards aid; process external |
| 10.7 | 9 | Retention | E | External retention controls |
| 4.0 – logging failure detect | 9 | Pipeline failure alerting | C/P | Add health checks + alert policy |

### A.4 4.0 Delta Concepts
| Concept | Theme | Enhancement | Coverage | Notes |
|---------|-------|------------|----------|-------|
| Targeted Risk Analysis | 6 / 9 | Risk-based timing deviations | E | Store TRA artifacts externally |
| Customized Approach | Any | Alternative control design | E | Documentation + validation external |
| Software Component Inventory | 1 / 6 | Formal inventory integrity | P | Partial via image+component metadata |

---
## Appendix B – NIST 800‑53 Runtime / Incident Subset
| Control | Theme | Coverage | Notes |
|---------|-------|----------|-------|
| SI‑4 | 7 | C | Container process & network telemetry |
| IR‑4(5) | 7 | C | Automated policy enforcement |
| IR‑5 | 7 | C | Active runtime detection policies |
| IR‑6(1) | 7 / 9 | C | Notifier automation evidences reporting |
| AU‑6 / AU‑12 | 9 | P | Supplemental events only (not full audit) |

---
## Appendix C – HIPAA 164 Mapping (Selected)
| Citation | Theme | Coverage | Notes |
|----------|-------|----------|-------|
| 164.308(a)(1)(ii)(D) | 2 / 9 | P | Activity review; exports + reports |
| 164.308(a)(4) | 3 | P | Access management evidence; approvals external |
| 164.308(a)(6) | 7 | P | Incident detection; procedures external |
| 164.312(a)(1)(i) | 3 | P | Service account uniqueness; human identity via IdP |
| 164.312(a)(1)(ii–iii–iv)* | 3 / 8 / 9 | E | Emergency access, logoff, encryption platform-bound |
| 164.312(b) | 9 | P | Audit controls subset (security events) |
| 164.312(c)(1) | 1 / 6 | C | Integrity via gating & tampered image prevention |
| 164.312(d) | 3 | P | Auth context (service accounts); MFA external |
| 164.312(e) | 4 | P | Network segmentation evidence; encryption external |

> HIPAA Platform Clarification: OpenShift OAuth idle timeout settings address automatic logoff expectations; cluster / etcd encryption and storage class encryption (where enabled) address encryption-at-rest expectations. Include platform configuration exports (sans secrets) as external evidence.
> Evidence Export Note: Export (a) OAuth session timeout configuration (yaml/json) and (b) encryption-at-rest enablement manifests (etcd + storage class) as signed artifacts; store alongside quarterly HIPAA technical safeguard evidence bundle.

---
## Appendix D – NIST SP 800‑190 Section 4.1.x
| Ref | Theme | Coverage | Intent |
|-----|-------|----------|--------|
| 4.1.1 | 1 | P | Minimal base / reduce surface |
| 4.1.2 | 1 | C | Trusted registries (policy) |
| 4.1.3 | 2 | P | Remove unnecessary components |
| 4.1.4 | 1 / 6 | C | Pre-deploy scanning |
| 4.1.6 | 6 | P | Rebuild vs patch-in-place |
| 4.1.7 | 8 | C | No secrets in images |
| 4.1.8 | 2 | C | Non-root enforcement |
| 4.1.9 | 2 | C | Immutable / read-only FS |
| 4.1.10 | 1 | P | SBOM generation correlation |
| 4.1.11 | 1 | P | Signatures / integrity (policy) |
| 4.1.12 | 1 | C | Digest pinning |
| 4.1.13 | 2 | P | Remove setuid/gid escalation paths |
| 4.1.14 | 1 | E | License compliance (external scanning) |
| 4.1.15 | 1 | P | Secure build pipeline integrity |

Legend: * items with platform or process focus outside RHACS core are marked (P) Partial or (E) External.

## Appendix E – External Control Register (Sample Template)
Use this table internally (expand per environment). Populate “Status” with: Green (current evidence), Amber (evidence aging – review soon), Red (evidence missing / expired).

| Domain / Control Area | Scope / Examples | Primary Owner / System | Evidence Artifact (Type + Location) | Review Cadence | Last Verified | Status | Notes / Residual Risk |
|-----------------------|------------------|------------------------|-------------------------------------|---------------|--------------|--------|-----------------------|
| Host OS & Kernel Hardening | Node CIS, kernel params, module allowlists | Platform / SRE | CIS benchmark report (PDF) in GRC repo | Quarterly | YYYY-MM-DD | Green | Ensure kernel live patch window < SLA |
| Node Patch & Reboot Strategy | Kubelet, OS patches | Platform / SRE | Patch dashboard export | Monthly | YYYY-MM-DD | Green | Track mean patch lag |
| IAM / MFA / SSO | IdP (OAuth, LDAP, SAML) | IAM Team | IdP config snapshot + MFA policy doc | Semi-Annual | YYYY-MM-DD | Amber | Pending FIDO2 rollout |
| Key Management / KMS | Envelope encryption keys | Security / Crypto | KMS key policy JSON + rotation logs | Annual | YYYY-MM-DD | Green | Verify rotation interval ≤ 365d |
| Secrets Lifecycle & Rotation | Vault / External Secret Operator | Security Platform | Rotation report + exception list | Quarterly | YYYY-MM-DD | Amber | 2 legacy static creds awaiting migration |
| Data-at-Rest Encryption | Storage classes, database | Infra / DB | Encryption enablement evidence | Annual | YYYY-MM-DD | Green | Cross-check new storage class defaults |
| Network Encryption (TLS / Mesh) | mTLS, ingress TLS | Platform / NetSec | Mesh policy export + cert inventory | Quarterly | YYYY-MM-DD | Green | Expiring cert alert threshold 30d |
| WAF / API Gateway Protection | OWASP rules, DDoS | AppSec | WAF policy export + sampled logs | Monthly | YYYY-MM-DD | Green | Include anomaly score trend |
| SAST / DAST / Code QA (PCI Req 6) | Static + dynamic testing incl. dependency & IaC scans | AppSec / RHTAP | Signed scan report bundle (hash chain) + pipeline run ID | Per Release | YYYY-MM-DD | Amber | Coverage gap in legacy service X; correlate run ID to blocked deploy evidence |
| License Compliance / SBOM Legal | OSS license scans | Legal / AppSec | License scan diff + approvals | Quarterly | YYYY-MM-DD | Green | Automate accept/deny list sync |
| Backup & DR | Snapshot & restore tests | Infra | DR test report + RPO/RTO metrics | Semi-Annual | YYYY-MM-DD | Amber | Next restore test scheduled |
| Log Retention & Immutability | SIEM, Object store | SecOps | Retention config + WORM policy export | Annual | YYYY-MM-DD | Green | Confirm legal hold handling |
| SIEM Correlation & Tuning | Detection rules | SecOps | Rule pack diff + suppression log | Monthly | YYYY-MM-DD | Amber | High FP rate for rule set v2025.2 |
| Incident Response Runbooks | IR procedures | SecOps | Signed runbook version + change log | Annual | YYYY-MM-DD | Green | Next tabletop in planning |
| Targeted Risk Analyses (PCI 4.0) | Customized approach / SLA deviations | Risk/GRC | TRA documents (signed PDFs) | Per Exception | YYYY-MM-DD | Green | Ensure expiry field present |
| Data Masking / Tokenization | Non-prod data controls | Data Engineering | Masking job config + audit sample | Quarterly | YYYY-MM-DD | Amber | Expand scope to analytics cluster |
| Disaster Recovery Exercise | Full cluster failover | Infra / SecOps | Exercise report + findings tracker | Annual | YYYY-MM-DD | Red | Last exercise overdue |
| Enterprise Vulnerability (Hosts) | Host agent scanning (non-container) | SecOps | Host vuln report + remediation SLA stats | Monthly | YYYY-MM-DD | Amber | Align host SLA with container SLA |
| Managed Node OS Patching (ROSA/ARO) | Cloud-managed worker node base OS updates | Cloud Provider / Platform SRE | Provider SLA doc + patch cycle statement | As per provider | YYYY-MM-DD | Green | Shared responsibility—verify region/cluster version cadence |
| Control Plane Patching (Managed Service) | Managed OpenShift control plane updates | Cloud Provider | Release notes + upgrade window evidence | Per Upgrade | YYYY-MM-DD | Green | Track deprecation notices |

Add this register to compliance review packs; each RED item should have a remediation ticket and target date.

## Appendix F – Clarification Index (Nuanced Partial / Shared Controls)
| Topic / Control Aspect | RHACS Provides (Evidence / Enforcement) | External / Platform Responsibility | Recommended Evidence Bundle |
|------------------------|------------------------------------------|------------------------------------|-----------------------------|
| SBOM Association & Signature Policy | Policy gating on metadata (labels, digest pinning, unsigned image policy); violation & compliance reports | RHTAP SBOM generation, signing, storage; Sigstore admission cryptographic verification | Policy JSON, blocked deploy log, SBOM file + cosign verify output, admission controller config |
| Vulnerability SLA Enforcement | Detects fixable CVEs, blocks on severity, exports age metrics | Rebuild/patch workflows, base image maintenance, change approvals | SLA matrix doc, RHACS vuln trend export, rebuild pipeline logs |
| Host / Node Hardening | Visibility of container spec issues; indirect detection if privileged access requested | OS kernel params, CIS benchmark, host firewall, kernel patching | CIS report, kernel patch cadence, RHACS absence of privileged containers evidence |
| Network Segmentation | Gap detection (missing NetworkPolicies), flow visualization | Layer 7 authZ, DPI, IDS/IPS, mTLS policy (mesh) | NetworkPolicy coverage report, mesh policy export, IDS alert sample |
| Secrets Exposure | Pattern-based env / config secret detection, block on obvious keys | Vault / external secret operator, rotation, short-lived creds | RHACS secret policy violations, vault rotation report, exception register |
| Runtime Threat Detection | Process/network anomaly policies, notifier delivery evidence | Full incident response runbooks, forensics, SIEM correlation rules | Runtime alert sample + ticket, IR runbook version, SIEM correlated event |
| Logging & Integrity | Alert/log export events, compliance scheduling | WORM storage, retention config, log pipeline health, centralized audit trails | Hash chain index, object lock config, SIEM ingestion dashboards |
| License Compliance | (Indirect) package inventory via scans | License analysis, legal approval workflow, SBOM license scan | License scan diff, approval tickets, RHACS component report snapshot |
| Signature / Attestation Chain | Check for presence of expected labels/indicators | Key custody, Rekor transparency log validation, policy root-of-trust | Key management SOP, cosign verify log, RHACS policy pass report |
| Policy Exceptions | Violation + enforcement toggle visibility | Governance workflow (approvals, expiry), risk acceptance | See main section 'Policy Bypass / Exception Audit Requirements' for full process (register, expiry, remediation diff) |
| Admission Reliability | Webhook policy evaluation, fallback detection (if monitored) | HA configuration, certificate rotation, DNS/network reliability | Webhook SLO dashboard, failurePolicy configs, RHACS blocked vs allowed stats |
| Resource Governance | Missing limit detection policies | Capacity planning, auto-scaling strategy, quota sizing | RHACS limits compliance pass, quota manifests, utilization vs quota report |
| Data-in-Transit Security | (Partial) Flag plaintext endpoints (custom) | TLS termination, mTLS enforcement (mesh/gateway) | Mesh cert inventory, gateway TLS config, RHACS custom detection result |
| Data-at-Rest Integrity | Image immutability gating, non-root enforcement | Storage encryption (KMS), snapshot protection | KMS encryption config, snapshot immutability proof, RHACS non-root policy pass |
| SBOM vs Component Inventory | Vulnerability-derived component listing | Formal SPDX/CycloneDX artifact, legal/license context | RHACS component export, SBOM file hash, license report |

> Use this index to pre-empt auditor “scope inflation” questions: for each shared control, you present split responsibilities plus cohesive evidence chain.

---
## 12. Extending & Maturing
| Phase | Focus | Additions |
|-------|-------|----------|
| Foundational | Visibility + Gate | Critical vuln & privileged config enforcement |
| Progressive | Segmentation + Least Privilege | 100% NetworkPolicy + RBAC diff reviews |
| Advanced | Automation & Response | Runtime enforcement, ticket & ChatOps hooks |
| Optimized | Metrics & Predictive | SLA trend KPIs, policy-as-code pipelines |

---
## 13. Common Pitfalls & Remedies
| Pitfall | Impact | Remedy |
|---------|--------|--------|
| Missing registry integration | Blind image coverage gaps | Add registry & rescan backlog |
| Policies only in “alert” mode | Drift & vulnerable images ship | Gradually enable enforcement (risk-ranked) |
| Excess cluster-admin bindings | High lateral compromise blast radius | Consolidate & implement quarterly review |
| Sparse NetworkPolicies | Lateral movement & exfil risk | Default deny + iterative allow modeling |
| Alert fatigue | Missed true positives | Measure precision; tune or suppress noisy patterns |
| No resource limits | Availability degradation | Enforce limits + quotas |
| Secrets in env vars | Credential theft risk | Vault mapping & policy block |

---
## 14. Maintaining the Guide
- Quarterly review for framework revisions (PCI DSS 4.0 clarifications, NIST updates)
- Regenerate mapping tables when new internal checks/policies added
- Treat policy set as code (signed commits, mandatory review)
- Track improvement KPIs: TTRc, NetworkPolicy coverage %, RBAC admin subject count, alert precision

---
## 15. Summary
Combining RHACS (visibility, policy gating, runtime telemetry, evidence exports) with OpenShift (SCC, NetworkPolicy, signature verification, admission & RBAC primitives) yields a continuously validated control stack covering major container security expectations across NIST, PCI DSS, HIPAA, and NIST 800‑190. Focus on measurable reduction (vuln backlog, misconfig drift, alert noise) while maintaining immutable evidence.

> Sustained compliance emerges from disciplined engineering feedback loops: enforce baselines, measure risk reduction, automate evidence, iterate.

---
