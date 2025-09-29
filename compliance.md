# Kubernetes & Container Security Compliance Guide (End-User Focus)

Practical guidance for structuring and evidencing container/Kubernetes security controls with **Red Hat Advanced Cluster Security (RHACS / StackRox)** and **OpenShift**. This is *enablement material* (not a formal attestation) and must be paired with organizational policies, procedures, and broader platform controls.

---
## 0. How to Use & Scope
This guide normalizes overlapping framework language into actionable security “themes”. For each theme you get: intent, risk, platform + RHACS capabilities, key actions, and incremental evidence. Use the quick reference + appendices to translate into specific control IDs.

> Coverage Model Clarification: The scope combines (a) OpenShift / RHCOS platform primitives ("OCP" – SCC/Pod Security, RBAC, NetworkPolicy, MachineConfig/OSTree, ClusterImagePolicy & signature admission, Compliance & Security Profiles Operators, ingress TLS, optional mesh mTLS) and (b) Red Hat Advanced Cluster Security ("RHACS") overlay capabilities (image & component scanning, deploy misconfig & vuln gating, runtime anomaly detection, secret pattern detection, policy & compliance evidence exports). Tables now show three columns (OCP | RHACS | External). A blank cell means “no substantive contribution.” The External column lists items outside the combined in‑scope boundary that must be evidenced via Appendix E (External Control Register).

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
High-level crosswalk of each theme to the principal framework control families. This is an orientation aid only—see Appendices A–D for granular control-by-control coverage, notes, and evidence nuances.

| Theme | NIST 800-53 (Primary Technical Controls) | NIST 800-190 (Key Refs) | PCI DSS (Primary Req) | HIPAA 164 (Representative Clauses) |
|-------|-------------------------------------------|-------------------------|-----------------------|------------------------------------|
| 1 Image Provenance & Supply Chain | CM-2, CM-6, RA-5 (also SI-7, SR-11 partial) | 4.1.1–4.1.4, 4.1.11–4.1.12 | 6 | 164.308(a)(1), 164.312(c)(1) |
| 2 Baseline Config & Drift | CM-2, CM-6, CM-7, CM-3 | 4.1.2, 4.1.3, 4.1.8, 4.2.7 | 2 | 164.308(a)(1)(ii)(D) |
| 3 Least Privilege & RBAC | AC-2, AC-3, AC-6, CM-5 | 4.2.1, 4.2.4 | 7 | 164.308(a)(4), 164.312(a)(1) |
| 4 Network Segmentation | SC-7 (+ SC-7(3)/(4)), AC-3 (enforcement tie) | 4.2.2 | 1 | 164.312(e) |
| 5 Resource Governance | SC-6 (availability), CM-7 (least functionality); CP-10 (External) | 4.2.5 | 2.2.5 | 164.308(a)(7) (contingency alignment) |
| 6 Vulnerability Lifecycle | RA-5, SI-2 | 4.1.4, 4.1.6, 4.1.14 | 6 | 164.308(a)(1) |
| 7 Runtime Detection & Response | SI-4, IR-4(5), IR-5, IR-6(1), AU-12 (runtime alert generation) | 4.5.1, 4.5.2 | 10 | 164.308(a)(6), 164.312(b) |
| 8 Secrets Protection | SI-7, SI-7(1) (integrity aspects) | 4.1.7, 4.2.3 | 3 (selected) | 164.312(a)(1), 164.312(c)(1), 164.312(d) |
| 9 Logging & Evidence | AU-6, AU-12, AU-9 (partial – external WORM), IR-6(1), SI-4 (telemetry) | 4.2.6 | 10 | 164.312(b), 164.308(a)(1)(ii)(D) |

Tri-Column Coverage Model (applies to all control mapping & evidence tables): Columns enumerate OCP (OpenShift/RHCOS primitives), RHACS (security overlay), External (out-of-scope systems/governance). Per column: C = fully enforced/evidenced within that layer; P = partial contribution (shared responsibility or evidentiary assist); blank = negligible/no substantive contribution; External column uses E when entirely outside OCP+RHACS scope. See Section 0 for model rationale.

Notes:
- CP-10 (System Recovery) explicitly categorized External: DR plan execution & recovery testing lie outside platform/RHACS evidentiary scope.
- AU-9 marked partial: RHACS hashing = tamper-evidence; immutable retention (object lock/WORM) external.
- AU-12 added to Runtime Detection acknowledging runtime alerts feed the generated audit/security event corpus.

> Interpretation Nuance: If an intended "C" capability is temporarily not enforced (e.g., policy in warn, webhook fail-open), treat it operationally as downgraded (manage via exception register) until restored—do not silently leave as C in internal audit prep artifacts.

---
## Appendix A – PCI DSS Detailed Mapping (Req 2, 6, 7, 10 + 4.0 Delta)
Tables now use three coverage columns: OCP (OpenShift/RHCOS primitives), RHACS (overlay controls), External (outside scope requiring separate evidence).

### A.1 Requirement 2 & 6
| PCI Sub‑Req | Theme | Summary | OCP | RHACS | External | Notes |
|-------------|-------|---------|-----|-------|----------|-------|
| 2.2 / 2.2.1–2.2.5 | 2 | Secure config, least functionality | C | C |  | SCC/Pod Security + RHACS misconfig policies jointly enforce least privilege (capabilities, non-root, restricted mounts). |
| 2.3 | 2 / 9 | Secure non‑console admin | P | P | E | TLS/bastion & RBAC constrain channels (OCP=P); RHACS can surface insecure endpoints (P); hardened remote admin (MFA, bastion ops) external. |
| 2.4 | 1 | Component inventory | P | P | E | Image/registry visibility (RHACS=P) + cluster image references (OCP=P); authoritative CMDB/SBOM inventory external. |
| 6.1 | 6 | Identify vulns |  | C |  | RHACS continuous image & component scanning (C); OCP relies on RHACS feed. |
| 6.2 | 6 | Timely patch |  | P | E | RHACS policy gates (P); patch orchestration & rebuild external. |
| 6.3 / 6.3.1 | 1 | Secure dev & remove test data | P | P | E | Admission constraints (e.g., disallow :latest) (OCP=P) + RHACS build/deploy policy (P); secure SDLC tasks external. |
| 6.3.2 (4.0) | 1 / External | Secure coding practices (public-facing apps) |  | P | E | RHACS blocks risky deploy configs (P); SAST/DAST, dependency & IaC scans external (RHTAP/AppSec). |
| 6.4 / 6.4.1 / 6.4.2 | 2 / 3 / 6 | Change control, env & duty separation | P | P | E | RBAC separation + namespaces (OCP=P); RHACS violation evidence (P); CAB/workflow external. |
| 6.5.x | 1 / 6 | Coding vulns |  | P | E | RHACS detects vulnerable libraries (P); code-level remediation & SAST external. |
| 6.6 | 7 / 9 | Web app protection |  | P | E | RHACS runtime anomaly policies (P); WAF / L7 inspection external. |

### A.2 Requirement 7
| Sub‑Req | Theme | Focus | OCP | RHACS | External | Notes |
|---------|-------|-------|-----|-------|----------|-------|
| 7.1–7.1.4 | 3 | Need-to-know, role definition, approvals | C | P | E | OCP RBAC primitives enforce (C); RHACS surfaces excessive privilege (P); approval workflow/governance external. |
| 7.2 / 7.2.1–7.2.3 | 3 / 4 | Access system & default deny | C | P |  | OCP RBAC & NetworkPolicies provide enforcement (C); RHACS coverage & drift analytics (P). |

### A.3 Requirement 10
| Sub‑Req (3.2.1 / 4.0) | Theme | Focus | OCP | RHACS | External | Notes |
|------------------------|-------|-------|-----|-------|----------|-------|
| 10.1 / 10.2.x / 10.3.x | 7 / 9 | Event linkage, capture & detail | P | P | E | OCP audit/events (P) + RHACS security events (P); full enterprise correlation & non-security logs external. |
| 10.5.x | 9 | Protect log integrity |  | P | E | RHACS hashing (P); immutable/WORM storage external. |
| 10.6 | 9 | Daily review |  | P | E | RHACS dashboards/exports (P); formal review process external. |
| 10.7 | 9 | Retention |  |  | E | Long-term retention & legal hold external. |
| 4.0 – logging failure detect | 9 | Pipeline failure alerting | P | P |  | OCP forwarder / pipeline health (P) + RHACS notifier/error metrics (P) combine for detection. |

### A.4 4.0 Delta Concepts
| Concept | Theme | Enhancement | OCP | RHACS | External | Notes |
|---------|-------|------------|-----|-------|----------|-------|
| Targeted Risk Analysis | 6 / 9 | Risk-based timing deviations |  |  | E | Governance/risk acceptance artifact external. |
| Customized Approach | Any | Alternative control design |  |  | E | Alternative control design & validation external. |
| Software Component Inventory | 1 / 6 | Formal inventory integrity | P | P | E | OCP image refs + RHACS component data (P/P); authoritative SBOM inventory mgmt external. |

### A.2 Additional PCI Requirements (Context & Gap Clarification)
This clarifies frequently asked PCI areas beyond Req 2, 6, 7, 10 where platform + RHACS are partial or out-of-scope.

| PCI Requirement | Relevance to Container/RHACS | Theme(s) | OCP | RHACS | External | Notes / Evidence Pointer |
|-----------------|------------------------------|----------|-----|-------|----------|--------------------------|
| Req 1 (Firewalls & Segmentation) | Internal east/west segmentation via NetworkPolicy | 4 | C | P | E | OCP NetworkPolicies enforce (C); RHACS coverage & flow viz (P); perimeter firewalls & CDE zoning external. |
| Req 3 (Protect Stored CHD) | Data encryption / key mgmt, tokenization | External |  |  | E | KMS / tokenization external; cluster provides workload isolation only. |
| Req 4 (Transmission Encryption) | TLS/mTLS for CHD in transit | 4 | C | P | E | OCP ingress/route TLS + optional mesh mTLS (C); RHACS reports gaps/custom checks (P); external cert lifecycle governance as needed. |
| Req 5 (Anti‑Malware) | Containers rely on vuln mgmt + allowlist | 6 / 7 | P | P | E | OCP provides isolation primitives (P minimal); RHACS suspicious process & vuln gating (P); traditional AV or sandbox external. |
| Req 8 (Authentication) | User authN, MFA | 3 / External | P |  | E | OCP OAuth integration (P); enterprise IdP + MFA external. |
| Req 9 (Physical) | Data center controls | External |  |  | E | Physical security out-of-scope. |
| Req 11 (Testing) | Segmentation tests, pen tests | 4 / 6 / External | P | P | E | OCP baseline segmentation config (P); RHACS continuous scanning (P); formal pen / segmentation tests external. |
| Req 12 (Policies) | Governance program | External |  |  | E | Policy documents & governance external (platform/RHACS supply evidence only). |

Coverage Legend (Appendix A): C = fully enforced/evidenced within that layer; P = partial contribution (shared responsibility); blank = no substantive contribution; External column (E) = outside combined OCP+RHACS scope.

### A.3 PCI 4.0 Customized Approach / Targeted Risk Analysis Handling
Maintain a Targeted Risk Analysis (TRA) record for any deviation (e.g., different vuln remediation timelines). Include objective, alternative technique, residual risk, approver, revalidation date.

### A.4 Minimal PCI Evidence Bundles
| Objective | OCP Artifact | RHACS Artifact | External Artifact | Narrative |
|-----------|-------------|---------------|-------------------|-----------|
| Segmentation (Req 1) | NetworkPolicy manifests + coverage % | Coverage export / flow graph | Firewall / mesh policy | Demonstrates layered intra-cluster deny + perimeter & L7/mTLS controls. |
| Vulnerability Mgmt (Req 6) | (optional) ImageContentSourcePolicy / digest pinning evidence | Blocked Critical CVE deploy log | Rebuild pipeline log | Shows enforcement gate + actual rebuild/remediation chain. |
| Access (Req 7) | RBAC diff (quarterly signed) | Privilege anomaly report | IAM role design approval | Least privilege maintenance across platform + identity governance. |
| Logging (Req 10) | Audit log forwarding config excerpt | Daily export hash index | SIEM WORM retention config | Integrity + retention assurance with hash chain + immutable store. |
| Change Control (Req 6.4) | MachineConfig / policy commit reference | Policy JSON commit hash | CAB ticket referencing hash | Traceability from enforced config to approved change record. |

### A.5 PCI Quick Gap Checklist
1. Any namespace lacking deny-all baseline policy? (Req 1 risk)
2. Critical fixable CVE past SLA? (Req 6 gap)
3. >1 cluster-admin group? (Req 7 gap)
4. Missing a daily export hash? (Req 10 evidence gap)
5. Customized approach without TRA? (4.0 deficiency)

---
## Appendix B – NIST 800‑53 Runtime / Incident Subset
| Control | Theme | OCP | RHACS | External | Notes |
|---------|-------|-----|-------|----------|-------|
| SI‑4 | 7 |  | C |  | Runtime process & network telemetry (RHACS baseline + anomaly). |
| IR‑4(5) | 7 |  | C |  | Automated response via runtime policy actions & notifiers. |
| IR‑5 | 7 |  | C |  | Continuous runtime incident monitoring. |
| IR‑6(1) | 7 / 9 |  | C |  | Automated reporting to external systems via notifiers. |
| AU‑6 / AU‑12 | 9 | P | P | E | OCP audit/log events (P) + RHACS security events (P); full centralized correlation & retention external. |

### B.1 Expanded NIST 800‑53 Mapping (Selected High‑Relevance Controls)
Focused on Moderate baseline (Rev 5) control families most often cited in platform/container security audits. Not exhaustive; omit families with minimal direct technical tie (e.g., PE – Physical) or purely programmatic (e.g., PM) where RHACS offers no evidence. Use this as a *translation accelerator*, not a replacement for a formal System Security Plan (SSP).

| Control (Rev5) | Control Title (Abbrev) | Primary Theme(s) | OCP | RHACS | External | Notes / Contribution & Boundaries |
|----------------|------------------------|------------------|-----|-------|----------|------------------------------------------|
| AC‑2 / AC‑2(1) | Account Management / Automated Disable | 3 | C | P | E | OCP RBAC enforces; RHACS highlights cluster-admin subjects; lifecycle (provision/disable) external IAM. |
| AC‑3 | Access Enforcement | 3 / 4 | C | P |  | RBAC & NetworkPolicy in OCP; RHACS evidences usage/drift. |
| AC‑6 / AC‑6(1) | Least Privilege / Authorizations | 3 | C | P | E | OCP roles & SCC enforce; RHACS detects over-privilege; approval workflow external. |
| AC‑17 / AC‑17(2) | Remote Access / AuthN Strength | 3 / External |  |  | E | MFA / remote access controls external (IdP, bastion). |
| AC‑19 | Access Control for Mobile / BYOD | External |  |  | E | Not applicable to in-cluster workloads. |
| AU‑2 / AU‑2(3) | Event Logging / Central Review | 9 | P | P | E | OCP audit events + RHACS security events; central correlation & full audit set external. |
| AU‑6 / AU‑6(3) | Audit Review / Correlation | 9 | P | P | E | Requires SIEM correlation externally. |
| AU‑8 | Time Stamps | 9 | P |  | E | Node/cluster NTP (platform); correlation governance external. |
| AU‑9 / AU‑9(2) | Audit Protection / Tamper Resistance | 9 |  | P | E | RHACS export hashing (P); WORM/object lock external. |
| AU‑12 | Audit Generation | 9 | P | P | E | Partial security telemetry only; full audit scope external. |
| CA‑7 | Continuous Monitoring | 1–9 | P | P | E | Contributes technical signals; org-wide monitoring strategy external. |
| CM‑2 / CM‑2(2) | Baseline Configuration / Automation | 1 / 2 | C | P | E | OCP declarative config (MachineConfig, SCC); RHACS drift/misconfig detection; baseline approval external. |
| CM‑3 | Configuration Change Control | 1 / 2 / 6 | P | P | E | Evidence diffs (P); formal CAB external. |
| CM‑5 | Access Restrictions for Changes | 3 | C | P | E | RBAC gating (C); RHACS visibility (P); Git approval external. |
| CM‑6 | Configuration Settings | 1 / 2 | C | P | E | OCP enforces via SCC/Policies; RHACS policy mapping; hardening catalog external. |
| CM‑7 / CM‑7(1) | Least Functionality / Prevent Unauthorized Software | 1 / 2 / 7 | P | P | E | Platform restricts privilege/capabilities (P); RHACS anomaly/risky binary detect (P); allowlist governance external. |
| CP‑9 | Information System Backup | External |  |  | E | Backup & restore validation external. |
| CP‑10 | System Recovery | External |  |  | E | DR exercises external. |
| IR‑4 / IR‑4(5) | Incident Handling / Automated Response | 7 |  | C |  | Runtime action policies + notifiers. |
| IR‑5 | Incident Monitoring | 7 |  | C |  | Continuous runtime observation. |
| IR‑6 / IR‑6(1) | Incident Reporting / Automated Reporting | 7 / 9 |  | C |  | Automated forwarding to SIEM/ticket. |
| IR‑8 | Incident Response Plan | External |  |  | E | Human process & documentation external. |
| MA‑4 | Nonlocal Maintenance | External |  |  | E | Platform ops domain external. |
| RA‑5 / RA‑5(2) | Vulnerability Monitoring / Update Mechanisms | 6 | P | C | E | RHACS scans/gating (C); OCP assists via image pinning (P); host/non-container assets external. |
| SA‑11 | Developer Security Testing | 1 / 6 |  | P | E | Post-build gating only; SAST/DAST external. |
| SA‑15 | Development Process / Standards | External |  |  | E | Secure SDLC governance external. |
| SC‑6 | Resource Availability Protection | 5 | C | P |  | OCP quotas/limits (C); RHACS missing limits detection (P). |
| SC‑7 / SC‑7(3)/(4) | Boundary Protection / Segmentation / Deny by Default | 4 | C | P | E | NetworkPolicy enforcement (C); RHACS coverage/flow viz (P); L7/WAF/mTLS governance external. |
| SC‑8 / SC‑8(1) | Transmission Confidentiality & Integrity | 4 | C | P | E | OCP ingress TLS, optional mesh mTLS/IPsec (C); RHACS evidence/reporting (P); key lifecycle & cipher policy management external. |
| SC‑13 | Cryptographic Protection (At Rest) | External |  |  | E | Storage/etcd encryption external. |
| SC‑28 | Protection of Information at Rest | External |  |  | E | Volume/database encryption external. |
| SI‑2 | Flaw Remediation | 6 | P | C | E | RHACS detects vulnerable images & enforces gates (C); rebuild orchestration external (E). |
| SI‑3 | Malicious Code Protection | 7 |  | P | E | Suspicious process patterns only; traditional AV external. |
| SI‑4 / SI‑4(2)/(4) | System Monitoring / Indicators / Traffic Anomalies | 7 / 9 | P | C | E | OCP provides baseline audit/network constructs (P); RHACS anomaly detection (C); deep packet/IDS external. |
| SI‑5 | Security Alerts / Advisories | 6 / 9 |  | P | E | CVE/advisory ingestion; enterprise advisory program external. |
| SI‑7 | Software / Information Integrity | 1 / 8 | P | C | E | RHACS signed image + secret exposure detection (C); full chain (signing infra) external. |
| SI‑10 | Information Input Validation | External |  |  | E | App/WAF layer control external. |
| SR‑11 | Component Authenticity | 1 | P | P | E | Signature presence policies (RHACS) + admission config (OCP) (P/P); attestation chain external. |

Legend Recap (Appendix B): Column-specific. OCP: OpenShift/RHCOS primitives. RHACS: overlay detection/enforcement/evidence. External: out-of-scope systems or governance. C = fully enforced/evidenced in that column; P = partial contribution; blank = negligible; E (External column only) = entirely external responsibility.

*SC‑8 Clarification:* Marked Partial because OpenShift natively terminates and serves TLS for Routes/Ingress, can enable encrypted node overlay (IPsec depending on network configuration/version), and (optionally) Service Mesh supplies mTLS for east‑west traffic. RHACS itself does not generate, rotate, or validate certificates or cipher policies—capture evidence via: Ingress Controller TLS config/certificate inventory, mesh PeerAuthentication / DestinationRule (or equivalent) showing STRICT mTLS, and (if applicable) cluster network encryption status documentation. If none of these platform features are enabled yet, downgrade SC‑8 to External (E) until cryptographic controls are operational.

> Implementation Tip: When building an SSP, cite this table and then link each (P) / (E) control to either (a) platform configuration export (e.g., NetworkPolicy manifests, SCC profiles, mesh mTLS policy) or (b) governance artifacts (CAB approvals, IR plan version). For (C) items, embed RHACS policy JSON export hash + sample violation or compliance report line item.

### B.2 Tailoring & Gaps
1. Tailor out controls not applicable to container platform scope (e.g., AC‑19) to prevent artificial gap listings.
2. For each (E) control, ensure an owner appears in the External Control Register (Appendix E) — absence indicates governance risk.
3. For mixed controls (C/P), define an internal rule: treat an unmet prerequisite (e.g., admission webhook fail‑open) as temporary downgrade → mark exception with expiry.
4. Maintain a delta log: when RHACS adds functionality narrowing a (P) control toward (C), update this appendix and version the change (auditors appreciate traceability).

### B.3 Minimal Evidence Bundles (Examples)
| Control Focus | OCP Artifact | RHACS Artifact | External Artifact | Sufficiency Rationale |
|---------------|-------------|---------------|-------------------|-----------------------|
| RA‑5 (Vuln Monitoring) | (optional) Image digest pinning manifest | Vulnerability report export (timestamp + hash) | Pipeline rebuild log referencing digest | Correlates detected risk → enforced gate → rebuild action. |
| SC‑7 (Segmentation) | NetworkPolicy manifest set + coverage % | Coverage trend graph | Mesh mTLS policy export + firewall ACL | Validates layered L3/L4 deny + L7/mTLS + perimeter segmentation. |
| CM‑2 (Baseline Config) | MachineConfig & SCC profile list | Policy set JSON (signed commit) | Hardening standard doc version | Links declarative baseline → enforcement → approved standard. |
| IR‑4(5) (Automated Response) | (N/A) | Runtime policy kill/scale action log | Incident ticket with closure notes | Shows automated containment tied to formal IR follow-up. |
| AU‑9 (Audit Protection) | Audit forwarder config checksum | Hash chain index of daily exports | Object store WORM policy export | Demonstrates end-to-end tamper resistance chain. |


---
## Appendix C – HIPAA 164 Mapping (Selected)
| Citation | Theme | OCP | RHACS | External | Notes |
|----------|-------|-----|-------|----------|-------|
| 164.308(a)(1)(ii)(D) | 2 / 9 | P | P | E | Activity review support via audit (OCP) + security events (RHACS); formal review workflow external. |
| 164.308(a)(4) | 3 | C | P | E | RBAC enforcement (C); RHACS privilege visibility (P); approvals external. |
| 164.308(a)(6) | 7 |  | P | E | Runtime detection (P); incident response procedures external. |
| 164.312(a)(1)(i) | 3 | C | P | E | Service account uniqueness (OCP); RHACS over-priv detection; human identity & IAM external. |
| 164.312(a)(1)(ii–iii–iv)* | 3 / 8 / 9 | P | P | E | Session/logoff & secret exposure partial; encryption & emergency access external. |
| 164.312(b) | 9 | P | P | E | Partial audit/security events; centralized PHI audit trail external. |
| 164.312(c)(1) | 1 / 6 | P | C | E | RHACS integrity gating (C); OCP image pinning/signature admission (P); full provenance chain external. |
| 164.312(d) | 3 | P | P | E | AuthN context (service accounts) + detection; MFA external. |
| 164.312(e) | 4 | C | P | E | NetworkPolicy segmentation (C); RHACS coverage evidence (P); TLS/mTLS key lifecycle external. |

> HIPAA Platform Clarification: OpenShift OAuth idle timeout settings address automatic logoff expectations; cluster / etcd encryption and storage class encryption (where enabled) address encryption-at-rest expectations. Include platform configuration exports (sans secrets) as external evidence.
> Evidence Export Note: Export (a) OAuth session timeout configuration (yaml/json) and (b) encryption-at-rest enablement manifests (etcd + storage class) as signed artifacts; store alongside quarterly HIPAA technical safeguard evidence bundle.

### C.1 Additional HIPAA Safeguard Clarifications
| Citation | Safeguard Area | Theme(s) | OCP | RHACS | External | Notes |
|----------|----------------|----------|-----|-------|----------|-------|
| 164.308(a)(1)(i) | Risk Analysis | 1–9 | P | P | E | Technical metrics feed risk; formal analysis external. |
| 164.308(a)(5) | Security Awareness | External |  |  | E | Training program external. |
| 164.308(a)(7) | Contingency Plan | 5 / External | P |  | E | Quotas & limits (P); DR/backup external. |
| 164.308(a)(8) | Evaluation | 9 | P | P | E | Continuous exports (P/P); evaluation plan external. |
| 164.310 (Physical) | Facility Access | External |  |  | E | Physical controls external. |
| 164.312(a)(2)(i) | Unique User ID | 3 | C | P | E | OCP identity scoping (C); RHACS mapping (P); human user identity external. |
| 164.312(f) | Emergency Access | External |  |  | E | Break-glass IAM external; track in exception register. |

### C.2 HIPAA Evidence Bundle Examples
| Focus | OCP Artifact | RHACS Artifact | External Artifact | Narrative |
|-------|-------------|---------------|-------------------|----------|
| Integrity | ClusterImagePolicy / signature admission config | Blocked unsigned image log | Cosign verify output + key SOP | Combined platform verification config + enforcement outcome + key governance. |
| Audit Controls | Audit log forward config excerpt | Security event export hash | SIEM PHI access log sample | Infrastructure + security events correlated with PHI access trail. |
| Transmission Security | NetworkPolicy manifest + (if mesh) PeerAuthentication STRICT | (optional) Custom detection for plaintext endpoint | Ingress/mTLS config export | Demonstrates enforced segmentation + encrypted transport; detection for gaps. |
| Risk Management Input | MachineConfig & RBAC drift report | Vuln & misconfig trend export | Formal Risk Assessment report | Technical risk metrics feeding enterprise risk analysis. |

### C.3 HIPAA Quick Gap Checks
1. Unsigned image in production? (Integrity risk)
2. Privileged container exception without expiry? (Access safeguard gap)
3. Missing daily security event export hash? (Audit evidence gap)
4. No key rotation proof (<12 months)? (Integrity/encryption supporting gap)
5. DR test older than policy interval? (Contingency gap)

### C.4 Tailoring Statement
State RHACS is not the system of record for PHI access logs; it supplies infrastructure-layer security telemetry only.

### C.5 HIPAA Scope Statement (PHI Access Logging & Data Handling)
Use (or adapt) the following statement in audit packets to pre‑empt scope inflation around Protected Health Information (PHI) access monitoring:
> HIPAA technical safeguard evidence in this guide is limited to container platform and workload infrastructure controls (configuration enforcement, vulnerability/risk gating, segmentation, runtime anomaly detection, and supporting security telemetry). Application-layer PHI access events, database query logs, EHR system activity, and patient data masking/tokenization controls are maintained and evidenced by external systems (see External Control Register). RHACS and OpenShift do not serve as the system of record for PHI read/write, disclosure, or user-level access logs; they provide only infrastructure security context (policy violations, runtime anomalies, configuration drift) that may supplement investigations. Any request for PHI access trails should be redirected to the designated application/DB logging owners identified in the External Control Register.

Implementation Note: Include this scope statement alongside the Appendix G scope declaration in HIPAA audit readiness binders. If an auditor requests PHI access samples, respond using the redirect pattern (Appendix G.6) and cite this subsection.

---
## Appendix D – NIST SP 800‑190 Section 4.1.x
| Ref | Theme | OCP | RHACS | External | Intent |
|-----|-------|-----|-------|----------|--------|
| 4.1.1 | 1 | P | P | E | Minimal base surface via image sourcing + policy detection. |
| 4.1.2 | 1 | P | C | E | Trusted registries (policy enforcement primarily RHACS); OCP admission config (P). |
| 4.1.3 | 2 | P | P | E | Remove unnecessary components (policy + build guidance externally governed). |
| 4.1.4 | 1 / 6 |  | C |  | Pre-deploy scanning (RHACS). |
| 4.1.6 | 6 |  | P | E | Rebuild vs patch practice external; RHACS gating (P). |
| 4.1.7 | 8 | P | C |  | No secrets in images (RHACS detection C; OCP build controls partial). |
| 4.1.8 | 2 | C | P |  | Non-root enforcement (SCC) + RHACS detection. |
| 4.1.9 | 2 | C | P |  | Read-only FS (SCC/Pod settings) + policy detection. |
| 4.1.10 | 1 | P | P | E | SBOM correlation partial; generation external. |
| 4.1.11 | 1 | P | C | E | Signature/int integrity gating (RHACS policy C; platform admission P). |
| 4.1.12 | 1 | P | C |  | Digest pinning (policy enforcement). |
| 4.1.13 | 2 | C | P |  | Remove escalation paths (SCC + detection). |
| 4.1.14 | 1 |  |  | E | License compliance external. |
| 4.1.15 | 1 | P | P | E | Secure build pipeline integrity evidence external; policy gating partial. |

Legend: * items with platform or process focus outside RHACS core are marked (P) Partial or (E) External.

### D.1 Additional 800‑190 Sections (Selected)
| Ref | Area | Theme(s) | OCP | RHACS | External | Notes |
|-----|------|----------|-----|-------|----------|-------|
| 4.2.1 | Orchestrator Access Control | 3 | C | P | E | RBAC enforcement (C); RHACS visibility (P); strong authN external. |
| 4.2.2 | Segmentation & Network Policy | 4 | C | P | E | NetworkPolicy enforcement (C); coverage analytics (P); L7/mTLS governance external. |
| 4.2.3 | Secret Management | 8 | P | P | E | Leak detection (RHACS) + basic secret object handling (OCP P); vault & rotation external. |
| 4.2.4 | Limit Privileges | 2 / 3 | C | P | E | SCC/Pod Security (C); RHACS detection (P); host hardening external. |
| 4.2.5 | Resource Controls | 5 | C | P |  | Quotas/limits (C); missing limits detection (P). |
| 4.2.6 | Logging & Monitoring | 7 / 9 | P | P | E | Partial security events; full central logging external. |
| 4.2.7 | Admission & Policy Enforce | 1 / 2 | P | C | E | RHACS gating (C); OCP admission ordering & SCC (P); fail-closed config required; some policy roots external. |
| 4.3.1 | Host Hardening | External |  |  | E | CIS benchmark outside scope. |
| 4.3.2 | Host Vulnerabilities | External |  |  | E | Host scanning agents external. |
| 4.4.1 | Registry Security | 1 | P | P | E | Allowed registry policy (RHACS + OCP admission partial); registry RBAC external. |
| 4.4.2 | Build Integrity | 1 / 6 | P | P | E | Gating on outputs; provenance attestations external. |
| 4.5.1 | Runtime Threat Detection | 7 |  | C | E | Runtime baselines & patterns; deep forensics external. |
| 4.5.2 | IR Integration | 7 / 9 |  | C | E | Notifiers feed IR; runbooks external. |

### D.2 800‑190 Evidence Bundles
| Focus | OCP Artifact | RHACS Artifact | External Artifact | Narrative |
|-------|-------------|---------------|-------------------|----------|
| Segmentation | NetworkPolicy manifests + coverage % | Coverage % + flow graph | Firewall/mesh policy export | Layered segmentation (deny baseline, L7/mTLS, perimeter). |
| Secrets | (optional) External secret operator config reference | Secret violation trend | Vault rotation report | Detection complementing managed secret lifecycle & rotation. |
| Build Integrity | ClusterImagePolicy / admission verify config | Blocked unsigned image log | Pipeline attestation (SLSA/in‑toto) | Trust chain: config → enforcement → provenance proof. |
| Runtime Detection | (N/A) | Runtime alert → ticket | IR ticket with closure | Detection-to-response validation. |

### D.3 Quick Gap Check
1. Image from unapproved registry? (4.4.1)
2. Namespace missing deny-all baseline? (4.2.2)
3. Privileged container present? (4.2.4)
4. Missing attestation for critical service image? (4.4.2)
5. Collector coverage <100% nodes? (4.5.1 risk)

### D.4 Tailoring Note
Document that deep packet inspection, full memory forensics, and persistent packet capture are out-of-scope; list compensating tools in External Control Register.

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
| SAST / DAST / Code QA (PCI 6.3.2) | Static + dynamic testing incl. dependency & IaC scans | AppSec / RHTAP | Signed scan report bundle (hash chain) + pipeline run ID | Per Release | YYYY-MM-DD | Amber | Coverage gap in legacy service X; correlate run ID to blocked deploy evidence |
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
| Topic / Control Aspect | OCP Provides (Evidence / Enforcement) | RHACS Provides (Evidence / Enforcement) | External Responsibility | Recommended Evidence Bundle |
|------------------------|----------------------------------------|----------------------------------------|------------------------|-----------------------------|
| SBOM Association & Signature Policy | Admission signature verification config (ClusterImagePolicy), digest pinning | Policy gating on unsigned images / metadata; violation & compliance reports | SBOM generation, signing, storage (RHTAP), key custody | Policy JSON, admission config, blocked deploy log, SBOM file + cosign verify output |
| Vulnerability SLA Enforcement | (Optional) Image pinning manifests | Detects fixable CVEs, blocks severity, age metrics | Rebuild workflows, base image maintenance, change approvals | SLA matrix doc, vuln trend export, rebuild pipeline logs |
| Host / Node Hardening | MachineConfig enforcement, SCC restricting host access | Detection of privileged/host mount attempts | CIS benchmark, kernel params, firewall, patch cadence | CIS report, MCO diff, absence of privileged containers evidence |
| Network Segmentation | NetworkPolicy enforcement, namespace isolation baseline | Gap detection (missing policies), flow visualization | L7 authZ, DPI, IDS/IPS, mesh mTLS governance | NetworkPolicy coverage report, mesh policy export, IDS alert sample |
| Secrets Exposure | Platform secret objects, external secret operator integration | Pattern-based env/config secret detection | Vault storage, rotation, short-lived creds | Secret violation trend, vault rotation report, exception register |
| Runtime Threat Detection | (Baseline isolation reducing noise) | Process/network anomaly policies, notifier evidence | Full IR runbooks, forensics, SIEM correlation rules | Runtime alert sample + ticket, IR runbook version, SIEM correlated event |
| Logging & Integrity | Audit log emission & forwarding config | Alert/log export events, compliance scheduling, hash chain | WORM storage, retention, central correlation | Hash chain index, object lock config, SIEM ingestion dashboards |
| License Compliance (800-190 4.1.14 External) | (N/A) | (Indirect) package inventory via scans | License analysis, legal approval workflow | License scan diff, approval tickets, component report snapshot |
| Signature / Attestation Chain | Signature verification enforcement (admission) | Policy check for presence of signatures/labels | Key custody, Rekor transparency validation | Key management SOP, cosign verify log, policy pass report |
| Policy Exceptions | (N/A) | Violation visibility, enforcement phase tracking | Governance workflow (approvals, expiry) | Exception register, policy diff, closure ticket |
| Admission Reliability | Admission ordering & failurePolicy on platform webhooks | Webhook evaluation results & error metrics | HA config, cert rotation, DNS/network reliability | Webhook SLO dashboard, error metrics, blocked vs allowed stats |
| Resource Governance | Quotas & LimitRanges enforce ceilings | Missing limit detection policies | Capacity planning & autoscaling strategy | Limits compliance pass, quota manifests, utilization vs quota report |
| Data-in-Transit Security | Ingress TLS termination, optional mesh mTLS/IPsec | (Optional) Detection of plaintext endpoints (custom) | Certificate lifecycle, cipher policy management | Mesh cert inventory, gateway TLS config, detection result |
| Data-at-Rest Integrity | Encrypted etcd/storage (platform config) | Enforce signed/immutable images, non‑root | Storage encryption keys, snapshot protection | KMS config, snapshot immutability proof, non-root policy pass |
| SBOM vs Component Inventory | (N/A) | Vulnerability-derived component listing | Formal SPDX/CycloneDX & license context | Component export, SBOM file hash, license report |

> Use this index to pre-empt auditor “scope inflation” questions: for each shared control, you present split responsibilities plus cohesive evidence chain.

---
## Appendix G – Scope & Boundary Declaration
This appendix defines the authoritative scope boundaries for the evidence and control coverage described in this guide. Use it verbatim (with environment-specific substitutions) at the start of an audit cycle to suppress mis-scoping and to direct auditors to the correct authoritative systems.

### G.1 In-Scope Technical Components (Split: Platform Baseline vs RHACS Overlay)

#### G.1a Platform Baseline (OCP / RHCOS)
| Component | Scope Description | Control Surface (Representative) | Primary Evidence Artifacts |
|-----------|-------------------|----------------------------------|-----------------------------|
| OpenShift Kubernetes Control Plane (API Server, Scheduler, Controller Manager, etcd) | Cluster orchestration & API | RBAC, admission ordering context, audit/event emission | RBAC diff exports, selected audit log excerpts (forwarded), API server config (sanitized) |
| OpenShift RHCOS Nodes (Transactional OS) | Container execution substrate | OSTree signed images, MachineConfig-managed state, SELinux enforcing | MachineConfig diff history, OSTree commit IDs, SELinux enforcing status sample |
| Machine Config Operator (MCO) | Declarative node config reconciliation | Kernel args, file drop-ins, kubelet config | Signed MachineConfig YAML commits, MCO status reports |
| Compliance Operator (if deployed) | Benchmark scanning | CIS / custom profile rule evaluation | Scan summary report, pass/fail delta trend |
| Security Profiles Operator (SPO) (if deployed) | Seccomp / SELinux profile lifecycle | Custom profile distribution & attachment | Profile YAML + attachment manifests, audit log entries proving enforcement |
| Gatekeeper / OPA (if deployed) | Constraint-based policy | Naming/label/OPA invariants, custom admission checks | ConstraintTemplate & Constraint YAML (signed), violation events summary |
| Image Signature / Verification Config (ClusterImagePolicy, Quay, Sigstore) | Image trust & provenance enforcement | Signature & certificate trust roots, policy binding | ClusterImagePolicy export, verification logs, signer key inventory |
| Service Mesh / Ingress TLS Config (if enabled) | Transport security (north-south & east-west) | mTLS policy, TLS cipher config, route/ingress termination | Mesh PeerAuthentication/DestinationRule (STRICT), Ingress TLS cert inventory |
| Network & Segmentation Primitives | L3/L4 isolation & namespace scoping | NetworkPolicy enforcement, Multus/UDN segmentation | NetworkPolicy manifests, coverage % report, UDN inventory mapping |
| Resource Governance (Quotas/LimitRange) | Capacity & DoS resilience | Namespace quotas, limit ranges | Quota manifests + utilization report |

#### G.1b RHACS Overlay
| Component | Scope Description | Control Surface (Representative) | Primary Evidence Artifacts |
|-----------|-------------------|----------------------------------|-----------------------------|
| RHACS Central | Policy brain & API | Policy evaluation, compliance reporting, vuln data | Policy JSON exports (signed), compliance report hashes |
| RHACS Scanner / Scanner DB | Image & component analysis | Vulnerability & component inventory | Scan result exports, vuln trend metrics |
| RHACS Admission Controller (Validating Webhook) | Deploy-time gating | Misconfig, vuln, signature, risk-based deny/warn | Admission denial events, failurePolicy config snapshot |
| RHACS Sensor & Collector | Runtime & deploy telemetry | Process/network baselines, runtime policy triggers | Runtime alert logs, connected node coverage report |
| RHACS Notifiers (SIEM, Ticket, Chat) | External evidence & IR linkage | Alert forwarding & ticket creation | Notifier config snapshot, sample forwarded alert IDs |
| Secret Pattern Detection | Last-line exposure detection | Environment/config secret pattern matches | Secret violation trend report |
| Exception / Policy Phase Tracking | Progressive enforcement governance | Warn→Block transitions, time-bound exceptions | Exception register excerpt, policy phase labels export |
| Signature / Attestation Policy Integration | Enforce trusted images | Unsigned / untrusted image deny | Blocked deploy event, policy config + signer list |
| Vulnerability SLA Metrics | Risk reduction measurement | Age, fixability, SLA breach detection | Vulnerability SLA dashboard export, blocked image evidence |

### G.2 Explicit Out-of-Scope Areas
These areas are acknowledged dependencies or complementary controls but **not** in evidentiary scope for RHACS/OpenShift security enforcement in this guide. They must produce their own artifacts (tracked in External Control Register / Appendix E):
| Domain | Out-of-Scope Rationale | Primary System(s) | Required External Evidence |
|--------|-----------------------|-------------------|----------------------------|
| Enterprise IAM / MFA / SSO | User identity lifecycle & strong auth handled upstream | IdP (Keycloak, Okta, AAD, etc.) | MFA policy doc, IdP config snapshot, access review reports |
| Non-RHCOS Host OS Hardening / Bare Metal / Ancillary VMs | Guide centers on managed RHCOS nodes; other OS baselines differ | RHEL, Windows Server, Hypervisor layer | CIS benchmark reports, patch cadence, hardening scripts |
| Vault / Key Lifecycle Management | Secrets storage, rotation, escrow, key destruction | HashiCorp Vault, KMS (AWS KMS, Azure Key Vault), HSM | Key policy JSON, rotation logs, vault audit log excerpt |
| SAST / DAST / IaC Scanning | Application & infrastructure code analysis outside runtime/deploy gating | CI/CD security tools (SonarQube, CodeQL, Checkov, Trivy IaC) | Scan reports (hash), remediation tickets, pipeline run IDs |
| Software Composition Analysis License Governance | Legal & license risk not enforced in RHACS | Dependency/license scanner | License scan diff, approval register |
| Backup & Disaster Recovery | Data/state resilience, restore validation | Backup platform, DR orchestration | DR test report, RPO/RTO metrics, backup integrity log |
| Business Continuity / BIA | Organizational process domain | GRC tooling | BIA document, review approval |
| WAF / API Gateway / L7 Threat Mitigation | Application-layer security beyond L3/L4 policy | API Gateway, WAF, CDN | WAF policy export, sampled blocked request logs |
| IDS / IPS / Deep Packet Inspection | Packet payload & advanced signature analysis | Network IDS/IPS, eBPF sensors | Alert sample, rule pack version, coverage map |
| SIEM Correlation & Advanced Analytics | Cross-domain event normalization & correlation logic | SIEM / UEBA platform | Correlation rule pack diff, suppression list, dashboard screenshot |
| Central Log Retention, WORM Storage | Long-term immutable storage & legal hold | Object store (S3 Object Lock, GCS), SIEM archive | Retention policy export, object lock configuration, hash chain index |
| Data Encryption (At Rest & In Transit) Beyond Cluster Defaults | TLS termination, database/storage encryption lifecycle | Mesh, Ingress Controller, DB/KMS | TLS cipher policy, cert inventory, encryption enablement evidence |
| Incident Response Runbooks & Forensic Procedures | Human process & deep forensic tooling | IR platform, playbook repository | Runbook version hash, tabletop exercise report |
| Advanced Forensics & Memory Analysis | Memory/disk timeline, packet capture beyond RHACS telemetry | Forensics suite / EDR | Memory dump procedure, forensic artifact chain of custody |
| Host Vulnerability Management Outside Container Images | Kernel & package CVEs on host OS beyond image layer | Host scanning agents | Host vuln report, remediation SLA metrics |
| Data Privacy / PHI Access Auditing | Application-level data access not visible to RHACS | App logs, DB audit logs | PHI access log sample, masking/tokenization report |

### G.3 RHCOS Transactional (Controlled) vs “Immutable” Clarification
RHCOS (Red Hat Enterprise Linux CoreOS) is a **transactional, controlled** operating system managed via OSTree + MachineConfig Operator, not strictly immutable. Key assurance anchors:
1. **Signed Content:** OS updates delivered as signed OSTree commits (Red Hat content trust chain).
2. **Declarative State:** Desired node configuration declared via MachineConfig objects; drift visible and reconciled.
3. **Controlled Update Pipeline:** Cluster version operator orchestrates staged, verified rollouts (supports change evidence via version + commit IDs).
4. **SELinux Enforcing:** Mandatory access control assures workload confinement.
5. **No Assumption of Absolute Immutability:** Local alterations outside MachineConfig (emergency debug) must be treated as *exceptions* and remediated (or codified) quickly; evidence = diff + closure ticket.

Evidence Bundle (Example):
- MachineConfig YAML (signed commit) + associated OSTree commit IDs.
- `oc adm release info` output (release image signature) captured & hashed.
- SELinux enforcing status sample across nodes.
- Exception log (if any) for manual node changes with remediation.

### G.4 Scope Statement (Sample Language)
Use this statement in audit introductions:
> The scope of container platform security evidence covers workload and cluster security controls enforced and/or evidenced by RHACS, OpenShift control plane components, transactional RHCOS nodes (via MachineConfig & OSTree), and designated Red Hat-supported security operators (Compliance Operator, Security Profiles Operator, Gatekeeper where deployed). Controls outside this boundary (enterprise IAM/MFA, key lifecycle, application-layer security testing, DR/backup, WAF/IDS, SIEM correlation logic, long-term log retention, data encryption lifecycle) are provided and evidenced by external systems referenced in the External Control Register.

### G.5 Boundary Validation Checklist (Quarterly)
| Check | Method | Pass Criterion | Exception Handling |
|-------|--------|---------------|-------------------|
| All nodes on expected OSTree commit set | Compare reported node OSTree commit IDs against approved release manifest | 100% match (allow controlled canary subset) | Log deviation → investigate → reconcile MachineConfig |
| MachineConfig drift | Review current rendered MachineConfig state vs version-controlled baseline | No unmanaged node file changes | Create remediation PR or exception entry |
| SELinux enforcing everywhere | Sample representative nodes to confirm SELinux enforcement status | All = Enforcing | Investigate node; restore enforcing & document |
| Unsupported manual changes (out-of-band node edits) | MachineConfig Operator rendered-state comparison plus (optional) compliance file rule and targeted node inspection | No unmanaged file drift; all nodes conform to rendered MachineConfig | Immediate cordon & investigate → revert or codify via MachineConfig; raise exception ticket (time‑bound); treat manual change as policy violation |
| Operator baselines intact (Compliance/SPO) | Confirm operators healthy; review compliance suites & remediations status; verify active security profiles match approved hashes in repo; ensure no failed checks or unmanaged local-only profiles | All relevant operator components healthy; every profile matches approved baseline; zero failed compliance checks | If drift or failure detected: raise exception, restore profile from source or update baseline via approved review, document closure |

### G.6 Handling Out-of-Scope Auditor Requests
Provide a polite redirect pattern:
| Request Type | Response Template |
|--------------|-------------------|
| “Show MFA enrollment statistics” | Outside RHACS/OpenShift scope; refer to IAM evidence bundle (IdP config + MFA policy + enrollment report). |
| “Provide WAF blocked request sample” | WAF is external; see External Control Register (WAF domain) for policy export & log sample location. |
| “Demonstrate database encryption keys” | Key management is external; provide KMS key policy & rotation logs referenced in External Control Register. |
| “Show PHI access logs” | Application/DB audit responsibility; RHACS supplies infrastructure security events only (see Appendix C tailoring statement). |

### G.7 Change Control & Versioning of Scope
Version this Appendix (G) independently; any addition/removal of in-scope components requires:
1. Update Appendix G table(s)
2. Commit with signed tag referencing change ticket
3. Regenerate Appendix E entries if new external dependencies introduced
4. Notify audit preparation distribution list

> Principle: Scope drift without explicit versioning erodes evidence credibility—treat scope like code.

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
Combining RHACS (visibility, policy gating, runtime telemetry, evidence exports) with OpenShift (SCC, NetworkPolicy, signature verification, admission & RBAC primitives) yields a continuously validated control stack covering major container security expectations across NIST, PCI DSS, HIPAA, and NIST 800‑190. Focus on measurable reduction (vuln backlog, misconfig drift, alert noise) while maintaining tamper‑resistant, cryptographically verifiable evidence.

> Sustained compliance emerges from disciplined engineering feedback loops: enforce baselines, measure risk reduction, automate evidence, iterate.

---
