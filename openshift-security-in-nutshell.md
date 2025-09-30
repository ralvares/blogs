# OpenShift Security in a Nutshell: A Deep Dive for Technical Experts

## Security Overview Snapshot
Layered lifecycle narrative (foundation → supply chain → workloads → runtime → governance). Read top‑to‑bottom for a quick orientation:
- Foundation: Minimal, container‑optimized operating system (RHCOS) + hardened control plane (TLS 1.2+ encryption, SELinux, scoped auth) reduce inherent attack surface.
- Supply chain: Curated, digest‑pinned base images + repeatable rebuild pipelines propagate fixes once across all dependent workloads.
- Workloads: Admission control, SCC least‑privilege defaults, and scoped RBAC prevent unsafe privilege, root usage, or risky host access.
- Runtime & movement: NetworkPolicies / UDN + isolation and monitoring constrain lateral movement while supporting multi‑tenant density.
- Risk operations: Remediation guided by image freshness, fixability, exposure, and privilege context— not raw CVE counts.
- Lifecycle & updates: Signed releases, channels, and EUS options keep clusters current with less drift and rework.
- Governance & assurance: Encryption, signatures, audit logging, and exportable evidence accelerate compliance reviews.

## Introduction
OpenShift stands out as a Kubernetes platform engineered with security at its core, designed to address the complex threat landscape of modern containerized environments. For pre-sales engineers and security architects, understanding OpenShift's security architecture is crucial for positioning it against competitors and addressing customer concerns around compliance, risk mitigation, and operational efficiency. This comprehensive guide delves into the technical underpinnings of OpenShift's security model, highlighting how it implements defense-in-depth, zero-trust principles, and automated enforcement to reduce attack surfaces and operational overhead.

## Foundational Protection: Defense-in-Depth Architecture
Beginner summary (why this layer matters):
- Reduces what attackers can reach by minimizing the platform footprint.
- Enforces secure defaults (non‑root, encrypted traffic) before workloads deploy.
- Creates layered containment so one failure does not become a cluster breach.
OpenShift's security foundation is built on a multi-layered defense-in-depth strategy that anticipates and mitigates threats from the operating system level up to the application runtime. This approach ensures that even if one layer is compromised, subsequent layers provide containment and recovery mechanisms.

### Red Hat CoreOS (RHCOS): The Secure Base
At the heart of OpenShift is Red Hat CoreOS (RHCOS), a minimal, container-optimized operating system tailored for container workloads. Unlike general‑purpose OSes, RHCOS removes non‑essential services, significantly reducing the exposed component surface compared to general‑purpose distributions. Key security features include:
- **SELinux Enforcement**: Configured in enforcing mode by default, SELinux provides mandatory access controls (MAC) that confine processes to their intended domains, preventing privilege escalation and lateral movement.
- **Root Filesystem & Updates**: Root filesystem managed via OSTree with transactional updates and rollback, ensuring atomic, reversible changes that minimize downtime and exposure during patching.

### Control Plane Security
The OpenShift control plane is hardened with enterprise-grade protections:
- **TLS Encryption**: Inter-component communications use TLS 1.2+ encryption; mutual TLS is enforced on key paths like API server ↔ etcd and API server ↔ kubelet.
- **RBAC and Authentication**: Strict Role-Based Access Control (RBAC) is enforced by default, integrating with OAuth2 and enterprise identity providers (LDAP, Active Directory, OIDC). Service accounts are scoped to namespaces, reducing blast radius.
- **etcd Encryption**: Sensitive data in etcd is encrypted at rest (requires configuration).

### Threat-Aware Design and Real-World Mitigations
OpenShift proactively addresses known attack vectors:
- **Container Breakout Prevention**: Security Context Constraints (SCCs) enforce non-root execution by default (via the restricted SCC), block privilege escalation, and restrict host access; privileged SCCs exist for specific use cases. For example, CVE-2024-21626 exploits container build processes to escape to the host; OpenShift's SCCs and SELinux policies stop such attacks from spreading across the cluster.
- **Network Isolation**: By default, pod-to-pod traffic is open across namespaces (namespaces provide administrative scoping and RBAC separation, not automatic network blocking). To secure it, apply NetworkPolicies for least-privilege access. For stronger multi-tenant isolation, use User-Defined Networks (UDNs, available in OpenShift 4.15+) or Cluster UDNs, which create separate IP subnets.
- **Admission Controllers**: SCCs enforce workload safety, complemented by validating/mutating admission webhooks where configured, blocking misconfigurations like privileged pods or host mounts.

This foundation ensures that OpenShift reduces exposure to threats like lateral movement, root abuse, and untrusted code execution without requiring extensive custom configurations.

### Supply Chain & Base Image Governance (Shift-Left Rebuild Pattern)
External CI/CD pipelines and registry integration (e.g., Tekton, GitHub Actions, GitLab CI, Argo) — with optional RHACS policies where deployed — enable a “fix once → propagate” pattern oriented entirely around container images:
- Curated, frequently rebuilt base images (e.g., Red Hat UBI, certified partner images) keep dependency drift low; selection/governance is a process/policy, not a built‑in "approval" feature.
- Policy controls (allowed registries, tag immutability, minimal severity gates) can be implemented via pipeline checks, admission (ValidatingAdmissionPolicy / Gatekeeper), or RHACS (if installed) to block untrusted or vulnerable images.
- Digest pinning ensures immutability; signature creation (cosign/Sigstore) happens in the build pipeline; enforcement can be done via RHACS signature policies or custom admission controllers.
- Automated rebuild pipeline: When a base/base-layer image is updated, CI triggers downstream image rebuilds so updated layers propagate across applications—avoiding ad‑hoc, reactive manual image patching.
- Example artifacts: signature verification log, blocked unsigned image event (if enforced), vulnerability policy export, deployed image digest list, exception register (if any).
Outcome: Shorter remediation cycle time and lower recurring operations overhead versus manual, one‑off image triage.

## Platform Lifecycle and Upgrade Security
Beginner summary:
- Predictable, signed updates reduce risk from outdated components.
- Support phases guide when to upgrade to stay protected.
- Disconnected (air‑gapped) workflows still allow timely security updates.
Security in OpenShift extends throughout the platform's lifecycle, from deployment to decommissioning, ensuring continuous compliance and patch management.

### Managed Components and Release Process
Red Hat maintains critical components (RHCOS, CRI-O, kubelet) through a rigorous release cycle, including security audits and vulnerability assessments. Updates are delivered via Operator Lifecycle Manager (OLM), ensuring consistency across clusters.

### Support Timelines and Extended Update Support (EUS)
Each release has defined support phases: Full Support (bug fixes and security patches), Maintenance (critical security fixes), and EUS (extended updates for stability and security in long-term environments). This predictability allows customers to plan migrations and avoid unsupported versions that expose them to unpatched vulnerabilities.

### Transparency and Compliance Artifacts
- **SBOMs and VEX**: Red Hat provides Software Bills of Materials (SBOMs) and Vulnerability Exploitability eXchange (VEX) documents, enabling automated vulnerability scanning and compliance reporting (e.g., for NIST, CISA, NIS2, and Cyber Resilience Act (CRA) requirements).
- **Air-Gapped Updates**: Signed releases support disconnected environments using OpenShift's supported image mirroring workflows (e.g., oc mirror, image content source policies) for secure patch delivery.

This lifecycle management minimizes configuration drift and ensures platforms remain hardened against evolving threats.

### Risk-Based Vulnerability & Lifecycle Alignment
Borrow risk signals instead of reacting to raw CVE totals:
- Fixability first: Gate on fixable Critical (then High) CVEs; avoid churn on non‑fixable issues.
- Exposure context: Combine ingress/egress posture + network policy scope + SCC privilege level.
- Image freshness: Track age; stale images correlate with accumulated unremediated issues.
- Lifecycle phase awareness: Align upgrades with Full Support / Maintenance / EUS windows to avoid security debt.
Outcome: Focus engineering on exploitable risk surfaces—often reducing remediation noise and audit friction.

## Data Protection: Encryption and Integrity
Beginner summary:
- Protects sensitive data both where it is stored and while moving.
- Centralizes key and certificate handling to reduce manual errors.
- Ensures compromised pods cannot easily read or leak secrets.
OpenShift implements comprehensive data protection mechanisms to safeguard sensitive information at rest and in transit.

### Secrets and Encryption Management
While Kubernetes Secrets are base64-encoded by default, OpenShift enhances this with:
- **etcd Encryption**: AES-256 encryption for secrets, with key rotation support.
- **External KMS Integration**: Seamless integration with cloud KMS (AWS, Azure) or Vault for centralized key management, supporting compliance with standards like FIPS 140-2.
- **Automated Certificate Management**: cert-manager integration for TLS certificate lifecycle, reducing manual overhead.

### Volume Encryption and Persistent Storage
Data persistence is secured without application changes:
- **CSI Driver & ODF Encryption**: Persistent volumes can use underlying cloud provider encryption (e.g., AWS EBS, Azure Disk) or OpenShift Data Foundation (ODF) for integrated encryption across cloud and on-premises. This means that no matter where your cluster runs, your application data can be encrypted without changes to the app itself.
- **Node-Level Encryption**: LUKS-based full-disk encryption on RHCOS nodes protects against physical access or disk theft.
- **Application Data Protection**: Databases, logs, and secrets remain encrypted, even in hybrid cloud scenarios.

### TLS Everywhere
All communications are TLS-encrypted by default:
- **API and Web Console**: Mutual TLS is used for key control plane paths (e.g., API server ↔ etcd).
- **Service Mesh Integration**: Istio or Red Hat Service Mesh extends encryption to east-west traffic, with mTLS enforcement.
- **Ingress and Egress**: Automated certificate handling for external routes.

This ensures data integrity and confidentiality, mitigating risks like eavesdropping or tampering.

## Identity, Access, and Workload Controls
Beginner summary:
- Ensures only the right users and services can perform sensitive actions.
- Blocks risky workload settings by default (via restricted SCC); privileged access requires explicit SCC assignment.
- Verifies image origin and integrity before running workloads.
OpenShift embeds zero-trust principles through granular access controls and workload enforcement.

### Authentication and Authorization
- **OAuth2 Integration**: Default OAuth server supports enterprise SSO, with fine-grained RBAC for users, groups, and service accounts.
- **Audit Logging**: Structured logs capture all API interactions, integrable with SIEMs (Splunk, ELK) for compliance (e.g., SOX, GDPR).

### Workload Security and SCCs
Admission controllers enforce SCCs, preventing:
- Root execution and privilege escalation.
- Host resource access (networking, PID, mounts).
- Misconfigurations that could lead to breaches.

### Image Supply-Chain Integrity
- **Signature Verification**: Integrates with Sigstore for cryptographic signing; blocking unsigned images requires policy enforcement (e.g., via admission controllers or RHACS).
- **Trusted Registries**: Policies restrict pulls to approved sources, with RHACS providing policy-driven detection of vulnerabilities and risky configurations plus enforcement via admission control.
- **Build Security**: Controlled build environments (e.g., Tekton, GitHub Actions, GitLab Runners, Argo) perform reproducible container builds with pinned base image digests, signature generation (cosign/Sigstore), provenance attestations, and policy gates to block untrusted artifacts, reducing supply-chain risk.

These controls automate security, reducing human error and enabling DevSecOps workflows.

## Runtime Isolation and Visibility
Beginner summary:
- Limits blast radius if a container is compromised.
- Provides monitoring and alerting for potential issues (e.g., via integrated monitoring stack and audit logs).
- Provides data needed for incident investigation and compliance.
Once deployed, OpenShift maintains runtime security through isolation and observability.

### Network Controls
- **NetworkPolicies**: Enforce micro-segmentation, with UDNs (available in OpenShift 4.15+) for stronger isolation in multi-tenant setups.
- **Multus and Multi-NetworkPolicies**: Support legacy VLAN connectivity and advanced traffic control, integrating with SDN for zero-trust networking.

### Audit and Monitoring
- **Integrated Monitoring**: Built-in platform monitoring and alerting provide metrics, health insights, and basic anomaly detection without additional setup, enabling proactive issue identification.
- **Network Observability**: Flow logs, dropped packets, and traffic analysis via optional operators.
- **Compliance Operator**: Automated compliance scanning for CIS Benchmarks, PCI-DSS, STIG, HIPAA, and other regulatory frameworks, with exportable evidence for audits.

This visibility enables proactive threat hunting and incident response.

## Workload Classification & Node Placement ("Compute Zones")
High-level intent: run workloads of different data sensitivity on one cluster without pretending namespaces alone solve everything. Separate node pools (zones) plus simple labels and policy let you prove higher‑risk data never quietly co-resides with low‑risk apps.

Why it exists (problem framing):
- Some risks (kernel escape, side‑channel timing, noisy neighbor contention, forensic contamination) are outside the reach of NetworkPolicies.
- Teams often jump straight to extra clusters (cost, complexity) because they lack a lightweight middle step.
- Auditors want evidence that sensitive workloads are deliberately placed, not "best effort".

Core principles (keep it small):
1. Clear ladder of sensitivity (e.g., Public → Internal → Confidential → Restricted). Fewer levels = fewer mistakes.
2. Each level maps to its own worker node pool. Higher levels never share nodes with lower ones.
3. A single required workload label (e.g., data-classification) must match the node pool label. If it doesn’t, deployment is rejected.
4. Stricter level ⇒ tighter guardrails (privilege, networking, secrets patterns) and faster patch/vulnerability response.
5. Continuous lightweight checks: "Does any running pod’s declared classification differ from the node it landed on?" Zero tolerance for drift.
6. Document what is still shared (kernel, control plane) and when you would promote a level to its own cluster.

Simple operating model:
- Publish the taxonomy + handling rules in version control.
- Label and taint nodes per zone (e.g., taint nodes with classification level to restrict scheduling).
- Use node selectors and tolerations on pods to ensure workloads land on matching zones.
- Enforce label consistency with one policy mechanism.
- Track evidence: node pool inventory, drift checks, exceptions.
- Review periodically to decide if a zone needs its own cluster.

Outcome in one sentence: Compute Zones give you a pragmatic, auditable middle ground—proving deliberate segregation of sensitive workloads—before incurring the overhead of multiplying clusters.


## MITRE ATT&CK + OpenShift and RHACS

**Beginner summary:**

- Maps common attack steps to the controls that reduce or detect them.
- Helps teams justify platform controls to auditors and leadership.
- Reinforces layered defense: multiple safeguards for each tactic.
Mapping common container/Kubernetes threat tactics to native controls for defensible conversations. (Technique IDs from MITRE ATT&CK where applicable.)

### Initial Access
**Techniques**

T1552.001 (Token theft)
T1528 (Cloud Account Access)
T1555 (Credential dump)
T1190 (Exploit vulnerable component)
T1203 (Public-facing application exploit)

**Example Scenario**

A developer accidentally commits a service account token to a public Git repository. An attacker uses the stolen credentials to access the cluster and deploy a pod, or exploits an outdated, unauthenticated web service exposed via a Route.

**Mitigations**

- OAuth with external IdPs (e.g., LDAP, GitHub, OIDC) ensures federated and auditable authentication with short-lived tokens.
- etcd encryption at rest protects stored tokens and credentials.
- RHACS enforces image signature verification, ensuring only trusted and signed images are deployed.
- RHACS blocks unscanned images or those pulled from unapproved registries.
- Audit logs capture unauthorized access patterns.

### Credential Access
**Techniques**

T1555 (Credential Dumping)
T1528 (Cloud Account Access)

**Example Scenario**

A compromised pod gains access to mounted secrets and attempts to exfiltrate cloud access keys or service account tokens via environment variables.

**Mitigations**

- etcd encryption protects secrets in the control plane.
- SCCs restrict access to host-level secret storage and prevent unnecessary host mounts.
- RHACS detects secrets exposed as environment variables and flags deployments violating secure secret handling policies.
- Kubernetes RBAC controls restrict secret access to only authorized service accounts within the correct namespace.
- RHACS/Audit logs provide visibility into secret access events.

### Privilege Escalation
**Techniques**

T1068 (Privileged Container)
T1078.004 (Valid Cloud Accounts)
T1098 (Account Addition)
T1087 (Account Discovery)

**Example Scenario**

A CI/CD misconfiguration allows a developer to deploy a container requesting privileged SCC. Alternatively, a user creates a ClusterRoleBinding granting cluster-admin to a service account.

**Mitigations**

- SCC enforcement denies privileged containers or host namespace access unless explicitly allowed.
- RHACS policy blocks deployments using privileged, hostPID, or hostNetwork settings.
- OpenShift audit logs capture all RBAC changes and ClusterRoleBindings, enabling post-event analysis.
- RHACS detects and alerts on privilege escalation attempts, role bindings, and misuse of elevated privileges.
- Kubernetes RBAC scoping ensures fine-grained access control to prevent unauthorized privilege elevation.

### Persistence
**Techniques**

T1602.002 (Kubernetes Pod Spec Modification)
T1053.005 (Scheduled Task/Job)

**Example Scenario**

An attacker modifies a CronJob or Deployment spec to continuously pull a backdoored image, ensuring persistent access to the cluster.

**Mitigations**

- RHACS detects drift from baselines, including new or updated pods with risky behaviors.
- Integration with GitOps (e.g., ArgoCD) provides visibility into unauthorized configuration changes and allows automated rollback.
- Admission control and RHACS policies can block workloads not matching defined standards (e.g., labels, annotations, registries).
- Audit logs track spec updates and Deployment/Job creation events.

### Execution
**Techniques**

T1059 (Command Execution)
T1609 (Container Escape)

**Example Scenario**

An attacker gains interactive access to a pod using kubectl exec and uses it to download malware, establish persistence, or attempt container escape.

**Mitigations**

- RHACS detects and alerts on exec activity, especially when initiated by unexpected users or service accounts.
- SCCs deny containers the ability to run as root, escalate privileges, or access host IPC and PID namespaces.
- OpenShift audit logs track exec activity including the initiator and target pod.

### Defense Evasion
**Techniques**

T1562 (Disable Logging)
T1070.004 (Clear Audit Logs)

**Example Scenario**

A privileged container modifies API server logging configuration or attempts to overwrite/delete audit logs to obscure unauthorized activity.

**Mitigations**

- OpenShift audit logs are centrally configured and should be forwarded to immutable or external storage.
- Only cluster admins can modify audit profiles, and all changes are logged.
- Immutable infrastructure principles (e.g., read-only file systems) can limit an attacker's ability to clear logs.

### Discovery
**Techniques**

T1083 (System Discovery)
T1033 (User Account Discovery)

**Example Scenario**

A compromised pod or workload begins querying the Kubernetes API to list nodes, namespaces, service accounts, and RBAC bindings to understand the cluster topology.

**Mitigations**

- RBAC scoping prevents broad access to discovery APIs, especially across namespaces.
- OpenShift audit logs track all API calls, enabling detection of reconnaissance patterns.
- Service accounts should be minimally scoped and namespace-bound by default.

### Lateral Movement
**Techniques**

T1021.004 (SSH)
T1571 (Non-standard Ports)
T1046 (Network Scanning)
T1040 (Network Sniffing)

**Example Scenario**

A pod is compromised and begins scanning internal IP ranges, initiating connections to other pods via non-standard ports or attempting SSH brute force to jump between workloads.

**Mitigations**

- Kubernetes NetworkPolicies with default-deny configurations isolate workloads by namespace, label, or application.
- RHACS flags deployments with overly permissive ingress/egress, or containers using suspicious ports and protocols.
- Disallow use of hostNetwork and NodePorts unless explicitly needed via SCCs.
- SCCs deny access to raw networking capabilities and host-level devices.

### Collection
**Techniques**

T1083 (System Discovery)
T1033 (User Discovery)

**Example Scenario**

An attacker collects mounted secrets, ConfigMaps, or sensitive environment variables from compromised pods.

**Mitigations**

- Avoid storing secrets in environment variables; mount as read-only volumes with least privilege.
- SCCs restrict container access to host volumes, /proc, or /etc.
- RHACS policies flag containers that expose sensitive data (e.g., access keys, passwords, tokens).
- Use RBAC to scope access to ConfigMaps and Secrets, especially across namespaces.

### Command and Control (C2)
**Techniques**

T1571 (Non-standard Port Communication)

**Example Scenario**

A compromised pod initiates an outbound connection over an encrypted channel to an attacker-controlled server on a high, non-standard port.

**Mitigations**

- OpenShift NetworkPolicies with egress rules can block unauthorized outbound traffic.
- SCCs deny use of host networking or raw socket capabilities.
- RHACS detects baseline deviations in runtime behavior, such as unexpected processes initiating network connections or containers communicating with unfamiliar external destinations.

### Impact
**Techniques**

T1490 (Inhibit System Recovery)
T1489 (Service Stop)
T1491 (Defacement)
T1496 (Resource Hijacking)
T1485 (Service Crash)

**Example Scenario**

An attacker deploys a resource-heavy container that exhausts node memory, deletes backups, and replaces the front-end UI of a customer-facing app with a defaced page.

**Mitigations**

- Deployment revision history allows rollback to known-good versions of workloads.
- OADP (OpenShift API for Data Protection) provides full backup and recovery support for clusters, namespaces, and PVCs.
- ResourceQuotas and LimitRanges prevent over-consumption and container sprawl.
- SCCs restrict privileged workloads that could cause node instability or impact control plane components.
- OpenShift Monitoring integrated with Alertmanager notifies operators of node pressure, pod crashes, and container-level anomalies.
- RHACS policy engine can block deployments that violate operational or availability rules (e.g., containers without probes, high resource limits, no liveness/readiness checks).

*Contributes to mitigation/detection; layered defenses required.

## Appendix: CIA Triad Mapped to OpenShift Security Controls (with MITRE ATT&CK)
Purpose: Provide a concise assurance matrix linking confidentiality, integrity, and availability objectives to native OpenShift capabilities (core) and clearly optional ecosystem additions. “Techniques Mitigated/Detected” indicates contribution to preventing or discovering activity (not absolute prevention).

### Confidentiality
| CIA Pillar | Security Domain | Native OpenShift Capability (Core) | Optional / Ecosystem | Common Threats Reduced | MITRE ATT&CK Tactics | Example Techniques Mitigated/Detected* |
|------------|-----------------|------------------------------------|----------------------|------------------------|----------------------|--------------------------------|
| Confidentiality | Authentication & Token Handling | OAuth server; external IdP integration (LDAP/AD/OIDC); short‑lived tokens; service account scoping | RHACS policy on risky service accounts | Stolen credential reuse; unauthorized API access | Initial Access; Credential Access | T1552.001 (Token theft); T1528 (Cloud Account Access); T1555 (Credential Dump) |
| Confidentiality | Secrets & Key Protection | etcd encryption at rest; namespace scoping; secret volumes (vs env); TLS to API | External KMS (Vault, AWS KMS); RHACS secret exposure detection | Secret exfiltration; plaintext leakage | Credential Access; Collection | T1555 (Credential Access); (API enumeration + exfil) |
| Confidentiality | Network Segmentation | Namespaces; NetworkPolicies (ingress/egress) | UDN / Multus secondary networks | Cross‑namespace snooping; lateral recon | Lateral Movement; Command & Control | T1046 (Network Scanning); T1571 (Non‑standard Port C2); T1040 (Network Sniffing) |
| Confidentiality | Supply Chain Image Integrity | Image digests; trusted registry constraints; admission checks | Signature enforcement (cosign + RHACS); vulnerability policy gates | Tampered / rogue images; provenance uncertainty | Initial Access; Execution | T1190 (Exploit vulnerable component); (malicious image run) |

### Integrity
| CIA Pillar | Security Domain | Native OpenShift Capability (Core) | Optional / Ecosystem | Integrity Risks Reduced | MITRE ATT&CK Tactics | Example Techniques Mitigated/Detected* |
|------------|-----------------|------------------------------------|----------------------|------------------------|----------------------|--------------------------------|
| Integrity | Host & Runtime Hardening | RHCOS (minimal, container-optimized OS); SELinux enforcing; SCC (non‑root, no privilege escalation) | RHACS runtime policy (process / syscall baseline) | Container breakout attempts; privilege escalation | Privilege Escalation; Execution | T1068 (Privileged Container); T1059 (Command Exec); T1609 (Container Admin Command) |
| Integrity | Workload Admission & Policy | SCC; resource constraints; label/annotation validation (admission) | Gatekeeper / ValidatingAdmissionPolicy; RHACS deployment gates | Unsafe pod specs; stealthy misconfig | Defense Evasion; Persistence | T1602.002 (Pod Spec Modification); T1562 (Defense Evasion) |
| Integrity | Configuration & Drift Control | Deployment/StatefulSet revision history; immutable image digests | GitOps (Argo CD) drift detection & rollback | Unauthorized config changes; silent drift | Persistence; Privilege Escalation | T1602.002; T1098 (Account Addition via RBAC change) |
| Integrity | Image Build & Promotion Discipline | Namespaces / stage separation in CI/CD pipelines | Pipeline signing (cosign); RHACS supply chain policies | Injection of unverified artifacts | Initial Access; Execution | (Malicious build artifact); T1190 |

### Availability
| CIA Pillar | Security Domain | Native OpenShift Capability (Core) | Optional / Ecosystem | Availability Risks Reduced | MITRE ATT&CK Tactics | Example Techniques Mitigated/Detected* |
|------------|-----------------|------------------------------------|----------------------|---------------------------|----------------------|--------------------------------|
| Availability | Health & Resilience | Readiness/liveness probes; horizontal pod autoscaling; multi‑zone scheduling | Service Mesh circuit breaking | Crash amplification; cascading failures | Impact | T1485 (Service Crash) |
| Availability | Resource Governance | ResourceQuotas; LimitRanges; priority classes | RHACS policy on excessive resource requests | Resource exhaustion / noisy neighbor | Impact; Execution | T1496 (Resource Hijacking) |
| Availability | Monitoring & Alerting | Integrated platform monitoring & alerting; events; audit integration | Network observability add-ons; external SIEM | Delayed detection of failures or runtime anomalies | Discovery; Impact | T1083 (Discovery leading to abuse); T1490 (Inhibit Recovery) |
| Availability | Backup & Recovery | etcd backup tooling; rollout strategies; revision history | OADP (Velero); DR tooling | Data/state loss; irreversible misconfig | Impact; Persistence | T1490 (Inhibit System Recovery); T1489 (Service Stop) |

*Techniques mitigated/detected: Control contributes to prevention or detection; layered defenses still required.

Summary (Narrative Overview):
- **Confidentiality**: Robust authentication and authorization (AuthN/Z) mechanisms, integrated with secure secrets management in etcd and external KMS options, ensure that sensitive data remains protected. Network segmentation via NetworkPolicies and UDNs prevents unauthorized lateral movement and snooping across namespaces. Image signing and provenance enforcement, supported by RHACS, guarantee that only verified and untampered container images are deployed, reducing risks from supply chain attacks and credential misuse.
- **Integrity**: Security Context Constraints (SCCs) enforce non-root execution and prevent privilege escalation, while SELinux provides mandatory access controls at the host level. Admission controllers validate workload specifications before deployment, blocking unsafe configurations. Immutable image digests and GitOps integrations detect and rollback unauthorized changes, ensuring that container specs and configurations remain tamper-proof and consistent with trusted baselines.
- **Availability**: Readiness and liveness probes, combined with horizontal pod autoscaling, maintain application health and responsiveness. ResourceQuotas and LimitRanges prevent resource exhaustion from noisy neighbors or malicious workloads. Comprehensive monitoring and alerting, integrated with external SIEMs, accelerate detection of anomalies. Backup and recovery tools like OADP enable quick restoration from incidents, minimizing downtime and data loss.


## Compliance and Ecosystem Integrations
OpenShift facilitates compliance with frameworks including CIS Benchmarks, DISA STIG, PCI-DSS, HIPAA, FedRAMP, and emerging regulatory focus areas like DORA and NIS2 (proper configuration required). It does so through:
- **Certified Components**: FIPS-validated cryptography and SELinux for government workloads.
- **Third-Party Tools**: Integrations with RHACS, Quay, and external scanners for end-to-end security.
- **Automation**: Operators for policy enforcement, reducing audit overhead.

Link platform + RHACS controls to framework themes using a simple coverage model (OCP | RHACS | External). Clearly mark partial vs external to pre‑empt scope inflation during audits.
Outcome: Smoother evidence preparation; fewer custom scripts to gather artifacts.

## Competitive Advantages for Pre-Sales

### Detailed Technical Sales Version
When evaluating Kubernetes platforms, OpenShift differentiates through integrated security controls that reduce custom assembly effort. Upstream Kubernetes typically requires stitching together admission, network policy enforcement, signing, image governance, and lifecycle tooling. OpenShift delivers these primitives ready for configuration, often accelerating secure implementation. Security Context Constraints (SCCs) and TLS defaults reduce misconfigs; network isolation requires NetworkPolicies. This eliminates common misconfiguration paths and shortens audit preparation.

Total cost of ownership improves as managed lifecycle (automated updates, SBOMs, defined support phases) reduces maintenance overhead versus maintaining disparate add‑ons in environments like self-managed upstream, EKS, or GKE. Compliance readiness benefits from FIPS-validated cryptography, audit logging, and exportable evidence artifacts—lowering the manual effort to satisfy frameworks such as PCI DSS or HIPAA. Teams frequently report reduced incident triage time as secure defaults constrain privilege and lateral movement potential.

Ecosystem flexibility remains: RHACS for advanced scanning/policy, external KMS for key management, service mesh for mTLS, GitOps for drift control. This supports hybrid and multi‑cloud strategies with consistent enforcement. Emphasize how defense‑in‑depth—from the operating system hardening layer through runtime monitoring—contains lateral movement attempts that constitute a significant share of container breach activity in industry reporting.

### Executive Summary Version
- **Accelerates secure implementation**: Integrated admission, network isolation, signing, and least‑privilege defaults reduce the time to a governed, production‑ready baseline.
- **Lowers operating and compliance effort**: Managed updates, SBOM/VEX transparency, and exportable evidence decrease repetitive integration and audit cycles.
- **Reduces risk surface and response time**: Built-in isolation, non‑root enforcement, and CI-triggered rebuild patterns that propagate base image updates across dependent workloads limit blast radius and speed remediation.


## Conclusion
OpenShift's security is integrated across every layer and lifecycle phase—from the operating system to workloads, runtime, and governance—providing a hardened platform that scales with enterprise needs. For technical experts, this means proactive risk reduction, faster remediation cycles, and consistent enforcement. In a world of increasing cyber threats, OpenShift helps organizations allocate more time to delivering business value instead of assembling and maintaining fragmented security tooling.

Security in OpenShift is integrated into every layer and lifecycle stage of the platform, ensuring resilient operations, reduced risk, and faster compliance.

Executive takeaway: With OpenShift, security is continuous, automated, and aligned to business outcomes.
