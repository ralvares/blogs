# Cloud-Native Security: From CVE Overload to Risk-Driven Resilience

This repository is a practical guide for navigating the modern vulnerability landscape in OpenShift and Kubernetes environments. It explains why CVE counts are so high, how container security differs from traditional VM patching, and how to move from reactive fixes to a risk-driven, resilient security program using Red Hat Advanced Cluster Security (RHACS).

---

## Narrative Map

### 1. Traditional VM Security: Where We Started
**Document:** [from-vms-to-containers-lifecycle-evolution-and-security-impact.md](from-vms-to-containers-lifecycle-evolution-and-security-impact.md)  
**Overview:**  
Explains the legacy approach to patching and vulnerability management in virtual machine environments. Highlights the challenges of manual patching, configuration drift, and limited visibility, setting the stage for why a new approach is needed.

---

### 2. The Container Shift: Why Containers Are Different
**Document:** [the-importance-of-the-base-image.md](the-importance-of-the-base-image.md)  
**Overview:**  
Describes how containers use immutable images and centralized patching. Shows why “zero CVE” images are a myth without disciplined rebuilds, and how increased visibility in container environments surfaces more vulnerabilities than ever before.

---

### 2a. Base Image Approval Policy
**Document:** [base-image-approval-policy.md](base-image-approval-policy.md)  
**Overview:**  
Describes the policy and automated enforcement for ensuring all container builds use only approved, secure base images. Explains how this reduces supply chain risk and is enforced in CI/CD using Conftest.

---

### 3. The Way Forward: Risk-Driven Security
**Document:** [from-cve-chaos-to-resilience.md](from-cve-chaos-to-resilience.md)  
**Overview:**  
Outlines a modern, risk-driven approach to vulnerability management using RHACS. Covers actionable strategies for prioritizing remediation, aligning with OpenShift lifecycle, and meeting compliance requirements. Provides an executive summary of RHACS value.

---

### 4. Compliance Mapping: Controls, Evidence & Boundaries
**Document:** [compliance.md](compliance.md)  
**Overview:**  
Provides a detailed compliance alignment guide for OpenShift and RHACS. Maps container/Kubernetes security controls to frameworks such as NIST 800-53, PCI DSS, HIPAA, and NIST 800-190. Explains in-scope vs. out-of-scope responsibilities, evidence expectations, and how to present platform capabilities during audits. Includes appendices for control mapping, scope declaration, and clarification registers.

---

## How to Use This Guide

1. **Start with the legacy pain points** in VM security.  
2. **Understand how containers change the game** and why visibility increases.  
3. **Adopt a risk-based, automated security approach** with RHACS and OpenShift.  
4. **Use the compliance mapping** to translate platform capabilities into audit-ready evidence across multiple frameworks.

---
