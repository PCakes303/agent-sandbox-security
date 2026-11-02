# Agent Sandbox Security

Experimental contracts and reference validation for constrained agent/tool execution. This project defines execution policy, isolation requirements, resource ceilings, filesystem/network restrictions, emergency-stop integration, and fail-closed admission semantics.

**Important:** This release is a policy-contract validator, not an operating-system sandbox. It does not execute untrusted code, create namespaces/containers, enforce network or filesystem isolation, or guarantee resource containment. Production execution remains prohibited until a separately reviewed backend enforces the contract and passes adversarial conformance tests.

## Security posture
- Default deny; explicit allowlists only.
- No execution when identity, authorization, stop state, revocation, or required policy inputs are unavailable or stale.
- A manifest describes a workload; it never grants permission.
- Stop state is independently sourced from agent-emergency-control.
- Compliance control references are mapped through agent-compliance-governance.
- Untrusted workloads are never run by this repository's validator.

## Quick start
Run `python -m unittest discover -s tests -v` with Python 3.10+.

This repository applies a scoped mixed-license policy: original source code and machine-readable contracts are licensed under Apache-2.0; original human-readable documentation is licensed under CC BY 4.0. Third-party material retains upstream terms. Datasets, evidence, fixtures, sample payloads, media, and material with uncertain provenance are not blanket-licensed and require separate review. See [LICENSE.md](LICENSE.md).
