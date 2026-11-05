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
Use Python 3.10 or newer. Install the pinned development/test dependency, then run the regression suite:

```bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

The test runner uses Python's standard-library `unittest`; schema-parity checks additionally require the pinned `jsonschema` dependency.

This repository documents the ecosystem's intended scoped mixed-license policy: Apache-2.0 for eligible original code and machine-readable contracts, and CC BY 4.0 for eligible original human-readable documentation. Its manifest remains `pending-review` until contributor authority, file-level provenance and third-party notices are checked. Do not assume every file is cleared for redistribution. Third-party material retains upstream terms; data, evidence, fixtures, sample payloads and media receive no blanket license. See [LICENSE.md](LICENSE.md).
