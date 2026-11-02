# Security Policy

This repository is an experimental sandbox admission-policy contract and reference validator. It is not an operating-system sandbox and must not be used as a security boundary for untrusted workloads.

## Reporting

Do not publish exploitable vulnerability details in public issues. Use GitHub private vulnerability reporting or a private security advisory only if enabled for this repository. No dedicated private reporting address is published here; if GitHub private reporting is unavailable, the owner must configure an approved private reporting channel before production use. Do not include credentials, secrets, personal data, or confidential incident evidence in public channels.

## Security expectations

- Treat all policy inputs and workload metadata as untrusted.
- The reference parser enforces a 1 MiB raw JSON ceiling and a 32-level nesting limit before decoding; filesystem and egress lists are bounded.
- The normative schema is tested alongside the runtime validator for non-execution, resource ceilings, traversal paths and collection limits.
- Preserve default-deny behavior and the unconditional non-execution guarantee of this reference implementation.
- Do not claim CPU, memory, filesystem, network, syscall, tenant, or process isolation from policy validation alone.
- Any future runtime backend requires independent security review and adversarial conformance tests.
