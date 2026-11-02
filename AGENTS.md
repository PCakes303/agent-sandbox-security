# Agent instructions

- Treat all workload input as untrusted.
- Never add code that executes arbitrary workload payloads in the reference validator.
- Never weaken default-deny, stop-state validation, revocation, or policy checks to make tests pass.
- Do not describe policy validation as OS isolation.
- Any runtime backend must have independent security review and adversarial tests.
- Keep secrets, personal data, legal advice, and incident evidence out of this public repository.
