# Threat Model

## Assets
Host kernel and filesystem; credentials and secrets; tenant data; agent identity; policy and stop authority; audit evidence; availability and integrity of execution hosts.

## Adversaries
Malicious or compromised skill/tool; prompt-injected agent; malicious dependency or artifact publisher; compromised peer/node; tenant attempting escape or resource exhaustion; attacker replaying stale authorization or resume messages; insider misusing privileged controls.

## Trust boundaries
Untrusted workload to host; workload to network; tenant to tenant; agent to adapter; execution node to control plane; public metadata to authenticated identity; policy decision to enforcement point; emergency-stop authority to runtime.

## Threats and required mitigations
- Escape or host compromise: use a separately reviewed OS isolation backend, defense in depth, patched kernel/runtime, no ambient privileges, and adversarial escape testing.
- Unauthorized execution: authenticate identity, bind fresh policy decision to action/resource, verify artifact provenance, default deny.
- Stop bypass/replay: independent stop authority, authenticated monotonic epochs, stale-message rejection, local enforcement, controlled resume.
- Resource exhaustion: enforce CPU, memory, process, disk, output, network, and wall-clock quotas at OS/backend boundary.
- Data exfiltration: deny network by default, explicit egress allowlists, mount allowlists, no host credentials, data minimization.
- Cross-tenant access: separate namespaces/VMs or stronger isolation according to risk; test filesystem, IPC, network and cache boundaries.
- Audit tampering: authenticated ingestion, external checkpoints, restricted write authority, retention and access controls.
- Supply-chain compromise: pinned dependencies, SBOM, provenance and signature verification, revocation.
- Compliance failure: map use-case-specific obligations, data flows, retention, rights, incident timelines and required human review before deployment.

## Out of scope
This reference validator does not mitigate OS/kernel vulnerabilities, enforce isolation, prevent side channels, or provide production runtime guarantees.
