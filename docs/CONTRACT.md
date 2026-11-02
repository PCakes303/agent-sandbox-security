# Sandbox Admission and Isolation Contract 1.0

## Scope
This contract separates policy admission from actual isolation. The reference implementation validates declarative constraints and admission evidence only. It MUST NOT launch a workload or imply that requested restrictions are enforced.

## Admission prerequisites
A privileged workload may be admitted only when all of the following are present and verified by a trusted enforcement boundary:
1. Authenticated principal and workload identity bound to the requested audience and tenant.
2. Fresh default-deny policy decision bound to principal, action, resource, scopes, policy version, and expiry.
3. Verified artifact digest, publisher identity, signature, and provenance under the configured trust policy.
4. Active revocation status and current emergency-stop state with authenticated issuer, scope, monotonic epoch, freshness, and integrity.
5. Valid sandbox profile whose requested permissions are a subset of administrator-approved maximums.
6. Available audit sink and compliance control profile required by the deployment.
7. An isolation backend with tested enforcement of CPU, memory, process, time, storage, filesystem, network, IPC, and syscall restrictions appropriate to the workload.

Any missing, stale, malformed, indeterminate, or unavailable prerequisite MUST deny admission.

## Isolation profile
A backend MUST apply least privilege, immutable or ephemeral root filesystem, explicit writable mounts, no host credentials, no ambient host sockets, restricted syscalls, process-count and memory/CPU quotas, wall-clock deadline, output limits, network egress deny-by-default, DNS/IP/port allowlists where explicitly approved, and tenant separation. Limits are ceilings, not guarantees until enforced and tested by the backend.

## Emergency stop
Every execution lease MUST bind a stop authority identifier and monotonic stop epoch. The backend MUST check stop state before admission and at defined execution checkpoints. A newer stop epoch invalidates older leases. A node unable to validate current stop state MUST deny new privileged work and apply the documented safe-interruption behavior to active work. Workloads MUST NOT possess authority to alter stop state or resume themselves.

## Audit
Record admission decision, principal, artifact digest, profile, policy decision reference, stop epoch, backend identity/version, timestamps, outcome, resource-limit events, revocation events, stop events, and termination reason. Minimize personal and sensitive payload data. Audit integrity is not proof of event truth or completeness.

## Compliance
The deployment MUST map applicable legal and contractual obligations to controls and evidence. This repository provides no legal advice and does not certify compliance. Privacy, retention, data residency, breach response, and AI-use obligations are deployment-specific.

## Current release boundary
No OS sandbox backend exists here. Do not use this package as a security boundary or run untrusted workloads through it.
