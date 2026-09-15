# Final integration review after round-two fixes

Reviewed clean production `6cc65d635717ee6e69a0ac27c8cc78bd6f711800` on 15 September 2026. No additional critical
or high defect was found in the final integration review. This is a focused code
review and local verification, not an external security audit. This workstream
implemented the broker/relay changes; it independently reviewed the other
workstreams' phase, forwarder and native integration changes.

## Custody and identity

Startup loads existing ciphertext with or without a pin. Only confirmed missing
storage with no expected identity permits generation and conditional creation.
Pinned missing storage, load errors and invalid/decrypt-failing ciphertext never
create replacement keys. Signing and mint-burn custody behavior remain unchanged.
Absolute custody/helper/broker deadlines still fail closed; late PUT completion
is recovered by a subsequent load. The phase mutex is released for external I/O,
and swap read-only callback unwind drops its guard before resuming the panic.

## Local transport and diagnostics

The broker authorizes the kernel peer before request reads. Limits are 16 global
connections, four per CID; 16 global AWS workers, two per CID; and four dispatches
per second per CID with burst eight. Timeout does not release a still-running AWS
worker. Create has at most one conditional PUT and one GET, with no SDK/internal
retry. Full queues/rate buckets reject promptly; thread-start failures close the
socket, release quotas and leave the listener running.

The KMS relay uses guarded systemd socket activation. Actual VSOCK family, local
CID/port and peer CID are checked before any subprocess. systemd restricts each
source CID to two connections and all sources to 16; the connection service has
15-second lifetime and task/memory/descriptor caps, including aggregate limits.
The guard executes distro socat with a clean environment and one literal regional
TCP destination; TLS terminates inside the official SDK in the enclave. Old
unrestricted proxy units are retired in the migration instructions.

Swap egress now has four workers, four copy threads and eight queued connections
per listener. Queueing, nonblocking connect and both transfer directions share an
absolute lifetime; timeout/error closes both directions, while half-close permits
a complete response. Non-swap forwarder behavior stays on the prior code path.

Broker/native failure provenance is preserved only through fixed categories.
Unknown failures are not optimistically retryable, and no raw provider/host text
is forwarded. The coarse state is deliberately visible to the host/operator;
credentials, plaintext seed and sensitive provider diagnostics are excluded.

## Native integration and source provenance

The native helper checks the real KMS response KeyId before and after SDK parsing
and emits that checked response identity. Its flat private IPC rejects duplicate
members, while optional session-token semantics remain valid. The SDK request
lifecycle patch and fault-test bytes remain unchanged: retained proof has 16
passing fault/completion cases and 45 official SDK tests, with 10 unpatched
negative-control failures. Helper main.c changed in this round; the current
native/helper/E2E/EIF runs are recorded separately and the older helper results
are not reused as proof of changed source.

All four Cargo/NSM/pip lock hashes and native upstream coordinates match the saved
14 September public advisory query. `final-source-verification.json` binds the
current sources and exact maintained SDK patch. Parent systemd/socat are distro
packages outside that query; their separate scope is recorded in
`../round-two/host-dependency-disposition.md`.

## Fresh verification

All **62 deployment tests** and **222 independent IAM simulation cases** passed.
The policy fixture and production validator/policies are byte-identical. Source
hashes also match the completed **577 swap tests**, **542 mint-burn tests**, both
Clippy profiles, formatting, and **8 Linux forwarder tests** plus Linux build.
Actual Linux systemd **252.39** accepted all four units without warnings; the
verified distro socat package is **1.7.4.4-2**. Counts, commands and source/result
hashes appear in `final-test-verification.json` and
`../round-two/relay-systemd-verification.json`.

## Limits that remain explicit

The separate SDK connection-setup wait can miss an early notification; the helper
12-second deadline bounds that availability failure. The host can stop an enclave
or exhaust unrelated host resources. CID admission grants the full dedicated role
and cannot establish image identity; recipient attestation and narrow IAM remain
essential. An unpinned identity cannot authenticate a maliciously substituted
same-context seed; pin the verified address and complete backup/recovery validation
before funding. Inherited conditional webpki and optional Helios advisory limits
remain in `REMEDIATION.md`. Local unit checks and policy simulation do not prove
live AWS/Nitro enforcement, actual VSOCK socket activation/cgroup enforcement, or
production backup recovery.
