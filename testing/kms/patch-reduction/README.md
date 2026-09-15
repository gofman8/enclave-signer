# Minimal Nitro SDK patch verification

Production commit: `9eb759778e14b7c3e33aa1ebf73c85e0d4f20705`.
E2E source: `309ef408723dcf45148f4624db5ac80b4768cca0`, clean throughout the run.
Native suites and the negative control were rerun after the test-only error
assertion added in `5b34659`; production code did not change.

The SDK patch now changes **19 added / 8 removed source lines**, down from
41 / 14. It retains completion synchronization and two initialized cleanup
pointers. Allocation-NULL checks, partial-response destruction changes and
one-request synchronization-object cleanup were removed. The pinned AWS
allocator aborts on OOM; five forced-NULL tests bypassed that contract and
have been removed from the request-lifecycle suite.

The new [closed-connection regression](../native-tests/closed_connection.c)
uses actual AWS CRT SigV4 signing and HTTP transport. A loopback peer closes
before request activation. No wrappers replace signing or transport. Both
operation targets hang in the unmodified SDK until the three-second test alarm;
the reduced patch returns `AWS_ERROR_HTTP_CONNECTION_CLOSED` in under 1 ms.
This demonstrates the shared REST completion defect, not complete KMS service
semantics or TLS verification. See the [negative control comparison](closed-connection-comparison.json).

The production build script rebuilt the official SDK, its CLI tools and the
helper on Linux ARM64. All **five native suites** and **44 local E2E scenarios**
passed. The unchanged Rust enclave and parent binaries were reused and their
hashes matched the previous cleanup report. The SDK prefix's patch and effective
source hashes matched the tested checkout.

Results: [native suites](native-tests.log), [E2E](e2e-report.json),
[source and binary verification](verification.json).

Local E2E uses simulated KMS/IAM/STS/S3 and mock NSM. No live AWS or Nitro hardware
was used. The full enclave Docker/EIF build was not rerun for this reduction;
previous image/PCR measurements describe the earlier SDK patch.
