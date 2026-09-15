# Parent relay dependency scope

Checked 15 September 2026. The new relay uses the supported parent distribution's
systemd and socat packages, not vendored implementations of TLS or AWS signing.
The saved Cargo/NSM/pip advisory query does not cover these host packages. Its
unchanged-package conclusion must not be extended to the whole parent OS.

Local syntax verification used Debian bookworm-slim ARM64, systemd
252.39-1~deb12u2 and socat 1.7.4.4-2. The exact image digest, units, logs and limits
are recorded in `relay-systemd-verification.json`. The systemd version gate is a
functional minimum for verified VSOCK per-source admission, not a guarantee that
every installed host component is security patched. Deploy a supported distro
with its security updates; actual Nitro activation and admission remain live
parent checks.

The official [Debian socat package tracker](https://security-tracker.debian.org/tracker/source-package/socat)
was checked separately. The tested 1.7.4.4 series is outside the SOCKS5 client
introduced in 1.8.0.0, so it is unaffected by
[CVE-2026-56123](https://security-tracker.debian.org/tracker/CVE-2026-56123).
The supplied relay uses literal STDIO/TCP addresses and no SOCKS5 mode. Its
remaining [CVE-2024-54661](https://security-tracker.debian.org/tracker/CVE-2024-54661)
match concerns an installed readline.sh example, which this service never uses.
These are scope assessments, not a claim that every socat release above the
minimum is free of advisories.

The [Debian systemd tracker](https://security-tracker.debian.org/tracker/source-package/systemd)
contains open issues in the broader host package. This task validates the unit
parser and the pinned-version source's AF_VSOCK CID accounting; it is not a full
parent-OS audit. The new service emits fixed guard diagnostics, does not run
systemd-homed/machined functionality, and makes only a read-only manager version
query. Keep host package maintenance and host access controls operationally
separate from the enclave's KMS recipient-attestation boundary.
