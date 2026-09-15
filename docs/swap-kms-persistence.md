# RGB swap seed persistence

Production `rgb-swap` builds use AWS KMS to generate a 64-byte seed and S3 to
persist its encrypted `CiphertextBlob`. On initialization the enclave loads the
saved blob, decrypts it with KMS recipient attestation, and passes the seed to
its existing key derivation. Signing stays inside the enclave; it does not use
KMS Sign. `rgb-mint-burn` generation, cloning and signing remain unchanged.

Only a confirmed missing S3 object with no expected identity pin permits
`GenerateDataKey(NumberOfBytes=64)`. The broker writes with `If-None-Match: *`,
then reads the committed object. Concurrent initializers recover that same
winner. Storage errors, invalid ciphertext and decryption failures never fall
back to a new seed. Swap cloning is replaced by recovery from the saved blob.

The [native adapter](../enclave/kms-tool) uses the official AWS Nitro Enclaves
SDK for TLS, AWS request signing, NSM attestation and recipient decryption.
Credentials pass through private pipes; plaintext seed material stays inside
KMS and the enclave. The durable object is `CiphertextBlob`, not the ephemeral
`CiphertextForRecipient` encrypted to one invocation's recipient key.

## Enclave configuration

Set these public Docker build arguments for `Dockerfile.enclave.rgb` or the
combined `Dockerfile.enclave`; `build/build-enclave.sh` also forwards them:

| Setting | Value |
| --- | --- |
| `SWAP_KMS_KEY_ARN` | Full symmetric `ENCRYPT_DECRYPT` KMS key ARN; no alias. |
| `SWAP_KMS_REGION` | Region matching that key, for example `eu-central-1`. |
| `SWAP_KMS_SEED_ID` | Stable signer ID: 1–128 ASCII letters, digits, `.`, `_`, `-`. |
| `SWAP_KMS_EXPECTED_EVM_ADDRESS` | Empty for first bootstrap; then the verified EVM address, 40 hex digits with optional `0x`. |

Keep the key ARN, seed ID and Bitcoin network unchanged when recovering an
existing identity. A configured address pin rejects a different recovered seed
and makes missing storage fail before generation. There is no creation switch.
Configuration changes affect the image measurement and require updating KMS
permissions. These endpoint settings support the standard AWS commercial partition.

## Parent integration

The [Python broker](../deploy/swap-seed-broker.py) is the only additional host
application. It returns AWS credentials and reads/conditionally creates one S3
object; it never receives the plaintext seed. Use Python 3.10 or newer and the
locked runtime dependencies:

```bash
python3 -m venv .venv-swap-kms
.venv-swap-kms/bin/pip install -r deploy/requirements-swap-kms.txt
export AWS_REGION=eu-central-1
export SWAP_KMS_SEED_ID=swap-mainnet-signer-1
export SWAP_KMS_S3_BUCKET=YOUR_SEED_BUCKET
export SWAP_KMS_S3_KEY=swaps/signer-1/seed.kms
export SWAP_KMS_ALLOWED_CIDS=18
.venv-swap-kms/bin/python deploy/swap-seed-broker.py
```

Use a dedicated EC2 instance role with IMDSv2; boto3 obtains and refreshes its
credentials. Every allowed CID receives that **full role**, so give it only this
signer's KMS/S3 permissions. Comma-separated CIDs may share the same logical
signer; a CID is a routing address, not attested image identity. Run one broker
for this configured object on the parent. The enclave connects directly to
parent CID `3`, vsock port `8004`. TCP mode is for local development/tests only.

In another terminal, or through your existing host supervisor, run AWS's
standard `vsock-proxy` for the same KMS region. Its configuration and invocation
follow the repository's existing egress-proxy pattern:

```bash
export AWS_REGION=eu-central-1
cat > kms-vsock-proxy.yaml <<EOF_KMS
allowlist:
- {address: kms.${AWS_REGION}.amazonaws.com, port: 443}
EOF_KMS
vsock-proxy 8003 "kms.${AWS_REGION}.amazonaws.com" 443 --config kms-vsock-proxy.yaml
```

Permit outbound HTTPS to KMS/S3 and role access to IMDS. KMS TLS terminates in
the enclave; the proxy only forwards bytes. The standard proxy restricts the
destination, not source CIDs; isolation and process supervision belong to the
host deployment. Do not run a second listener on `8003` or `8004`. Swap Helios
uses `8005`/`8006` when enabled. No systemd units or deployment automation are
provided by this feature.

## AWS permissions and persistence

Use a dedicated KMS key and protected S3 bucket. The manually configured
[key usage example](../deploy/swap-kms-key-policy.json) and
[bucket policy example](../deploy/swap-seed-bucket-policy.json) contain
`REPLACE_*` placeholders. Replace all values and merge the key usage statements
into the key's existing administrator policy; the example is not a complete
administrator policy. Apply the bucket example to the dedicated bucket. Keep
the signer role free of unrelated policies, policy-management privileges,
object/version deletion and KMS key deletion permissions.

Set `REPLACE_APPROVED_PCR0` to the actual production EIF's PCR0 from
`nitro-cli describe-eif --eif-path YOUR_IMAGE.eif`; never use a debug image or
zero PCR. The key example permits only recipient-attested requests with this
exact public encryption context (the enclave supplies it automatically):

```json
{"application":"utexo-enclave-signer","flow":"rgb-swap","seed_id":"YOUR_SEED_ID","bitcoin_network":"bitcoin"}
```

Use the actual network: `bitcoin`, `testnet`, `signet`, or `regtest`. The explicit
key denies reject missing/wrong PCRs, changed/missing/extra context and alternate
seed-encryption APIs. The bucket example grants one-object reads and conditional
writes, denies overwrite/deletion, and requires HTTPS. `s3:ListBucket` is needed
so a missing object produces a 404 rather than an ambiguous permission error.
See AWS's [recipient-attestation conditions](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-attestation.html)
and [conditional S3 writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html).

Enable bucket versioning, block public access, and retain an independently
verified backup of the ciphertext and its key/context metadata. Exclude the
object from expiration/replication rules that remove or replace it. S3 does not
make the seed recoverable if the KMS key is deleted. The untrusted parent can
withhold or falsely acknowledge storage, so independently verify the object and
recovery before funding the signer.

## Bootstrap, restart and recovery

1. Build a new signer's EIF without an address pin. Configure the broker, relay,
   key and bucket policies for its actual CID, PCR0 and context.
2. Run the enclave without debug mode and issue
   `utexo-bridge-parent-cli --addr vsock://18:5000 init`. Supply no seed or cloning
   secret. Verify the public identity/attestation and independently back up the
   saved S3 ciphertext. This does not import a legacy ephemeral seed.
3. Rebuild with the verified `SWAP_KMS_EXPECTED_EVM_ADDRESS`. Update the key's
   approved PCR0 for the pinned image, start it, and verify identical keys after
   initialization and restart. During a rollout, approved PCR0 may be a list in
   both the allow and deny conditions; retire the bootstrap measurement afterward.
4. Before funding, remove `kms:GenerateDataKey` from the key's allow statement
   and add an unconditional deny for that action for the signer role. Keep
   `kms:Decrypt` for the pinned image. Test restore on a fresh parent. Subsequent
   upgrades authorize the new measured image for decryption of the same seed.

A timeout leaves initialization inactive; a conditional PUT may still complete.
Retry after service recovery to load the committed winner. Broker calls are
bounded and per-CID quotas/rate limits reject excess work. Never delete the blob,
change its seed ID/key, or remove the address pin to fix a funded signer.
Recover the original ciphertext/version from backup, using an administrator and
a protected recovery object if necessary. If a never-funded bootstrap was
poisoned, quarantine it and provision a new signer namespace; do not reuse any
identity from that failed attempt. Shared ciphertext preserves keys but does
not coordinate replicas or authorize concurrent application-level signing.

Before production use, test real AWS recipient-attestation denials,
conditional-write races and restart/backup
recovery on Nitro hardware; local builds do not prove those service boundaries.
