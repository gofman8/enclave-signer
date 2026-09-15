#!/usr/bin/env python3
"""Offline checks for test-only KMS/S3 policies and operator role."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from policy_fixtures import HERE, fixture_policies

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--node", default=shutil.which("node"))
parser.add_argument("--output", type=Path, default=ROOT / ".artifacts/kms-e2e/policy-checks.json")
args = parser.parse_args()
if not args.node:
    parser.error("Node.js is required")
account = "123456789012"
key_arn = f"arn:aws:kms:eu-west-1:{account}:key/dae39a52-e6c4-4ec9-87db-cccf8d7a0912"
bucket_arn = "arn:aws:s3:::local-rgb-swap-seeds"
object_arn = bucket_arn + "/swap/seed.kms"
bootstrap, restore = "aa" * 48, "bb" * 48
substitutions = {"REPLACE_ACCOUNT_ID": account, "REPLACE_SIGNER_ROLE": "local-e2e-signer",
    "REPLACE_KMS_KEY_ARN": key_arn, "REPLACE_SEED_ID": "local-rgb-swap",
    "REPLACE_BITCOIN_NETWORK": "regtest", "REPLACE_SEED_BUCKET": "local-rgb-swap-seeds",
    "REPLACE_SEED_OBJECT_KEY": "swap/seed.kms"}
broad = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
process = subprocess.Popen([args.node, str(ROOT / "testing/kms/policy-simulator.mjs")],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
results = []

def check(name, allowed, action, resource, context, policy, identities, principal):
    simulation = {"request": {"principal": principal, "action": action,
        "resource": {"resource": resource, "accountId": account}, "contextVariables": context},
        "identityPolicies": [{"name": f"fixture-{i}", "policy": p} for i, p in enumerate(identities)],
        "resourcePolicy": policy, "serviceControlPolicies": [], "resourceControlPolicies": []}
    process.stdin.write(json.dumps(simulation) + "\n")
    process.stdin.flush()
    verdict = json.loads(process.stdout.readline())
    results.append({"name": name, "expected_allowed": allowed,
        "passed": verdict.get("resultType") != "error" and (verdict.get("result") == "Allowed") == allowed,
        "verdict": verdict})

try:
    for phase in ("bootstrap", "transition", "restore"):
        key, bucket, role = fixture_policies(substitutions, bootstrap, restore, phase)
        values = {"application": "utexo-enclave-signer", "flow": "rgb-swap",
                  "seed_id": "local-rgb-swap", "bitcoin_network": "regtest"}
        context = {"kms:RecipientAttestation:PCR0": bootstrap,
            "kms:EncryptionContextKeys": list(values),
            **{"kms:EncryptionContext:" + k: v for k, v in values.items()}}
        approved = {"bootstrap": [bootstrap], "transition": [bootstrap, restore], "restore": [restore]}[phase]
        for principal in (f"arn:aws:iam::{account}:role/local-e2e-signer", f"arn:aws:sts::{account}:assumed-role/local-e2e-signer/session"):
            def c(name, allowed, action, resource, ctx, policy=key, identities=None):
                check(phase + " " + principal + " " + name, allowed, action, resource, ctx, policy,
                      [role] if identities is None else identities, principal)
            for pcr in (bootstrap, restore, "cc" * 48, "0" * 96, None):
                ctx = {k: v for k, v in context.items() if k != "kms:RecipientAttestation:PCR0"}
                if pcr is not None: ctx["kms:RecipientAttestation:PCR0"] = pcr
                for action in ("kms:GenerateDataKey", "kms:Decrypt"):
                    allowed = pcr in approved and (action == "kms:Decrypt" or phase != "restore" and pcr == bootstrap)
                    c(f"PCR {pcr} {action}", allowed, action, key_arn, ctx, identities=[broad])
            ctx = dict(context, **{"kms:RecipientAttestation:PCR0": approved[0]})
            for field in values:
                for missing in (False, True):
                    bad = dict(ctx)
                    name = "kms:EncryptionContext:" + field
                    if missing: bad.pop(name)
                    else: bad[name] = "wrong-value"
                    c(f"context {field} missing={missing}", False, "kms:Decrypt", key_arn, bad, identities=[broad])
            c("extra context", False, "kms:Decrypt", key_arn, dict(ctx, **{"kms:EncryptionContextKeys": [*values, "extra"]}), identities=[broad])
            for action in ("kms:Encrypt", "kms:ReEncryptFrom", "kms:GenerateDataKeyWithoutPlaintext", "kms:CreateGrant", "kms:PutKeyPolicy", "kms:ScheduleKeyDeletion"):
                c(action, False, action, key_arn, ctx, identities=[broad])
            c("other KMS key has no attached fixture policy", False, "kms:Decrypt", key_arn + "-other", ctx,
              {"Version": "2012-10-17", "Statement": []})
            secure = {"aws:SecureTransport": "true"}
            for name, allowed, action, resource, s3ctx, identities in (
                ("read seed", True, "s3:GetObject", object_arn, secure, [role]),
                ("create only", True, "s3:PutObject", object_arn, dict(secure, **{"s3:if-none-match": "*"}), [role]),
                ("list for missing", True, "s3:ListBucket", bucket_arn, secure, [role]),
                ("overwrite", False, "s3:PutObject", object_arn, secure, [broad]),
                ("delete", False, "s3:DeleteObject", object_arn, secure, [broad]),
                ("delete version", False, "s3:DeleteObjectVersion", object_arn, secure, [broad]),
                ("HTTP", False, "s3:GetObject", object_arn, {"aws:SecureTransport": "false"}, [broad]),
                ("other object", False, "s3:GetObject", object_arn + "-other", secure, [role]),
                ("role lacks bucket admin", False, "s3:PutBucketVersioning", bucket_arn, secure, [role]),
                ("broad grants are outside minimal policy scope", True, "s3:PutBucketVersioning", bucket_arn, secure, [broad])):
                c(name, allowed, action, resource, s3ctx, bucket, identities)
finally:
    process.stdin.close()
    process.wait(timeout=30)
report = {"scope": "Offline IAM simulation of test-only KMS/S3 usage examples, with test-only exact-scope identity and explicit manual bootstrap/restore policy edits; no AWS calls or deployment approval gate",
    "count": len(results), "passed": sum(r["passed"] for r in results),
    "policy_sha256": {n: hashlib.sha256((HERE / "policies" / n).read_bytes()).hexdigest() for n in ("swap-kms-key-policy.json", "swap-seed-bucket-policy.json")},
    "removed_framework_coverage": ["EIF approval validator", "systemd relay guard", "account-wide signer permissions boundary", "broad-grant bucket administration denials"], "cases": results}
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({k: v for k, v in report.items() if k != "cases"}))
for result in results:
    if not result["passed"]: print(json.dumps(result))
raise SystemExit(0 if results and all(r["passed"] for r in results) else 1)
