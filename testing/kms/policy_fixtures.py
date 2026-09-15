"""Testing-only identities and manual KMS rollout of the test-only policy examples."""
import copy
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def policy_template(path, substitutions):
    raw = Path(path).read_text()
    for old, new in substitutions.items():
        raw = raw.replace(old, new)
    if "REPLACE_" in raw:
        raise ValueError(f"unresolved policy placeholder in {path}")
    return json.loads(raw)


def fixture_policies(substitutions, bootstrap_pcr, restore_pcr, phase="transition"):
    """Model operator-managed bootstrap/restore grants; no approval framework."""
    if phase not in {"bootstrap", "transition", "restore"}:
        raise ValueError("invalid fixture policy phase")
    substitutions = {**substitutions, "REPLACE_APPROVED_PCR0": bootstrap_pcr}
    key = policy_template(HERE / "policies/swap-kms-key-policy.json", substitutions)
    bucket = policy_template(HERE / "policies/swap-seed-bucket-policy.json", substitutions)
    identity = policy_template(HERE / "signer-role-policy.json", substitutions)
    approved = {"bootstrap": [bootstrap_pcr], "transition": [bootstrap_pcr, restore_pcr],
                "restore": [restore_pcr]}[phase]
    for statement in key["Statement"]:
        condition = statement.get("Condition", {})
        for operator in ("StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase"):
            if "kms:RecipientAttestation:PCR0" in condition.get(operator, {}):
                condition[operator]["kms:RecipientAttestation:PCR0"] = approved
    # This is an explicit fixture/operator policy addition, not a guarantee
    # supplied by the test-only usage example. Normal rollout retires
    # generation before funding; transition keeps it on the bootstrap image only.
    allow = next(s for s in key["Statement"] if s["Sid"] == "AllowAttestedSeedOperations")
    if phase != "bootstrap":
        deny = {"Sid": "FixtureRetireGeneration", "Effect": "Deny",
                "Principal": copy.deepcopy(allow["Principal"]),
                "Action": "kms:GenerateDataKey", "Resource": "*"}
        if phase == "transition":
            deny["Condition"] = {"StringNotEqualsIgnoreCase": {
                "kms:RecipientAttestation:PCR0": bootstrap_pcr}}
        else:
            allow["Action"] = ["kms:Decrypt"]
        key["Statement"].append(deny)
    return key, bucket, identity
