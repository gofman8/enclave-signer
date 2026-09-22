"""Exercise the production helper's private IPC boundary through the real SDK.

Use the same Docker wrapper, local credentials and attested emulator as the
process E2E suite. Never include request/response payloads or stderr in failures:
they can contain credentials or the recovered seed.
"""

import base64
import binascii
import json
import subprocess


MESSAGE_LIMIT = 64 * 1024


def run_helper_contract(suite):
    fixture = suite.fixture_reset("helper-contract")
    env = {
        "KMS_E2E_PCR0": fixture["bootstrap_pcr0"],
        "KMS_E2E_CA_PEM": str(suite.certs["ca.pem"]),
        "KMS_E2E_PORT": str(suite.args.kms_port),
    }
    request = {
        "operation": "generate",
        "region": fixture["region"],
        "key_arn": fixture["key_arn"],
        "seed_id": fixture["seed_id"],
        "flow": "rgb-swap",
        "bitcoin_network": "regtest",
        **fixture["credentials"],
    }

    def encode(value):
        return json.dumps(value, separators=(",", ":")).encode("utf-8")

    def invoke(body, label):
        try:
            result = subprocess.run([str(suite.sdk_helper.wrapper)], input=body,
                env=env, capture_output=True, timeout=40, check=False)
        except subprocess.TimeoutExpired:
            raise AssertionError(f"{label}: helper exceeded the IPC deadline") from None
        assert len(result.stdout) <= MESSAGE_LIMIT, f"{label}: helper exceeded the output bound"
        return result

    def response(result, fields, label):
        assert result.returncode == 0, f"{label}: helper exited unsuccessfully"
        try:
            value = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise AssertionError(f"{label}: helper returned invalid JSON") from None
        assert isinstance(value, dict) and set(value) == fields, f"{label}: unexpected response fields"
        assert value["key_arn"] == fixture["key_arn"], f"{label}: response key mismatch"
        return value

    def binary(value, field):
        assert isinstance(value, str), f"{field}: expected a base64 string"
        try:
            return base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error):
            raise AssertionError(f"{field}: invalid base64") from None

    def assert_audit(expected):
        events = suite.audit()
        actual = [(event["service"], event["action"], event["allowed"]) for event in events]
        assert actual == [("kms", action, True) for action in expected], "unexpected helper AWS call count or authorization"

    missing_field = {key: value for key, value in request.items() if key != "access_key_id"}
    invalid = [
        ("malformed JSON", b'{"operation":'),
        ("trailing JSON", encode(request) + b" {}"),
        ("duplicate field", encode(request)[:-1] + b',"region":"eu-west-1"}'),
        ("escaped duplicate field", encode(request)[:-1] + b',"\\u0072egion":"eu-west-1"}'),
        ("embedded NUL", encode({**request, "secret_access_key": "invalid\u0000credential"})),
        ("wrong operation", encode({**request, "operation": "encrypt"})),
        ("missing required field", encode(missing_field)),
        ("missing flow", encode({key: value for key, value in request.items() if key != "flow"})),
        ("empty flow", encode({**request, "flow": ""})),
        ("wrong flow type", encode({**request, "flow": True})),
        ("oversized flow", encode({**request, "flow": "x" * 33})),
        ("invalid flow characters", encode({**request, "flow": "rgb/swap"})),
        ("duplicate flow", encode(request)[:-1] + b',"flow":"rgb-swap"}'),
        ("escaped duplicate flow", encode(request)[:-1] + b',"\\u0066low":"rgb-swap"}'),
        ("unknown field", encode({**request, "unexpected": "value"})),
        ("wrong field type", encode({**request, "session_token": True})),
        ("oversized credential", encode({**request, "session_token": "x" * (16 * 1024 + 1)})),
        ("oversized message", b" " * (MESSAGE_LIMIT + 1)),
        ("generation ciphertext field", encode({**request, "ciphertext": "AA=="})),
        ("missing decrypt ciphertext", encode({**request, "operation": "decrypt"})),
    ]
    with suite.case("official SDK helper IPC: strict bounds, ciphertext-only generation and recovery") as report:
        suite.api("/audit/reset", {})
        for label, body in invalid:
            result = invoke(body, label)
            assert result.returncode != 0, f"{label}: helper accepted invalid input"
            assert result.stdout == b"", f"{label}: helper emitted output for invalid input"
            assert_audit([])

        generated = response(invoke(encode(request), "generate"), {"key_arn", "ciphertext"}, "generate")
        ciphertext = binary(generated["ciphertext"], "ciphertext")
        assert 0 < len(ciphertext) <= 6144, "generate: ciphertext has an invalid length"
        assert_audit(["GenerateDataKey"])

        env["KMS_E2E_PCR0"] = fixture["restore_pcr0"]
        decrypted = response(invoke(encode({**request, "operation": "decrypt",
            "ciphertext": generated["ciphertext"]}), "decrypt"), {"key_arn", "seed"}, "decrypt")
        seed = binary(decrypted["seed"], "seed")
        assert len(seed) == 64, "decrypt: recovered seed has an invalid length"
        assert_audit(["GenerateDataKey", "Decrypt"])
        assert suite.object() is None, "helper IPC unexpectedly changed the seed object"
        # Valid identifiers belong to the calling application. The helper must
        # use the supplied flow, never silently substitute the swap namespace.
        # The unchanged swap-only fixture policy rejects both foreign calls.
        suite.api("/audit/reset", {})
        env["KMS_E2E_PCR0"] = fixture["bootstrap_pcr0"]
        for operation in ("generate", "decrypt"):
            foreign = {**request, "operation": operation, "flow": "rgb-mint-burn"}
            if operation == "decrypt":
                foreign["ciphertext"] = generated["ciphertext"]
            rejected = invoke(encode(foreign), f"foreign flow {operation}")
            assert rejected.returncode != 0, "helper ignored the application's flow"
            assert rejected.stdout == b"", "foreign flow produced key material"
        events = suite.audit()
        assert [(event["action"], event["allowed"]) for event in events] == [
            ("GenerateDataKey", False), ("Decrypt", False)], "foreign flow did not reach the policy boundary"
        report.update(rejected_input_cases=len(invalid), generated_seed_returned=False,
            kms_generate_calls=2, kms_decrypt_calls=2, recovered_seed_bytes=len(seed),
            successful_generate_calls=1, successful_decrypt_calls=1,
            foreign_flow_denials=2, encryption_context_flow="rgb-swap")
