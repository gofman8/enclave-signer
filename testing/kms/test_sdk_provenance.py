"""The local E2E refuses stale or modified SDK source exports."""

import json
from pathlib import Path
import tempfile
import unittest

from sdk_helper import UNMODIFIED_SDK_SOURCE, verify_sdk_provenance


class SdkProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.prefix = Path(self.temp.name) / "prefix"
        self.installed = self.prefix / "share/swap-kms"
        (self.root / "build").mkdir(parents=True)
        self.installed.mkdir(parents=True)
        self.manifest = "aws-nitro-enclaves-sdk-c v0.4.5 " + UNMODIFIED_SDK_SOURCE["upstream_commit"] + " https://example.invalid\n"
        (self.root / "build/swap-kms-dependencies.tsv").write_text(self.manifest)
        (self.installed / "dependencies.tsv").write_text(self.manifest)
        self.provenance = dict(UNMODIFIED_SDK_SOURCE)
        self.write_provenance()

    def write_provenance(self):
        (self.installed / "sdk-source.json").write_text(json.dumps(self.provenance))

    def test_matching_unmodified_export_is_reported(self):
        self.assertEqual(verify_sdk_provenance(self.root, self.prefix), self.provenance)

    def test_dependency_mismatch_is_rejected(self):
        (self.installed / "dependencies.tsv").write_text("old dependency stack\n")
        with self.assertRaisesRegex(RuntimeError, "dependency manifest"):
            verify_sdk_provenance(self.root, self.prefix)

    def test_stale_or_modified_provenance_is_rejected(self):
        for field, value in (("upstream_commit", "c" * 40),
                ("rest_c_sha256", "d" * 64), ("rest_c_sha256", "unknown"),
                ("source_modified", True), ("source_modified", 0)):
            with self.subTest(field=field, value=value):
                self.provenance = {**UNMODIFIED_SDK_SOURCE, field: value}
                self.write_provenance()
                with self.assertRaisesRegex(RuntimeError, "unmodified source"):
                    verify_sdk_provenance(self.root, self.prefix)

    def test_legacy_patch_receipt_is_rejected(self):
        self.provenance = {"upstream_commit": UNMODIFIED_SDK_SOURCE["upstream_commit"],
            "patch_sha256": "a" * 64, "effective_rest_c_sha256": "b" * 64}
        self.write_provenance()
        with self.assertRaisesRegex(RuntimeError, "unmodified source"):
            verify_sdk_provenance(self.root, self.prefix)

    def test_stale_installed_patch_is_rejected(self):
        (self.installed / "patches").mkdir()
        (self.installed / "patches/nitro-sdk-cleanup.patch").write_text("obsolete patch\n")
        with self.assertRaisesRegex(RuntimeError, "stale source patch"):
            verify_sdk_provenance(self.root, self.prefix)

    def test_unreviewed_sdk_upgrade_is_rejected(self):
        manifest = self.manifest.replace(UNMODIFIED_SDK_SOURCE["upstream_commit"], "c" * 40)
        (self.root / "build/swap-kms-dependencies.tsv").write_text(manifest)
        (self.installed / "dependencies.tsv").write_text(manifest)
        self.provenance["upstream_commit"] = "c" * 40
        self.write_provenance()
        with self.assertRaisesRegex(RuntimeError, "unmodified source"):
            verify_sdk_provenance(self.root, self.prefix)

    def test_missing_receipt_is_rejected(self):
        (self.installed / "sdk-source.json").unlink()
        with self.assertRaises(FileNotFoundError):
            verify_sdk_provenance(self.root, self.prefix)


if __name__ == "__main__":
    unittest.main()
