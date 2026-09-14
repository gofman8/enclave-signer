"""The local E2E must refuse a stale or differently patched SDK export."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from sdk_helper import verify_sdk_provenance


class SdkProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.prefix = Path(self.temp.name) / "prefix"
        self.installed = self.prefix / "share/swap-kms"
        (self.root / "build/patches").mkdir(parents=True)
        (self.installed / "patches").mkdir(parents=True)
        manifest = "aws-nitro-enclaves-sdk-c v0.4.5 " + "a" * 40 + " https://example.invalid\n"
        (self.root / "build/swap-kms-dependencies.tsv").write_text(manifest)
        (self.installed / "dependencies.tsv").write_text(manifest)
        patch = b"reviewed patch\n"
        (self.root / "build/patches/nitro-sdk-cleanup.patch").write_bytes(patch)
        (self.installed / "patches/nitro-sdk-cleanup.patch").write_bytes(patch)
        self.provenance = {"upstream_commit": "a" * 40,
            "patch_sha256": hashlib.sha256(patch).hexdigest(),
            "effective_rest_c_sha256": "b" * 64}
        self.write_provenance()

    def write_provenance(self):
        (self.installed / "sdk-source.json").write_text(json.dumps(self.provenance))

    def test_matching_export_is_reported(self):
        self.assertEqual(verify_sdk_provenance(self.root, self.prefix), self.provenance)

    def test_dependency_mismatch_is_rejected(self):
        (self.installed / "dependencies.tsv").write_text("old dependency stack\n")
        with self.assertRaisesRegex(RuntimeError, "dependency manifest"):
            verify_sdk_provenance(self.root, self.prefix)

    def test_patch_mismatch_is_rejected(self):
        (self.installed / "patches/nitro-sdk-cleanup.patch").write_text("older patch\n")
        with self.assertRaisesRegex(RuntimeError, "cleanup patch"):
            verify_sdk_provenance(self.root, self.prefix)

    def test_stale_or_invalid_provenance_is_rejected(self):
        for field, value in (("upstream_commit", "c" * 40),
                ("patch_sha256", "d" * 64), ("effective_rest_c_sha256", "unknown")):
            with self.subTest(field=field):
                original = self.provenance[field]
                self.provenance[field] = value
                self.write_provenance()
                with self.assertRaises(RuntimeError):
                    verify_sdk_provenance(self.root, self.prefix)
                self.provenance[field] = original

    def test_unpatched_export_is_rejected(self):
        (self.installed / "sdk-source.json").unlink()
        with self.assertRaises(FileNotFoundError):
            verify_sdk_provenance(self.root, self.prefix)


if __name__ == "__main__":
    unittest.main()
