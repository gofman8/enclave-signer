"""Build and invoke the real Linux AWS SDK helper from native E2E signers.

Only the test executable links the endpoint/CA wrappers and loads mock libnsm.
The production helper source and pinned SDK libraries are compiled unchanged.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid


def verify_sdk_provenance(root, prefix):
    """Refuse stale exported libraries before building the test helper."""
    installed = prefix / "share/swap-kms"
    manifest = (root / "build/swap-kms-dependencies.tsv").read_bytes()
    if (installed / "dependencies.tsv").read_bytes() != manifest:
        raise RuntimeError("SDK prefix dependency manifest differs from this checkout")
    sdk_commit = next(fields[2] for line in manifest.decode().splitlines()
        if (fields := line.split()) and fields[0] == "aws-nitro-enclaves-sdk-c")
    patch = (root / "build/patches/nitro-sdk-cleanup.patch").read_bytes()
    if (installed / "patches/nitro-sdk-cleanup.patch").read_bytes() != patch:
        raise RuntimeError("SDK prefix cleanup patch differs from this checkout")
    provenance = json.loads((installed / "sdk-source.json").read_text())
    if provenance.get("upstream_commit") != sdk_commit or provenance.get(
            "patch_sha256") != hashlib.sha256(patch).hexdigest():
        raise RuntimeError("SDK prefix source provenance differs from this checkout")
    source_hash = provenance.get("effective_rest_c_sha256", "")
    if len(source_hash) != 64 or any(c not in "0123456789abcdef" for c in source_hash):
        raise RuntimeError("SDK prefix has no valid effective REST source hash")
    return provenance


class SdkHelper:
    def __init__(self, root, artifacts, args, env):
        self.root, self.artifacts, self.args, self.env = root, artifacts, args, env
        docker = shutil.which("docker")
        if docker is None:
            raise RuntimeError("Docker is required for the official Linux Nitro SDK helper")
        self.docker = str(Path(docker).resolve())
        # Resolve the selected local context once. The enclave intentionally
        # clears its environment; the wrapper receives no user AWS credentials.
        self.host = subprocess.check_output([self.docker, "context", "inspect",
            "--format", "{{.Endpoints.docker.Host}}"], env=env, text=True).strip()
        self.config = artifacts / "docker-config"
        self.config.mkdir(exist_ok=True)
        self.command = [self.docker, "--host", self.host, "--config", str(self.config)]
        self.name = "swap-kms-sdk-e2e-" + uuid.uuid4().hex[:12]
        self.running = False
        self.image_id = None
        self.source_provenance = None
        self.wrapper = artifacts / "sdk-helper-wrapper.py"

    def run(self, command, **kwargs):
        return subprocess.run([*self.command, *command], env=self.env, check=True, **kwargs)

    def start(self):
        prefix = self.args.sdk_prefix.resolve()
        if not (prefix / "lib/libnsm.so").is_file() or not (
                prefix / "include/aws/nitro_enclaves/internal/cms.h").is_file():
            raise RuntimeError("Build the pinned SDK dependencies first; see testing/kms/README.md")
        self.source_provenance = verify_sdk_provenance(self.root, prefix)
        self.image_id = subprocess.check_output([*self.command, "image", "inspect",
            "--format", "{{.Id}}", self.args.sdk_image], env=self.env, text=True).strip()
        command = ["run", "--detach", "--rm", "--name", self.name,
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "256",
            "--mount", f"type=bind,source={self.root},target=/src,readonly",
            "--mount", f"type=bind,source={prefix},target=/opt/swap-kms,readonly",
            "--mount", f"type=bind,source={self.artifacts},target=/test-artifacts"]
        if sys.platform == "linux":
            # Linux host networking reaches the loopback-only emulator. Desktop
            # Docker/Colima provide their host.docker.internal host gateway.
            command += ["--network", "host", "--add-host", "host.docker.internal:127.0.0.1"]
        command += [self.args.sdk_image, "sleep", "infinity"]
        self.run(command, stdout=subprocess.DEVNULL)
        self.running = True
        build = "/test-artifacts/sdk-helper-build"
        with (self.artifacts / "sdk-helper-build.log").open("w") as log:
            self.run(["exec", self.name, "cmake", "-GNinja", "-S", "/src/testing/kms",
                "-B", build, "-DCMAKE_BUILD_TYPE=Debug", "-DCMAKE_PREFIX_PATH=/opt/swap-kms",
                "-DBUILD_SHARED_LIBS=OFF"],
                stdout=log, stderr=subprocess.STDOUT)
            self.run(["exec", self.name, "cmake", "--build", build, "--parallel", "4"],
                stdout=log, stderr=subprocess.STDOUT)
        # Constants are encoded as Python data, never shell interpolation. The
        # input JSON remains a private pipe to docker exec, never an argument.
        config = {"command": self.command, "name": self.name, "build": build,
            "artifacts": str(self.artifacts)}
        self.wrapper.write_text(f"#!{sys.executable}\n" + '''
import json
import os
from pathlib import Path
CONFIG = json.loads(''' + repr(json.dumps(config)) + ''')
command = CONFIG["command"] + ["exec", "-i", CONFIG["name"], "/usr/bin/env", "-i",
    "LD_LIBRARY_PATH=" + CONFIG["build"] + "/mock:/opt/swap-kms/lib"]
for name in ("SWAP_KMS_E2E_PCR0", "SWAP_KMS_E2E_PORT"):
    if name in os.environ:
        command.append(name + "=" + os.environ[name])
if os.environ.get("SWAP_KMS_E2E_CA_PEM"):
    relative = Path(os.environ["SWAP_KMS_E2E_CA_PEM"]).resolve().relative_to(Path(CONFIG["artifacts"]))
    command.append("SWAP_KMS_E2E_CA_PEM=/test-artifacts/" + str(relative))
command.append(CONFIG["build"] + "/bin/swap-kms-tool")
os.execve(command[0], command, {"PATH": "/usr/bin:/bin"})
''')
        self.wrapper.chmod(0o700)

    def close(self):
        if self.running:
            subprocess.run([*self.command, "rm", "--force", self.name], env=self.env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            self.running = False
