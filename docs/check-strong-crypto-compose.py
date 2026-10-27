"""Prove the optional profile preserves resolved Compose configuration; start nothing."""

import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="kynotes-profile-check-") as directory:
    fixture = Path(directory) / ".env"
    fixture.write_text(
        "KYNOTES_DNS=192.0.2.53\n"
        "KYNOTES_IP=192.0.2.10\n"
        "BOOTSTRAP_ADMIN_PASS=synthetic-admin-password\n"
        "KYNOTES_BACKUP_DIR=/backups\n"
        "KYNOTES_BLOB_TARGET=sftp://mirror@backup.example:22/kynotes\n"
        "KYNOTES_BLOB_TARGET_SECRET=synthetic-sftp-password\n"
        "KYNOTES_BLOB_TARGET_HOST_KEY=SHA256:synthetic\n"
        "TRUSTED_PROXY_CIDRS=192.0.2.5/32\n"
    )
    env = {key: value for key, value in os.environ.items() if not key.startswith(("COMPOSE_", "KYNOTES_", "BOOTSTRAP_", "TRUSTED_", "KYPOST_", "GODEBUG"))}

    def render(files):
        command = ["docker", "compose", "--project-name", "kynotes-profile-check", "--project-directory", str(root), "--env-file", str(fixture)]
        for file in files:
            command += ["-f", str(root / file)]
        return json.loads(subprocess.check_output(command + ["config", "--format", "json"], env=env))

    overlays = ["docker-compose.build.yml", "docker-compose.lan-dns.yml", "docker-compose.local.yml"]
    chains = [[], *[[overlay] for overlay in overlays], overlays]
    for chain in chains:
        files = ["docker-compose.yml", *chain]
        baseline = render(files)
        configured = render([*files, "docker-compose.strong-crypto.yml"])
        assert "GODEBUG" not in baseline["services"]["kynotes-server"]["environment"], files
        assert configured["services"]["kynotes-server"]["environment"].pop("GODEBUG") == "fips140=on"
        assert configured == baseline, f"The strong profile changed another Compose setting in {files}"
print(f"All {len(chains)} Compose chains keep data, image/build, network, DNS, ports and secrets.")
