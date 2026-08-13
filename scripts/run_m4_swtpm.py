"""Cross-platform helper for the 15 isolated swtpm client pairs."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


CLIENT_IDS = [f"client{index:02d}" for index in range(1, 16)]
TPM_IDS = [f"tpm{index:02d}" for index in range(1, 16)]


def run(command: list[str], *, root: Path) -> None:
    print(" ".join(command), flush=True)
    subprocess.run(command, cwd=root, check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("provision", "quote", "stop"))
    parser.add_argument("--compose", type=Path, default=Path("compose.m4.yaml"))
    arguments = parser.parse_args()
    root = arguments.compose.resolve().parent
    compose = ["docker", "compose", "-f", str(arguments.compose.resolve())]

    if arguments.action == "stop":
        run([*compose, "down"], root=root)
        return 0

    for client_id in CLIENT_IDS:
        (root / "artifacts" / "m4-nodes" / client_id).mkdir(parents=True, exist_ok=True)
    (root / "artifacts" / "m4-trust").mkdir(parents=True, exist_ok=True)
    # run([*compose, "up", "-d", "--build", *TPM_IDS], root=root)
    if arguments.action == "provision":
        run([*compose, "up", "-d", "--build", *TPM_IDS], root=root)
    else:
        run([*compose, "up", "-d", *TPM_IDS], root=root)

    for index, client_id in enumerate(CLIENT_IDS, start=1):
        if arguments.action == "provision":
            run(
                [*compose, "--profile", "provision", "run", "--rm", client_id],
                root=root,
            )
        else:
            run(
                [
                    *compose,
                    "--profile",
                    "provision",
                    "run",
                    "--rm",
                    client_id,
                    "m4-tpm-quote",
                    "--workspace",
                    "/runtime",
                    "--tcti",
                    "swtpm:path=/run/swtpm/swtpm.sock",
                ],
                root=root,
            )
        print(f"[{index:02d}/15] {client_id} {arguments.action} completed", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
