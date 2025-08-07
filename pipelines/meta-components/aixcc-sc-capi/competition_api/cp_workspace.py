import asyncio
import contextlib
import os
import shutil
from pathlib import Path
from typing import Any

from git import Repo
from structlog.stdlib import get_logger

from competition_api.cp_registry import CPRegistry
from competition_api.flatfile import Flatfile

LOGGER = get_logger(__name__)


class BadReturnCode(Exception):
    pass


async def run(func, *args, stdin=None, **kwargs):
    await LOGGER.adebug("%s %s %s", func, args, kwargs)
    proc = await asyncio.create_subprocess_exec(
        func,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.PIPE if stdin else None,
        **kwargs,
    )
    stdout, stderr = await proc.communicate(
        input=stdin.encode("utf8") if stdin else None
    )
    return_code = proc.returncode

    # Program outputs may not be decodeable when POV blobs are passed to them
    await LOGGER.adebug("Process stdout: %s", stdout.decode("utf8", errors="ignore"))
    await LOGGER.adebug("Process stderr: %s", stderr.decode("utf8", errors="ignore"))

    return return_code, stdout, stderr


class CPWorkspace(contextlib.AbstractAsyncContextManager):
    def __init__(self, cp_name: str):
        cp = CPRegistry.instance().get(cp_name)
        if cp is None:
            raise ValueError(f"cp_name {cp_name} does not exist")
        self.cp = cp
        self.workdir: Path
        self.project_yaml: dict[str, Any]
        self.repo: Repo
        self.src_repo: Repo | None
        self.run_env: dict[str, str]

    async def __aenter__(self):
        # Make working copies
        self.workdir = self.cp.copy()
        self.project_yaml = self.cp.project_yaml

        self.repo = Repo(self.workdir)
        self.src_repo = None

        self.run_env = {
            "DOCKER_IMAGE_NAME": self.project_yaml["docker_image"],
            "DOCKER_HOST": os.environ.get("DOCKER_HOST", ""),
        }

        internal_dir = self.workdir / ".internal_only"
        if os.path.isdir(internal_dir):
            self.run_env["DOCKER_EXTRA_ARGS"] = f"-v {internal_dir}:/.internal_only"

        await LOGGER.adebug("Workspace: setup")
        await run(
            "docker",
            "login",
            "ghcr.io",
            "-u",
            os.environ.get("GITHUB_USER", ""),
            "--password-stdin",
            stdin=os.environ.get("GITHUB_TOKEN", ""),
        )
        await run("docker", "pull", self.project_yaml["docker_image"])

        return self

    async def __aexit__(self, _exc_type, _exc, _tb):
        shutil.rmtree(self.workdir, ignore_errors=True)

    def set_src_repo(self, ref: str):
        source = self.cp.source_from_ref(ref)

        if source is None:
            self.src_repo = None
            return

        self.src_repo = Repo(self.workdir / "src" / source)

    def sanitizer(self, sanitizer_id: str) -> str | None:
        return self.project_yaml.get("sanitizers", {}).get(sanitizer_id)

    def harness(self, harness_id: str) -> str | None:
        return self.project_yaml.get("harnesses", {}).get(harness_id, {}).get("name")

    def current_commit(self) -> str | None:
        if self.src_repo is None:
            return None
        return self.src_repo.head.commit.hexsha

    def checkout(self, ref: str):
        LOGGER.debug("Workspace: checkout %s", ref)

        if self.src_repo is None:
            raise NotImplementedError

        self.src_repo.git.checkout(ref, force=True)

        LOGGER.debug("Checked out %s", self.current_commit())

    async def build(self, source: str, patch_sha256: str | None = None) -> bool:
        await LOGGER.adebug(
            "Workspace: build" + (f" with patch {patch_sha256}" if patch_sha256 else "")
        )
        with open(self.workdir / ".env.project", "w+", encoding="utf8") as env:
            env.write(
                f'DOCKER_VOL_ARGS="-v {self.workdir}/work:/work '
                f"-v {self.workdir}/src:/src "
                f"-v {self.workdir}/out:/out "
                f'-v {self.workdir}/.internal_only:/.internal_only"\n'
            )

        if patch_sha256 is None:
            return_code, _, _ = await run(
                "./run.sh", "-x", "-v", "build", cwd=self.workdir, env=self.run_env
            )

        else:
            patch = Flatfile(contents_hash=patch_sha256)
            return_code, _, _ = await run(
                "./run.sh",
                "-x",
                "-v",
                "build",
                patch.filename,
                source,
                cwd=self.workdir,
                env=self.run_env,
            )

        return return_code == 0

    async def check_sanitizers(self, blob_sha256: str, harness: str) -> set[str]:
        blob = Flatfile(contents_hash=blob_sha256)
        await LOGGER.adebug(
            "Workspace: check sanitizers on harness %s with blob (hash %s)",
            harness,
            blob.sha256,
        )

        return_code, _, _ = await run(
            "./run.sh",
            "-x",
            "-v",
            "run_pov",
            blob.filename,
            self.harness(harness),
            cwd=self.workdir,
            env=self.run_env,
        )

        if return_code != 0:
            raise BadReturnCode

        output_dir = self.workdir / "out" / "output"

        pov_output_path = [
            p
            for p in sorted(os.listdir(output_dir), reverse=True)
            if p.endswith("run_pov")
        ][0]

        triggered: set[str] = set()
        for file in [
            output_dir / pov_output_path / "stderr.log",
            output_dir / pov_output_path / "stdout.log",
        ]:
            try:
                with open(file, "r", encoding="utf8") as f:
                    for line in f:
                        for key, sanitizer in self.project_yaml["sanitizers"].items():
                            if sanitizer in line:
                                triggered.add(key)
            except FileNotFoundError:
                await LOGGER.awarning("%s not found", file)

        return triggered

    async def run_functional_tests(self) -> bool:
        await LOGGER.adebug("Workspace: run tests")
        return_code, _, _ = await run(
            "./run.sh", "-x", "-v", "run_tests", cwd=self.workdir, env=self.run_env
        )
        return return_code == 0
