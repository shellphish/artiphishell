from pathlib import Path
import asyncio

from common import acquire, transform
import aiofiles
import uvloop

import pydatatask


@transform(acquire("https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.7.4.tar.xz"), "mkrepo")
def linux_repo_path(in_path: Path, out_path: Path):
    out_path.mkdir()
    (out_path / "67").symlink_to(in_path)


async def main():
    async with aiofiles.open("/dev/null", "wb") as nul:
        repo = pydatatask.TarfileFilesystemRepository(pydatatask.FileRepository(linux_repo_path))
        await repo.get_tarball("67", nul)


if __name__ == "__main__":
    uvloop.install()
    asyncio.run(main())
