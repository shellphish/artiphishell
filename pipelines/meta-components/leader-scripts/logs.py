#!/usr/bin/env python3

from typing import cast
import traceback
import asyncio
import sys
import subprocess

import uvloop
import pydatatask.staging

uvloop.install()

async def main():
    pipeline = pydatatask.staging.get_current_directory_pipeline()
    seen = set()
    async with pipeline:
        while True:
            subprocess.run("find /crs_scratch/submission -type f | xargs tail -v -n+1 2>/dev/null", shell=True, check=False)
            for taskname, task in pipeline.tasks.items():
                if 'done' not in task.links:
                    continue
                async for job in task.links['done'].repo:
                    if (taskname, job) in seen:
                        continue
                    seen.add((taskname, job))
                    try:
                        data = await cast(pydatatask.MetadataRepository, task.links['done'].repo).info(job)
                        addend = '' if data['success'] else ' FAILED'
                        try:
                            if 'logs' in task.links:
                                logs = await cast(pydatatask.BlobRepository, task.links['logs'].repo).blobinfo(job)
                            elif 'stdout' in task.links:
                                logs = await cast(pydatatask.BlobRepository, task.links['stdout'].repo).blobinfo(job)
                            else:
                                logs = b''
                        except:
                            logs = b'<error retrieving logs>'
                        if logs:
                            sys.stdout.buffer.write(f"::group::{taskname} {job}{addend}\n".encode())
                            sys.stdout.buffer.write(logs)
                            sys.stdout.buffer.write(b"\n::endgroup::\n")
                            sys.stdout.buffer.flush()
                        else:
                            print(f'{taskname}{addend}')
                    except:
                        traceback.print_exc()

            await asyncio.sleep(3)

if __name__ == '__main__':
    asyncio.run(main())
