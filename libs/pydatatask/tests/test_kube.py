import asyncio
import base64
import os
import random
import shutil
import string
import unittest
import warnings

import kubernetes_asyncio

from pydatatask.executor.pod_manager import PodManager, kube_connect
from pydatatask.host import Host, HostOS
from pydatatask.task import LinkKind
import pydatatask


def rid(n=6):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


class TestKube(unittest.IsolatedAsyncioTestCase):
    def __init__(self, method):
        super().__init__(method)

        self.minikube_profile = None
        self.minikube_path = shutil.which("minikube")
        self.kube_context = os.getenv("PYDATATASK_TEST_KUBE_CONTEXT")
        self.kube_namespace = os.getenv("PYDATATASK_TEST_KUBE_NAMESPACE", "default")
        self.test_id = rid()
        self.kube_host = Host("kube", HostOS.Linux)

    async def asyncSetUp(self):
        if self.kube_context is None:
            if self.minikube_path is None:
                raise unittest.SkipTest("No kube context specified and minikube is not installed")
            self.minikube_profile = f"pydatatask-test-{self.test_id}"
            p = await asyncio.create_subprocess_exec(
                self.minikube_path,
                "start",
                "--profile",
                self.minikube_profile,
                "--interactive=false",
                "--keep-context",
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await p.communicate()
            code = await p.wait()
            if code != 0:
                raise unittest.SkipTest(
                    f"No kube context specified and minikube failed to start. Logs below:\n\n{stdout.decode()}"
                )
            self.kube_context = self.minikube_profile

    async def test_kube(self):
        session = pydatatask.Session()
        kube = session.ephemeral(kube_connect(context=self.kube_context))

        cluster_quota = pydatatask.Quota.parse("1", "1Gi")

        podman = pydatatask.PodManager(
            cluster_quota,
            self.kube_host,
            f"test-{self.test_id}",
            self.kube_namespace,
            kube,
        )

        repo0 = pydatatask.InProcessMetadataRepository({str(i): f"weh-{i}" for i in range(50)})
        repoDone = pydatatask.InProcessMetadataRepository()
        repoLogs = pydatatask.InProcessBlobRepository()

        task = pydatatask.KubeTask(
            "task",
            podman,
            r"""
            apiVersion: v1
            kind: Pod
            spec:
              containers:
              - name: container
                image: busybox
                command:
                - "sh"
                - "-c"
                - |-
                    echo 'Hello world!'
                    echo "The message of the day is $(echo -n {{ repo0 }} | base64). That's great!"
                    echo 'Goodbye world!'
                    # lol {{ repo0 }}
                resources:                  
                  requests:                    
                    cpu: 10m
                    memory: 100Mi
            """,
            logs=repoLogs,
            done=repoDone,
        )
        task.link("repo0", repo0, LinkKind.InputMetadata)

        pipeline = pydatatask.Pipeline([task], session)

        async with pipeline:
            if self.minikube_profile is not None:
                # wait for boot I guess
                for _ in range(200):
                    if (await kube().v1.list_namespaced_service_account(self.kube_namespace)).items:
                        break
                    await asyncio.sleep(0.1)
                else:
                    raise Exception("Minikube failed to give us anything interesting within 20 seconds")

            await pipeline.update()
            live = task.links["live"].repo
            launched = [x async for x in live]
            assert launched
            assert await live.contains(launched[0])
            await pydatatask.delete_data(pipeline, "task", False, [launched[0]])
            while await live.contains(launched[0]):
                await asyncio.sleep(1)

            task.warned = False
            await task.launch(launched[0], 0)
            await asyncio.sleep(5)
            assert await live.contains(launched[0])

            await pydatatask.run(pipeline, forever=False, launch_once=False, timeout=120)
            assert not await live.contains(launched[0])

        assert len(repo0.data) == 50
        for job, weh in repo0.data.items():
            assert "node" in repoDone.data[job]
            async with await repoLogs.open(job, "r") as fp:
                logs = await fp.read()
            assert (
                logs
                == f"""\
Hello world!
The message of the day is {base64.b64encode(weh.encode()).decode()}. That's great!
Goodbye world!
"""
            )

    async def asyncTearDown(self):
        if self.minikube_profile is not None and self.minikube_path is not None:
            p = await asyncio.create_subprocess_exec(
                self.minikube_path,
                "delete",
                "--profile",
                self.minikube_profile,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await p.communicate()
            code = await p.wait()
            if code != 0:
                warnings.warn(f"minikube failed to delete {self.minikube_profile}. Logs below:\n\n{stdout.decode()}")


if __name__ == "__main__":
    unittest.main()
