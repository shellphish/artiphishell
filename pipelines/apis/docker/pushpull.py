#!/usr/bin/env python3

import json
from asyncio.subprocess import create_subprocess_exec, PIPE
from asyncio import gather, Task, create_task, sleep
from aiohttp import web, ClientSession
from aiojobs.aiohttp import setup, spawn
from kubernetes import client, config

REGISTRY = "docker-registry:5000"
MY_PORT = 7677

try:
    config.load_incluster_config()
except:
    OTHER_NODES = []
    SELF_NODES = []
else:
    with open('/var/run/secrets/kubernetes.io/serviceaccount/namespace', 'r', encoding='utf-8') as fp:
        namespace = fp.read().strip()
    with open('/etc/hostname', 'r', encoding='utf-8') as fp:
        pod_name = fp.read().strip()

    v1 = client.CoreV1Api()
    pods = []
    while len(pods) != 3 or any(pod.status.host_ip is None for pod in pods):
        pods = v1.list_namespaced_pod(namespace=namespace, label_selector="shellphish-app=docker-api").items
    OTHER_NODES = [pod.status.host_ip for pod in pods if pod.metadata.name != pod_name]
    SELF_NODES = [pod.status.host_ip for pod in pods if pod.metadata.name == pod_name]

print(f"Starting up with other nodes {OTHER_NODES}")

_session = None
async def on_startup(app):
    global _session
    _session = ClientSession()

    app[docker_poll] = create_task(background_docker_images())

def session() -> ClientSession:
    assert _session is not None
    return _session

KNOWN_PUSHED_IMAGES = set()
KNOWN_PULLED_IMAGES = set()

async def background_docker_images():
    while True:
        await sleep(1)
        async for basename in load_local_docker_images():
            KNOWN_PULLED_IMAGES.add(basename)
            if basename not in KNOWN_PUSHED_IMAGES:
                await background_push(basename)
                KNOWN_PUSHED_IMAGES.add(basename)

async def load_local_docker_images():
    p = await create_subprocess_exec("docker", "images", "--format=json", stdout=PIPE)
    assert p.stdout is not None
    while True:
        line = await p.stdout.readline()
        if not line:
            break
        data = json.loads(line)

        if data["Tag"] == "\u003cnone\u003e":
            continue
        if data['Repository'].startswith(f'{REGISTRY}/'):
            continue
        yield f'{data["Repository"]}:{data["Tag"]}'
    await p.wait()

async def handle_push(request: web.Request):
    basename = str(request.match_info["image"])
    print("Pull request @", basename)
    await spawn(request, background_push(basename))
    return web.Response(text='')

async def background_push(basename: str):
    if not OTHER_NODES:
        return
    p = await create_subprocess_exec("docker", "tag", basename, f"{REGISTRY}/{basename}")
    await p.wait()
    p = await create_subprocess_exec("docker", "push", f"{REGISTRY}/{basename}")
    await p.wait()

    while any(isinstance(x, BaseException) for x in await gather(*(session().get(f"http://{node}:{MY_PORT}/health") for node in OTHER_NODES))):
        await sleep(1)

    await gather(*(session().get(f"http://{node}:{MY_PORT}/pull/{basename}") for node in OTHER_NODES))

async def handle_pull(request: web.Request):
    basename = str(request.match_info["image"])
    if basename not in KNOWN_PULLED_IMAGES:
        print("Pull request @", basename)
        await background_pull(basename)
    else:
        print("Pull request skipped @", basename)
    return web.Response(text='')

async def background_pull(basename: str):
    p = await create_subprocess_exec("docker", "pull", f"{REGISTRY}/{basename}")
    await p.wait()
    p = await create_subprocess_exec("docker", "tag", f"{REGISTRY}/{basename}", basename)
    await p.wait()

async def handle_health(request: web.Request):
    return web.Response(text="OK")

async def handle_nodes(request: web.Request):
    return web.Response(text=json.dumps([{"ip": ip, "self": ip in SELF_NODES} for ip in OTHER_NODES + SELF_NODES]))

async def handle_sync(request: web.Request):
    waiting_for = {x async for x in load_local_docker_images()}
    print("Sync request @", waiting_for)
    while waiting_for - KNOWN_PUSHED_IMAGES:
        print("Still missing", waiting_for - KNOWN_PUSHED_IMAGES)
        await sleep(0.1)
    return web.Response(text="Sync finished\n")

app = web.Application()
setup(app)
app.add_routes([web.get('/push/{image:.*}', handle_push),
                web.get('/pull/{image:.*}', handle_pull),
                web.get('/sync', handle_sync),
                web.get('/nodes', handle_nodes),
                web.get('/health', handle_health)])
app.on_startup.append(on_startup)
docker_poll = web.AppKey("docker_poll", Task[None])

if __name__ == '__main__':
    web.run_app(app, port=MY_PORT, host='0.0.0.0')
