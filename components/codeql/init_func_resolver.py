import requests
import os

project_id = os.environ.get("PROJ_ID")
cp_name = os.environ.get("CP_NAME")
base_url = os.environ.get("FUNC_RESOLVER_URL")
if os.getenv('CRS_TASK_NUM'):
    base_url = base_url.replace('TASKNUM', os.getenv('CRS_TASK_NUM'))
else:
    if 'TASKNUM' in base_url:
        raise ValueError("Env CRS_TASK_NUM is not set but FUNC_RESOLVER_URL contains TASKNUM")

res = requests.post(
    f"{base_url}/init_server",
    data={"project_id": project_id, "cp_name": cp_name},
    files={"data": open("/tmp/func_resolver/data.tar", "rb")},
)

print(">>> Init server status", res.status_code)
print(">>> Init server response:", res.text)
