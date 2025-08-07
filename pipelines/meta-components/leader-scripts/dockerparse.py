import json, sys, collections

v = json.load(sys.stdin)
result = collections.defaultdict(list)
lblv = [dict(x.split("=", 1) for x in vx["Labels"].split(",") if '=' in x) for vx in v]
for vx, vxlbl in zip(v, lblv):
    if not('owner_task' in vxlbl and 'owner_job' in vxlbl and 'owner_replica' in vxlbl):
        continue
    ident = f"{vxlbl['owner_task']}___{vxlbl['owner_job']}___{vxlbl['owner_replica']}"
    result[ident].append(vx["ID"])
json.dump(dict(result), sys.stdout)
