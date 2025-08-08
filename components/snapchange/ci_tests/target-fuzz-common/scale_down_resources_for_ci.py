import yaml

with open('../../pipeline.yaml', 'r', encoding='utf-8') as f:
    data = yaml.safe_load(f)

data['tasks']['snapchange_take_snapshot']['job_quota']['mem'] = '4Gi'
#data['tasks']['snapchange_fuzz']['job_quota']['cpu'] = '2'
#data['tasks']['snapchange_fuzz']['job_quota']['mem'] = '4Gi'

with open('../../pipeline.yaml', 'w', encoding='utf-8') as f:
    yaml.dump(data, f)
