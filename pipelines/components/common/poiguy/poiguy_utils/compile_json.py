import jsonschema

from schema import json_schema_v2 as json_schema


def compile_json_with_schema(**kwargs):
    json_data = dict(kwargs)
    json_data['crash_id'] = kwargs['crash_report_id']
    json_data['stack_traces'] = kwargs.get('stack_traces', [])
    json_data["additional_information"] = kwargs.get('additional_information', {})
    
    try:
        jsonschema.validate(instance=json_data, schema=json_schema)
        return 0, json_data
    except jsonschema.exceptions.ValidationError as e:
        print("JSON data is invalid.")
        print(f'##### {e.absolute_path}: {e.message} #####')
        json_data['pois'] = []
        json_data['stack_traces'] = []
        return 1, json_data
