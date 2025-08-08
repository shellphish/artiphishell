#!/usr/bin/env python3

import argparse
import json
import os
import shlex
import shutil
import time
import yaml
import jinja2

def template_ql_directory(out_dir, template_dir, **kwargs):
    # os.walk(directory)

    template_data = {
        'enumerate': enumerate,
        'range': range,
        'len': len,
        'sorted': sorted,
        'zip': zip,
        'json': json,
        'yaml': yaml,
        'shquote': shlex.quote,
        'os': os,
    }
    project_id = str(kwargs['project_id'])
    name = str(kwargs['name'])
    template_data['qlpack_name'] = f'shellphish-support-syndicate/info-extraction-{name}-{project_id}'
    template_data.update(kwargs)

    for root, dirs, files in os.walk(template_dir):
        relative_path = os.path.relpath(root, template_dir)
        out_path = os.path.join(out_dir, relative_path)
        os.makedirs(out_path, exist_ok=True)
        for file in files:
            if not file.endswith('.j2'):
                # just copy the file
                shutil.copy(os.path.join(root, file), out_path)
                continue

            # render the template
            with open(os.path.join(root, file), 'r') as f:
                try:
                    template = jinja2.Template(f.read())
                    rendered = template.render(**template_data)

                    with open(os.path.join(out_path, file[:-3]), 'w') as out:
                        out.write(rendered)
                except Exception as e:
                    print(f"Error rendering {file}: {e}")
                    raise e

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Specialize the info-extraction QL pack')
    parser.add_argument('language', type=str, help='The language of the QL pack')
    parser.add_argument('data_file', type=str, help='The data file, can either be a YAML or json file')
    ARGS = parser.parse_args()

    with open(ARGS.data_file, 'r') as f:
        data = yaml.safe_load(f)

    template_ql_directory("info-extraction-ql-pack/", f"info-extraction-{ARGS.language}-template/", **data)