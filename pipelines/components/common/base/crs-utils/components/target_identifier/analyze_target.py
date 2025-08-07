from collections import defaultdict
import json
import os
import subprocess
import yaml
import logging

from targets import TARGET_IDENTIFIERS

LOG = logging.getLogger("analyze_target")

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def identify_targets(target_dir):
    src_dir = os.path.join(target_dir, 'src')
    known_applications = defaultdict(list)
    by_extension = defaultdict(list)
    for root, dirs, files in os.walk(src_dir):
        for target, identifiers in TARGET_IDENTIFIERS.items():
            for identifier in identifiers:
                if res := identifier(root, dirs, files):
                    known_applications[target].append({
                        'relative_path': os.path.relpath(root, target_dir),
                        'metadata': res
                    })
        if '/.git/' not in root:
            for file in files:
                ext = file.split('.')[-1] if '.' in file[1:] else ''
                by_extension[ext].append(os.path.join(root, file))

    by_language = defaultdict(list)
    for ext, files in by_extension.items():
        if not ext:
            continue
        if ext in ('c', 'h'):
            by_language['c'].extend(files)
        elif ext in ('pem', 'crt', 'key'):
            by_language['certificates'].extend(files)
        elif ext in ('bazel', 'bzl', 'bazelrc'):
            by_language['bazel'].extend(files)
        elif ext in ('am', 'm4'):
            by_language['autotools'].extend(files)
        elif ext in ('bat',):
            by_language['batch'].extend(files)
        elif ext in ('perl', 'pl'):
            by_language['perl'].extend(files)
        elif ext == 'java':
            by_language['java'].extend(files)
        elif ext == 'py':
            by_language['python'].extend(files)
        elif ext in ('sh',):
            by_language['shell'].extend(files)
        elif ext in ('cpp', 'cc', 'cxx', 'hpp'):
            by_language['cpp'].extend(files)
        elif ext in ('go',):
            by_language['go'].extend(files)
        elif ext in ('rb',):
            by_language['ruby'].extend(files)
        elif ext in ('js', 'ts', 'jsx', 'tsx'):
            by_language['javascript'].extend(files)
        elif ext in ('html','xhtml'):
            by_language['html'].extend(files)
        elif ext in ('css',):
            by_language['css'].extend(files)
        elif ext in ('json',):
            by_language['json'].extend(files)
        elif ext in ('yaml', 'yml'):
            by_language['yaml'].extend(files)
        elif ext in ('xml',):
            by_language['xml'].extend(files)
        elif ext in ('md',):
            by_language['markdown'].extend(files)
        elif ext in ('sql',):
            by_language['sql'].extend(files)
        elif ext in ('j2', 'jinja2'):
            by_language['jinja2'].extend(files)
        elif ext in ('jelly',):
            by_language['jelly'].extend(files)
            # print(f"Jelly files: {files}")
        elif ext in ('l', 'y'):
            by_language['lex-yacc'].extend(files)
        elif ext in ('vbs',):
            by_language['vbs'].extend(files)
        elif ext in ('jpg', 'jpeg', 'png', 'gif', 'svg', 'webp'):
            by_language['images'].extend(files)
        elif ext in ('jar', 'war', 'ear'):
            by_language['java-archive'].extend(files)
        elif ext in ('zip', 'tar', 'gz', 'bz2', 'xz', '7z'):
            by_language['archives'].extend(files)
        elif ext in ('pdf', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx'):
            by_language['office'].extend(files)
        elif ext in ('txt', 'log'):
            by_language['text'].extend(files)
        # else:
        #     print(f"Unknown extension: {ext} in {files}")
        #     by_language['unknown_'+ext].extend(files)

    return {
        'known_sources': known_applications,
        'files_by_language': {lang: len(files) for lang, files in sorted(by_language.items(), key=lambda x: len(x[1]))}
    }

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('target_dir', type=str)
    parser.add_argument('output', type=str)
    args = parser.parse_args()

    with open(os.path.join(args.target_dir, 'project.yaml')) as f:
        project = yaml.safe_load(f)

    if 'shellphish' not in project:
        project['shellphish'] = {}
    project['shellphish'].update(identify_targets(args.target_dir))
    with open(args.output, 'w') as f:
        f.write(json.dumps(project, indent=2))
