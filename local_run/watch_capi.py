#!/usr/bin/env python3

import os
import sys
import json
import subprocess
import base64
import time

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# https://github.com/sharkdp/bat/releases/download/v0.24.0/bat-v0.24.0-x86_64-unknown-linux-gnu.tar.gz
bat_loc = [None]
def get_bat():
    if bat_loc[0]:
        return bat_loc[0]
    try:
        existing_bat = subprocess.check_output(['which', 'bat']).decode().strip()
        if os.path.exists(existing_bat):
            bat_loc[0] = existing_bat
            return bat_loc[0]
    except subprocess.CalledProcessError:
        pass

    out_loc = os.path.join(ROOT_DIR, '.github/bin/bat')
    if os.path.exists(out_loc):
        bat_loc[0] = out_loc
        return bat_loc[0]

    tmp_dir = os.path.join(ROOT_DIR, 'tmp')
    os.makedirs(tmp_dir, exist_ok=True)

    subprocess.check_call(['wget','https://github.com/sharkdp/bat/releases/download/v0.24.0/bat-v0.24.0-x86_64-unknown-linux-gnu.tar.gz', '-O', os.path.join(tmp_dir, 'bat.tar.gz')])
    os.makedirs(os.path.join(tmp_dir, 'bat_extract'), exist_ok=True)
    subprocess.check_call(['tar', '-xzf', os.path.join(tmp_dir, 'bat.tar.gz'), '-C', os.path.join(tmp_dir, 'bat_extract')])
    os.rename(os.path.join(tmp_dir, 'bat_extract/bat-v0.24.0-x86_64-unknown-linux-gnu/bat'), out_loc)
    bat_loc[0] = out_loc
    return bat_loc[0]

gum_loc = [None]
def get_gum():
    if gum_loc[0]:
        return gum_loc[0]
    try:
        existing_gum = subprocess.check_output(['which', 'gum']).decode().strip()
        if os.path.exists(existing_gum):
            gum_loc[0] = existing_gum
            return gum_loc[0]
    except subprocess.CalledProcessError:
        pass

    out_loc = os.path.join(ROOT_DIR, '.github/bin/gum')
    if os.path.exists(out_loc):
        gum_loc[0] = out_loc
        return gum_loc[0]

    tmp_dir = os.path.join(ROOT_DIR, 'tmp')
    os.makedirs(tmp_dir, exist_ok=True)

    subprocess.check_call(['wget','https://github.com/charmbracelet/gum/releases/download/v0.14.5/gum_0.14.5_Linux_x86_64.tar.gz', '-O', os.path.join(tmp_dir, 'gum.tar.gz')])
    os.makedirs(os.path.join(tmp_dir, 'gum_extract'), exist_ok=True)
    subprocess.check_call(['tar', '-xzf', os.path.join(tmp_dir, 'gum.tar.gz'), '-C', os.path.join(tmp_dir, 'gum_extract')])
    os.rename(os.path.join(tmp_dir, 'gum_extract/gum_0.14.5_Linux_x86_64/gum'), out_loc)
    gum_loc[0] = out_loc

    return gum_loc[0]


seen_vds = {}
seen_gp = {}


'''
vds:
{
    "submission": {
        "cp_name": "Mock CP",
        "pou": {
            "commit_sha1": "11DAFA9A5BABC127357D710EE090EB4C0C05154F",
            "sanitizer": "id_1"
        },
        "pov": {
            "harness": "id_1",
            "data": "MMzMzMzMzMzMzMzMzMzMzMzMzMwwMDAxMDAwHDAwMDAwMDApwMAKMDAwKQo=\n"
        }
    },
    "response": {
        "status": "accepted",
        "vd_uuid": "2746113e-7339-4c12-a606-898023c18502",
        "cpv_uuid": "55d3c4c6-c069-4988-ab3e-d9ac76c21eb6"
    },
    "crashing_commit_id": "0e58e5aa47c9d41a4a95384566c3a238"
}

gp:
{
    "submission": {
        "cpv_uuid": "24434374-e74c-4752-9e5d-f075e6b014bc",
        "data": "ZGlmZiAtLWdpdCBhL21vY2tfdnAuYyBiL21vY2tfdnAuYwppbmRleCA1NTlkZjI2Li4xZDNlYTQ4\nIDEwMDY0NAotLS0gYS9tb2NrX3ZwLmMKKysrIGIvbW9ja192cC5jCkBAIC0xNywxNiArMTcsMjMg\nQEAgdm9pZCBmdW5jX2EoKXsKICAgICBpLS07CiB9CiAKKwogdm9pZCBmdW5jX2IoKXsKICAgICBj\naGFyICpidWZmOwogICAgIHByaW50ZigiZG9uZSBhZGRpbmcgaXRlbXNcbiIpOwogICAgIGludCBq\nOwogICAgIHByaW50ZigiZGlzcGxheSBpdGVtICM6Iik7CiAgICAgc2NhbmYoIiVkIiwgJmopOwor\nICAgIGlmIChqIDwgMCB8fCBqID49IDMpIHsKKyAgICAgICAgcHJpbnRmKCJJbnZhbGlkIGl0ZW0g\nbnVtYmVyXG4iKTsKKyAgICAgICAgcmV0dXJuOworICAgIH0KICAgICBidWZmID0gJml0ZW1zW2pd\nWzBdOwogICAgIHByaW50ZigiaXRlbSAlZDogJXNcbiIsIGosIGJ1ZmYpOwogfQogCisKKwogI2lm\nbmRlZiBfX19URVNUX19fCiBpbnQgbWFpbigpCiB7Cg==\n"
    },
    "response": {
        "status": "accepted",
        "gp_uuid": "24434374-e74c-4752-9e5d-f075e6b014bc"
    },
    "crashing_commit_id": "8463327eaef184959b73fc04da103a05"
}
'''


def create_box(*text, border="double", border_color="#00FF00", text_color="#00FF00", bg_color="#FF4136", width=70, align="center", bold=True):
    command = [
        get_gum(),
        "style",
        "--border", border,
        "--border-foreground", border_color,
        "--foreground", text_color,
        "--background", bg_color,
        "--padding", "2 4",
        "--width", str(width),
        "--align", align
    ]
    
    if bold:
        command.append("--bold")
    
    command.extend(text)
    #print(command)

    subprocess.check_call(command)
    
    return command

# Example usage:
# subprocess.check_call(create_box("[ CRITICAL SYSTEM VULNERABILITY DETECTED ]"))


def on_new_vds(target, vds):
    sanitizer_id = vds['submission']['pou'].get('sanitizer', '')
    sanitizer_name = target['sanitizers'].get(sanitizer_id, sanitizer_id)

    link = get_target_source_path(target, vds['submission']['pou']['commit_sha1'])
    create_box(
        "[ ☠️ VULNERABILITY DETECTED ☠️ ]",
        f"{sanitizer_name} detected for commit:",
        f'{link}',
        bg_color="#a7394f"
    )
    print(link)

def on_new_gp(target, gp):
    patch_base64 = gp['submission']['data']
    patch = base64.b64decode(patch_base64).decode()
    tmp_file = f'/tmp/{gp["crashing_commit_id"]}.patch'
    with open(tmp_file, 'w') as f:
        f.write(patch)

    create_box(
        "[ 🩹💉 PATCH GENERATED 🩹💉 ]",
        bg_color='#328563',
        border='rounded',
        border_color='#407aa0',
    )

    subprocess.check_call([
        get_bat(),
        tmp_file,
        '--color', 'always',
        '--paging', 'never',
        '-l', 'diff'
    ])


def check_vds_status(target):
    vds_dir = f'/crs_scratch/submission/vds'
    if not os.path.exists(vds_dir):
        return

    files = os.listdir(vds_dir)
    if len(files) == 0:
        return

    for file in files:
        with open(os.path.join(vds_dir, file), 'r') as f:
            data = json.load(f)

        vds_uuid = data['response']['vd_uuid']
        if vds_uuid in seen_vds:
            continue
        seen_vds[vds_uuid] = data
        on_new_vds(target, data)
    
def check_gp_status(target):
    gp_dir = f'/crs_scratch/submission/gp'
    if not os.path.exists(gp_dir):
        return

    files = os.listdir(gp_dir)
    if len(files) == 0:
        return
    
    for file in files:
        with open(os.path.join(gp_dir, file), 'r') as f:
            data = json.load(f)

        gp_uuid = data['response']['gp_uuid']
        if gp_uuid in seen_gp:
            continue
        seen_gp[gp_uuid] = data
        on_new_gp(target, data)



# {'cp_name': 'Mock CP', 'language': 'c', 'cp_sources': {'samples': {'address': 'git@github.com:shellphish-support-syndicate/aixcc-sc-mock-cp-src.git', 'ref': 'v2.0.1', 'artifacts': ['src/samples/mock_vp']}}, 'docker_image': 'ghcr.io/shellphish-support-syndicate/mock-cp:v3.0.2', 'sanitizers': {'id_1': 'AddressSanitizer: global-buffer-overflow', 'id_2': 'AddressSanitizer: SEGV'}, 'harnesses': {'id_1': {'name': 'filein_harness', 'source': 'src/test/filein_harness.c', 'binary': 'out/filein_harness'}}}
def load_target(target):
    import yaml
    with open(os.path.join(target, 'project.yaml'), 'r') as f:
        return yaml.safe_load(f)

def get_target_source_path(target,sha):
    target_sources = target['cp_sources']
    source = list(target_sources.values())[0]['address']
    source = source.replace('git@github.com:', 'https://github.com/')
    source = source.replace('.git', '')
    return f'{source}/commit/{sha}'

def loop(target):
    while True:
        try:
            check_vds_status(target)
        except Exception as e:
            pass
        try:
            check_gp_status(target)
        except Exception as e:
            pass
        time.sleep(5)

def main(args):
    target = load_target(args.target)
    loop(target)

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('target', type=str, help='Target to watch')
    args = parser.parse_args()
    args.target = os.path.abspath(args.target)

    os.chdir(ROOT_DIR)

    get_gum()
    get_bat()

    main(args)
