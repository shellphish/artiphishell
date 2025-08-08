#!/usr/bin/env python3

import os
import argparse
import sys
import subprocess

os.chdir(os.path.dirname(os.path.realpath(__file__))+ '/..')

os.system('rm -rf ~/.cache/act/shellphish-support-syndicate-ci-crs-actions\\@v2.0.0')
os.system('rm -rf ~/.cache/act/shellphish-support-syndicate-ci-crs-actions\\@v1.0.0')

def make_dirs(path):
    try:
        os.makedirs(path, exist_ok=True)
    except Exception as e:
        print('Error creating directory:', e)

def test_accessing_data_repo(token):
    # see if we can access the data repo
    url = f'https://git:{token}@github.com/shellphish-support-syndicate/artiphishell-tests-data.git'
    cmd = ['git','ls-remote', url]

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print('Error accessing data repo:', e)
        return False
    return True

def get_github_token():
    # check in ~/.config/artiphishell/github_token
    token_file = os.path.expanduser('~/.config/artiphishell/github_token')
    try:
        if os.path.exists(token_file):
            with open(token_file, 'r') as f:
                token = f.read().strip()

            if test_accessing_data_repo(token):
                return token

    except Exception as e:
        print('Error reading token file:', e)
    
    # Ask the user for the token
    print('Please enter your GitHub Personal Access Token to access Artiphishell repos during tests:')
    print('You can generate one here, it needs to be able to read repos and packages: https://github.com/settings/tokens/new?scopes=repo,read:packages&description=Artiphishell+Local+CI+access')
    token = input('GITHUB_TOKEN < ').strip()

    make_dirs(os.path.dirname(token_file))
    with open(token_file, 'w') as f:
        f.write(token)

    if not test_accessing_data_repo(token):
        raise Exception('Could not access data repo with the provided token')
    
    return token

def get_openai_key():
    # check in ~/.config/artiphishell/openai_key
    key_file = os.path.expanduser('~/.config/artiphishell/openai_key')
    try:
        if os.path.exists(key_file):
            with open(key_file, 'r') as f:
                key = f.read().strip()
            return key

    except Exception as e:
        print('Error reading key file:', e)
    
    # Ask the user for the key
    print('Please enter your OpenAI API Key to access OpenAI GPT-3 during tests:')
    key = input('OPENAI_API_KEY < ').strip()

    make_dirs(os.path.dirname(key_file))
    with open(key_file, 'w') as f:
        f.write(key)
    
    return key

def run_test_workflow(args):
    git_token = get_github_token()
    openai_key = get_openai_key()

    # Confirm that act is installed
    try:
        subprocess.run(['act', '--version'], check=True)
    except Exception as e:
        print('Error running act:', e)
        print('Please try installing https://github.com/nektos/act/releases/tag/v0.2.65')
        exit(1)
    
    cmd = [
        'act',
        '-s', f'GITHUB_TOKEN={git_token}',
        '-s', f'CI_DEPLOY_TOKEN={git_token}',
        '-s', f'OPENAI_KEY={openai_key}',
        '-a', 'local/act',
        '-v',
        '-P', 'self-hosted=ghcr.io/shellphish-support-syndicate/github-runner-env-small:latest',
        '--bind',
        '--detect-event',
        '--input', f'component={args.component}',
        '--input', f'runner=self-hosted',
    ]
    if args.test is not None and args.test != 'all':
        cmd += [
            '--job', 'run-internal-tests',
            '--matrix', f'target-test:{args.test}',
            '-W', '.github/workflows/generic-component-test.yaml'
        ]
    else:
        cmd += [
            '-W', '.github/workflows/generic-component-test.yaml'
        ]
    print('+',' '.join(cmd))

    os.execvp(cmd[0], cmd)

def main():
    parser = argparse.ArgumentParser(description='Run a test component')
    parser.add_argument('component', type=str, help='The component to test')
    parser.add_argument('test', type=str, help='The test to run', default='all', nargs='?')
    args = parser.parse_args()

    run_test_workflow(args)


if __name__ == '__main__':
    main()