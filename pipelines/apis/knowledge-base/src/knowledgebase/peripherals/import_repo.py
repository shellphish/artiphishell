import tqdm
from .. import settings
from ..models import git_repo

from git import Repo, Commit, Diff


def import_commits(repo: Repo):
    print('Importing commits...')

    all_commit_hashes = set(c.sha for c in git_repo.Commit.nodes)

    new_commits = [c for c in repo.iter_commits() if c.hexsha not in all_commit_hashes]

    commit_iter = tqdm.tqdm(list(new_commits), smoothing=0)
    for commit in commit_iter:
        commit_iter.set_description_str(f'{commit.hexsha[:10]}...')
        commit = git_repo.Commit.from_git_commit(commit)
        commit.save()


def import_tags(repo: Repo):
    print('Importing tags...')

    for tag in tqdm.tqdm(list(repo.tags)):
        tag = git_repo.Tag.from_ref(repo, tag)
        tag.save()

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Import a git repo into Neo4j')
    parser.add_argument('repo_path', help='Path to the git repo to import')
    parser.add_argument('to_import', help='What to import: commits, tags, or all', choices=['commits', 'tags', 'all'], default='all')
    args = parser.parse_args()

    repo = Repo(args.repo_path)
    print('Importing repo: %s' % repo)

    if args.to_import == 'commits' or args.to_import == 'all':
        import_commits(repo)
    elif args.to_import == 'tags' or args.to_import == 'all':
        import_tags(repo)
    else:
        raise Exception('Unknown import type: %s' % args.to_import)
