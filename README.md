# shellphish-crs

This is an admin repository! Go away!

anyway!

Use the scripts in the scripts folder to perform various maintainence and integration testing tasks.
Pushes to this repository will trigger pushes to the staging branch of aixcc-sc/asc-crs-shellphish.

# Current Errata:

1. You **NEED** the latest version of yq: https://github.com/mikefarah/yq/releases/tag/v4.44.1
2. You need to add a PAT. From the pipeline repo:
In order to clone the submodules, you will need to first create a PAT in your GitHub user settings.
Then let git know you want to use a credential store: `git config --global credential.helper store`.
Finally, add the PAT to your credentials.

```bash
echo 'https://git:<PAT>@github.com/' >> ~/.git-credentials
git config --global credential.helper store
```

4. `git config --global init.defaultBranch main`
5. `git clone https://github.com/shellphish-support-syndicate/shellphish-crs.git`
6. `git submodule update --init --recursive`
7. `pip install -e pipelines/meta-components/pydatatask/`
8. `cp pipelines/meta-components/aixcc-sc-capi/env.example pipelines/meta-components/aixcc-sc-capi/env`
9. `vim pipelines/meta-components/aixcc-sc-capi/env` and update `GITHUB_USER` and `GITHUB_TOKEN`
10. `cd pipelines/local_run; ./rebuild_local.sh`
11. `./add_target.sh https://github.com/shellphish-support-syndicate/targets-semis-aixcc-sc-challenge-002-jenkins-cp`
12. `./run.sh`
