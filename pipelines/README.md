# PIPELINE HEALTH

[![Pipeline Build](https://github.com/shellphish-support-syndicate/pipelines/actions/workflows/on_push_build_pipeline.yml/badge.svg)](https://github.com/shellphish-support-syndicate/pipelines/actions/workflows/on_push_build_pipeline.yml)

| Pipeline Run | Artifacts |
| ------------ | --------- |
| | |
| [![Full Pipeline Run (Linux)](https://github.com/shellphish-support-syndicate/pipelines/actions/workflows/pipeline_linux.yml/badge.svg)](https://github.com/shellphish-support-syndicate/pipelines/actions/workflows/pipeline_linux.yml) | [shellphish-support-syndicate/CI-results/tree/main/linux/finished](https://github.com/shellphish-support-syndicate/CI-results/tree/main/linux/finished) |
| [![Weekly Pipeline Run (Jenkins)](https://github.com/shellphish-support-syndicate/pipelines/actions/workflows/pipeline_jenkins.yml/badge.svg)](https://github.com/shellphish-support-syndicate/pipelines/actions/workflows/pipeline_jenkins.yml) | [shellphish-support-syndicate/CI-results/tree/main/jenkins/finished](https://github.com/shellphish-support-syndicate/CI-results/tree/main/jenkins/finished) |

Hello, and welcome to the pipeline control repository. Please have a seat.

In order to clone the submodules, you will need to first create a PAT in your GitHub user settings.  
Then let git know you want to use a credential store: `git config --global credential.helper store`.  
Finally, add the PAT to your credentials.
```bash
echo 'https://git:<PAT>@github.com/' >> ~/.git-credentials
```

If you're looking to resolve the red lines in git status on submodules you didn't touch, please run `git submodule update --init --recursive`. Pay attention to errors!

If you're looking to update everything to the latest version (i.e. perform the operation that CI does), please run `git submodule update --remote`.
You probably don't want `--recursive`, as this will cause upgrades for submodules of submodules, which means that things are not guaranteed to work.

If you're looking to run the entire pipeline from first principles, please go to the sandbox repository, which submodules this repository.
If you're looking to test your component in isolation, please run `pdl` and `pd` directly.

If you're looking to update the docker-compose.yaml in the aixcc-sc-crs-sandbox repository, please use `generate_docker_compose.sh`.
