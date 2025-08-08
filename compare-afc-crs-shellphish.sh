#!/bin/bash

tempdir=$(mktemp -d)

cd $tempdir
git clone https://github.com/aixcc-finals/afc-crs-shellphish.git afc-crs-shellphish-auto-update
git clone https://github.com/shellphish-support-syndicate/artiphishell.git -b submission/afc artiphishell

diff -r --exclude=.git --exclude=.github afc-crs-shellphish-auto-update/ artiphishell/
