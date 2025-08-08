#!/bin/bash
export TARGET_NAME=$1

pd restore "${TARGET_NAME}_backup" --all
pd rm grammar_guy_fuzz __all__
