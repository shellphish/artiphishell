#!/bin/bash
pd restore ./restore_latest_state --all
pd rm grammar_guy_fuzz __all__
