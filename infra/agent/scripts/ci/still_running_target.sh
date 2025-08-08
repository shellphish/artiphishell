#!/bin/bash

pd status | grep "live " | grep -v "live 0" | wc -l