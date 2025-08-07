#!/bin/bash
set -e
set -x

if [ ! -d "cvelistV5" ]; then
    git clone git@github.com:CVEProject/cvelistV5.git
fi

if [ ! -d "jenkins" ]; then
    git clone git@github.com:jenkinsci/jenkins.git
fi

if [ ! -d "linux" ]; then
    git clone git@github.com:torvalds/linux.git
fi


if [ ! -f '1425.csv' ]; then
    wget https://cwe.mitre.org/data/csv/1425.csv.zip
    unzip 1425.csv.zip
fi