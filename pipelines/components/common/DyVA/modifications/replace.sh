#!/usr/bin/env bash


for jazz in $(find / -type f -iname jazzer);
do
    mv $jazz $(dirname $jazz)/.jazzer
    cp /jazzer_replacement $(dirname $jazz)/jazzer
    chmod +x $jazz
done