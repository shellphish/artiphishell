#!/bin/bash

set -x

cd /backup

tar cfz k8s_info.tar.gz k8s_info

for p in $(ls pipeline/); do
    if [ ! -f "$p.tar.gz" ]; then
        tar cfz $p.tar.gz ./pipeline/$p
    fi
done

set +x

echo
echo
echo

echo 'mkdir -p $BACKUPDIR/'
echo "kubectl cp $(hostname):/backup/k8s_info.tar.gz "'$BACKUPDIR/k8s_info.tar.gz'

for p in $(ls pipeline/); do
    echo "kubectl cp $(hostname):/backup/$p.tar.gz "'$BACKUPDIR'"/$p.tar.gz"
done
