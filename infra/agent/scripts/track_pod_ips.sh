#!/bin/bash

while true; do

cp /pdt/pod_ips.txt /pdt/pod_ips.txt.in || true
kubectl get pods -o json | jq -r '.items[] | "\(.metadata.name) \(.status.podIPs[0].ip)"' >> /pdt/pod_ips.txt.in

# Now we uniq the file
sort -u /pdt/pod_ips.txt.in > /pdt/pod_ips.txt.uniq
mv /pdt/pod_ips.txt.uniq /pdt/pod_ips.txt


# Now try and get the dns lookups from all the pods

cp /pdt/dns_lookups.txt /pdt/dns_lookups.txt.in || true
kubectl logs -n kube-system -l k8s-app=kube-dns --tail 10000 \
    | sed -E 's/.*\[INFO\] ([0-9.]+):[0-9]+ - [0-9]+ "[A-Z]+ IN ([^ ]+).*/\1 \2/' \
    | grep '^[0-9]' \
    | egrep -v '(cluster.local|internal.cloudapp.net)' \
    >> /pdt/dns_lookups.txt.in

sort -u /pdt/dns_lookups.txt.in > /pdt/dns_lookups.txt.uniq
mv /pdt/dns_lookups.txt.uniq /pdt/dns_lookups.txt

sleep 30

done