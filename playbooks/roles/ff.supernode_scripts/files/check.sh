#!/bin/bash
for domain in 11 12 13 14 15 16 17 18 19 20; do
	echo "Domain ${domain}	Nodes: $(ls -l "/etc/wireguard/peers-wg/wg-${domain}" | wc -l)"
done
