#!/bin/bash
# Print the number of wireguard peers per domain.
for domain in 11 12 13 14 15 16 17 18 19 20; do
    echo "Domain ${domain}	Nodes: $(ls "/etc/wireguard/peers-wg/wg-${domain}" 2>/dev/null | wc -l)"
done
