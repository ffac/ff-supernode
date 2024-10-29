#!/bin/bash
for domain in 11 12 13 14 15 16 17 18 19 20; do
	batctl bat${domain} multicast_forceflood $1
done
