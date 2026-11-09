#!/bin/bash
# Set multicast_forceflood (0 or 1) on every domain.
for domain in 11 12 13 14 15 16 17 18 19 20; do
    batctl "bat${domain}" multicast_forceflood "$@"
done
