#!/bin/bash
# Run a batctl command on every domain, e.g. ./check-bat.sh o
for domain in 11 12 13 14 15 16 17 18 19 20; do
    batctl "bat${domain}" "$@"
done
