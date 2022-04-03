#!/bin/bash

perl -w ./sort.pl \
    -i http_exploit_requests.log \
    -o a.out \
    -n localhost \
    -p 3001 \
    -v
