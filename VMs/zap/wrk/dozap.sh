#!/bin/bash

# Wait for benchmark
curl -k --head --retry 12 --retry-all-errors --retry-delay 5 https://benchmark:8443/benchmark

# Start scan
zap.sh -cmd -silent -config scanner.injectable=15 -autorun /zap/wrk/af-plan.yaml

#list='xss cmdi'
#for vuln in $list;do 
#    echo "Running scan for ${vuln}"
#    zap.sh -cmd -silent -config scanner.injectable=15 -autorun /zap/wrk/${vuln}/af-plan.yaml
#done

