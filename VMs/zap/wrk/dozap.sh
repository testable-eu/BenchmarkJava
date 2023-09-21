#!/bin/bash

# Wait for benchmark
curl -k --head --retry 12 --retry-all-errors --retry-delay 5 https://benchmark:8443/benchmark

# Start scan
zap.sh -cmd -silent -config scanner.injectable=15 -autorun /zap/wrk/cmdi/af-plan.yaml