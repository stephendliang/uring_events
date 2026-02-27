#!/bin/bash
# Benchmark script for io_uring HTTP server using wrk
#
# Usage: ./bench.sh [url] [threads] [connections] [duration]
#        ./bench.sh                          # defaults: localhost:8080, 2 threads, 100 conns, 20s
#        ./bench.sh http://127.0.0.1:8080/ 2 500 20s

URL="${1:-http://127.0.0.1:8080/}"
THREADS="${2:-2}"
CONNECTIONS="${3:-100}"
DURATION="${4:-20s}"

echo "=== Benchmark ==="
echo "URL:         $URL"
echo "Threads:     $THREADS"
echo "Connections: $CONNECTIONS"
echo "Duration:    $DURATION"
echo "================="
echo

wrk -t"$THREADS" -c"$CONNECTIONS" -d"$DURATION" --latency "$URL"
