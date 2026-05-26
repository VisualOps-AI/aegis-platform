#!/bin/bash
set -e

echo "Starting Witness Platform (Local Dev)"
echo "=========================================="
echo ""

echo "Starting Witness Governance on :9000..."
cd services/governance
python -m uvicorn server:app --host 0.0.0.0 --port 9000 &
GOVERNANCE_PID=$!
cd ../..

sleep 2

if [ -n "$OPENAI_API_KEY" ]; then
    sleep 1
    echo "Starting Witness Sentinel on :8080..."
    cd services/sentinel
    python -m uvicorn main:app --host 0.0.0.0 --port 8080 &
    SENTINEL_PID=$!
    cd ../..
else
    echo "WARNING: OPENAI_API_KEY not set - Witness Sentinel not started"
    SENTINEL_PID=""
fi

echo ""
echo "=========================================="
echo "Services running:"
echo "   Witness Governance: http://localhost:9000"
[ -n "$SENTINEL_PID" ] && echo "   Witness Sentinel:   http://localhost:8080"
echo ""
echo "Press Ctrl+C to stop all services"
echo "=========================================="

cleanup() {
    echo ""
    echo "Shutting down..."
    [ -n "$SENTINEL_PID" ] && kill $SENTINEL_PID 2>/dev/null
    kill $GOVERNANCE_PID 2>/dev/null
    exit 0
}
trap cleanup SIGINT SIGTERM

wait
