#!/bin/bash
# SpanTag — start all 8 microservices
# Run from: ~/spantag-keycloak/

ROOT="$(cd "$(dirname "$0")" && pwd)"
LOGS="$ROOT/logs"
mkdir -p "$LOGS"

echo "============================================"
echo " SpanTag Microservices — Keycloak Edition"
echo "============================================"
echo ""
echo "  Keycloak must already be running on :8180"
echo "  PostgreSQL must be running on :5432"
echo ""

PIDS=()

start_service() {
  local name=$1
  local dir=$2
  local jar=$3
  echo "  → Starting $name on port $4"
  java -jar "$ROOT/$dir/$jar" \
    > "$LOGS/$name.log" 2>&1 &
  PIDS+=($!)
  sleep 2
}

start_service "auth-service"    "regularAuthentication/regularAuthentication/target" "regularAuthentication-0.0.1-SNAPSHOT.jar" 9090
start_service "profile"         "profile/profile/target"                             "profile-0.0.1-SNAPSHOT.jar"               9093
start_service "user-service"    "userservice/userservice/target"                     "userservice-0.0.1-SNAPSHOT.jar"           9091
start_service "dashboard"       "dashboard/dashboard/target"                         "dashboard-0.0.1-SNAPSHOT.jar"             9094
start_service "payment-service" "payment-service/payment-service/target"             "payment-service-0.0.1-SNAPSHOT.jar"       9096
start_service "order-service"   "order-service/order-service/target"                 "order-service-0.0.1-SNAPSHOT.jar"         9095
start_service "oauth2-service"  "oauth2-service/oauth2-service/target"               "oauth2-service-0.0.1-SNAPSHOT.jar"        9092
start_service "gateway"         "Apigatewayapplication/Apigatewayapplication/target" "Apigatewayapplication-0.0.1-SNAPSHOT.jar" 1013

echo ""
echo "  All services started. Logs in: $LOGS/"
echo ""
echo "  Gateway:  http://localhost:1013"
echo "  Keycloak: http://localhost:8180/admin"
echo ""
echo "  Press Ctrl+C to stop all services"

trap 'echo "Stopping..."; for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null; done; exit' INT

wait
