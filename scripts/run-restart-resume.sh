#!/usr/bin/env bash

set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.rekey-resume.yaml}"
NODE_SERVICES=(node1 node2)
APP_SERVICES=("app-sender" "app-receiver")

cleanup() {
  docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans
}
trap cleanup EXIT

# ensure a clean slate before starting
docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans >/dev/null 2>&1 || true

wait_for_health() {
  local service="$1"
  local id status attempts
  attempts=0
  id="$(docker compose -f "${COMPOSE_FILE}" ps -q "${service}")"
  if [[ -z "${id}" ]]; then
    echo "missing container for ${service}"
    return 1
  fi

  while true; do
    status="$(docker inspect -f '{{.State.Health.Status}}' "${id}" 2>/dev/null || echo "unknown")"
    if [[ "${status}" == "healthy" ]]; then
      return 0
    fi
    attempts=$((attempts + 1))
    if [[ ${attempts} -gt 30 ]]; then
      docker compose -f "${COMPOSE_FILE}" logs "${service}" || true
      echo "healthcheck for ${service} did not pass"
      return 1
    fi
    sleep 1
  done
}

wait_for_services() {
  local service
  for service in "$@"; do
    wait_for_health "${service}"
  done
}

wait_for_restart_ready() {
  sleep 12
}

docker compose -f "${COMPOSE_FILE}" build
docker compose -f "${COMPOSE_FILE}" up -d node1 node2
wait_for_services "${NODE_SERVICES[@]}"

docker compose -f "${COMPOSE_FILE}" up -d "${APP_SERVICES[@]}"

wait_for_restart_ready

docker compose -f "${COMPOSE_FILE}" kill -s SIGKILL node1 node2
docker compose -f "${COMPOSE_FILE}" up -d node1 node2
wait_for_services "${NODE_SERVICES[@]}"

ids="$(docker compose -f "${COMPOSE_FILE}" ps -a -q "${APP_SERVICES[@]}")"
if [[ -z "${ids}" ]]; then
  echo "app containers missing"
  docker compose -f "${COMPOSE_FILE}" ps
  exit 1
fi

statuses="$(docker wait ${ids})"
echo "${statuses}" | awk '{print "exit status:", $0}'
if echo "${statuses}" | grep -Ev '^0$' >/dev/null; then
  docker compose -f "${COMPOSE_FILE}" logs "${APP_SERVICES[@]}" || true
  exit 1
fi
