#!/bin/sh
# One-shot Compose verification:
#   1. builds the runtime and verify images ("镜像构建" 复核),
#   2. starts the audit service on its configurable port and waits for health,
#   3. runs lock-rule tests plus commit/reject API and HTTP smoke inside the
#      verify container against the running audit service,
#   4. tears everything down and propagates the verify container's exit code.
set -u

if docker compose version >/dev/null 2>&1; then
  DC="docker compose"
else
  DC="docker-compose"
fi

set +e
$DC --profile verify up \
  --build \
  --abort-on-container-exit \
  --exit-code-from verify \
  verify
code=$?
set -e

$DC --profile verify down --remove-orphans >/dev/null 2>&1 || true

echo "verify exited with status $code"
exit $code
