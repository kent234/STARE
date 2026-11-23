#!/usr/bin/env bash
# Регистрация project runner для S.T.A.R.E.
#
# 1. GitLab → проект stare → Settings → CI/CD → Runners → New project runner
# 2. Скопируйте токен (начинается с glrt-)
# 3. Запустите:
#      RUNNER_TOKEN="glrt-..." ./scripts/register-gitlab-runner.sh
#
# Скрипт идемпотентен: повторная регистрация перезаписывает конфиг.

set -euo pipefail

if [[ -z "${RUNNER_TOKEN:-}" ]]; then
  echo "ERROR: RUNNER_TOKEN is required (glrt-... from GitLab project runners page)" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p secrets/gitlab-runner
docker compose -f docker-compose.runner.yml up -d

# Ждём, пока контейнер запустится.
for _ in $(seq 1 30); do
  if docker inspect -f '{{.State.Running}}' stare_gitlab_runner 2>/dev/null | grep -q true; then
    break
  fi
  sleep 1
done

TOKEN_FLAG="--token"
if [[ "$RUNNER_TOKEN" == GR* ]]; then
  # Legacy project registration token (GR1348941...).
  TOKEN_FLAG="--registration-token"
fi

docker exec stare_gitlab_runner gitlab-runner register \
  --non-interactive \
  --url "https://vcs.uni-dubna.ru/" \
  "$TOKEN_FLAG" "$RUNNER_TOKEN" \
  --executor docker \
  --docker-image "alpine:3.20" \
  --docker-privileged \
  --docker-helper-image "gitlab/gitlab-runner-helper:x86_64-v19.6.0" \
  --docker-pull-policy if-not-present \
  --description "stare-local-docker" \
  --tag-list "docker,stare" \
  --run-untagged=true \
  --locked=false

docker exec stare_gitlab_runner sh -c "sed -i 's/^concurrent = .*/concurrent = 3/' /etc/gitlab-runner/config.toml"
docker restart stare_gitlab_runner >/dev/null
sleep 2
docker exec stare_gitlab_runner gitlab-runner verify

echo
echo "Runner registered. Check:"
echo "  https://vcs.uni-dubna.ru/DAAG.24/stare/-/settings/ci_cd"
