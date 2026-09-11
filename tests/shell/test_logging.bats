#!/usr/bin/env bats

@test "logging.sh sources without error" {
  source "$(dirname "$BATS_TEST_DIRNAME")/../src/lib/core/logging.sh"
}

@test "log_info function exists" {
  source "$(dirname "$BATS_TEST_DIRNAME")/../src/lib/core/logging.sh"
  [ "$(type -t log_info)" = "function" ]
}
