#!/usr/bin/env bats

@test "validation.sh sources without error" {
  source "$(dirname "$BATS_TEST_DIRNAME")/../src/lib/core/validation.sh"
}

@test "validate_port rejects 0" {
  source "$(dirname "$BATS_TEST_DIRNAME")/../src/lib/core/validation.sh"
  run validate_port 0
  [ "$status" -ne 0 ]
}
