#!/usr/bin/env bats

@test "config.sh sources without error" {
  source "$(dirname "$BATS_TEST_DIRNAME")/../src/lib/core/config.sh"
}

@test "config has VNC defaults" {
  source "$(dirname "$BATS_TEST_DIRNAME")/../src/lib/core/config.sh"
  [ "$VNC_DISPLAY" = "1" ]
}
