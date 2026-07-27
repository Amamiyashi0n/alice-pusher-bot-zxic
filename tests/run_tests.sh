#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BEARSSL_DIR=${BEARSSL_DIR:-$ROOT/third_party/bearssl}
BEARSSL_PROFILE=$ROOT/tools/bearssl_sources.sh
HOST_CC=${HOST_CC:-cc}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

. "$BEARSSL_PROFILE"
set -- "$ROOT/tests/test_pdu.c" "$ROOT/src/bearssl_transport.c"
for source in $BEARSSL_PUSHER_SOURCES; do
	set -- "$@" "$BEARSSL_DIR/$source"
done
"$HOST_CC" -std=gnu99 -O1 -g -Wall -Wextra \
	-I"$ROOT/src" -I"$BEARSSL_DIR/inc" -I"$BEARSSL_DIR/src" \
	"$@" -pthread -o "$TMP/test-pdu"
"$TMP/test-pdu"
"$ROOT/tests/test_tls.sh"
