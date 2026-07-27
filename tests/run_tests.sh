#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BEARSSL_DIR=${BEARSSL_DIR:-$ROOT/third_party/bearssl}
BEARSSL_PROFILE=$ROOT/tools/bearssl_sources.sh
HOST_CC=${HOST_CC:-cc}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

. "$BEARSSL_PROFILE"
set --
for source in $BEARSSL_PUSHER_SOURCES; do
	set -- "$@" "$BEARSSL_DIR/$source"
done
"$HOST_CC" -std=gnu99 -O1 -g -Wall -Wextra -fPIC -shared \
	-I"$BEARSSL_DIR/inc" -I"$BEARSSL_DIR/src" "$@" \
	-Wl,-soname,libbearssl.so.0 \
	-Wl,--version-script="$ROOT/tools/bearssl_exports.map" \
	-o "$TMP/libbearssl.so.0"
"$HOST_CC" -std=gnu99 -O1 -g -Wall -Wextra \
	-I"$ROOT/src" -I"$BEARSSL_DIR/inc" \
	"$ROOT/tests/test_pdu.c" "$ROOT/src/bearssl_transport.c" \
	-L"$TMP" -Wl,-l:libbearssl.so.0 -pthread -o "$TMP/test-pdu"
LD_LIBRARY_PATH="$TMP${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$TMP/test-pdu"
"$ROOT/tests/test_tls.sh"
