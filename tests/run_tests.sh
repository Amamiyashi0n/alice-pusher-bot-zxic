#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BEARSSL_DIR=${BEARSSL_DIR:-$ROOT/third_party/bearssl}
BEARSSL_PROFILE=$ROOT/tools/bearssl_sources.sh
HOST_CC=${HOST_CC:-cc}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

mkdir -p "$ROOT/.build"
python3 "$ROOT/tools/embed_asset.py" "$ROOT/pic/miku_compressed.jpg" \
	"$ROOT/.build/avatar_asset.h" avatar_image image/jpeg
python3 "$ROOT/tools/embed_asset.py" "$ROOT/pic/sponsor_clean.jpg" \
	"$ROOT/.build/sponsor_asset.h" sponsor_image image/jpeg

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
"$HOST_CC" -std=gnu99 -O1 -g -Wall -Wextra \
	-Wno-unused-function -Wno-unused-variable \
	-Wno-unused-result -Wno-format-truncation \
	-ffunction-sections -fdata-sections -I"$ROOT/src" \
	"$ROOT/tests/test_autostart.c" -Wl,--gc-sections -pthread \
	-o "$TMP/test-autostart"
"$TMP/test-autostart"
