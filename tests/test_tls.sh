#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BEARSSL_DIR=${BEARSSL_DIR:-$ROOT/third_party/bearssl}
BEARSSL_PROFILE=$ROOT/tools/bearssl_sources.sh
HOST_CC=${HOST_CC:-cc}
TMP=$(mktemp -d)
SERVER_PID=

cleanup()
{
	if [ -n "$SERVER_PID" ]; then
		kill "$SERVER_PID" 2>/dev/null || true
	fi
	rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

wait_for_server()
{
	for ignored in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
		if [ -s "$TMP/port" ]; then
			return 0
		fi
		if ! kill -0 "$SERVER_PID" 2>/dev/null; then
			wait "$SERVER_PID"
			return 1
		fi
		sleep 0.05
	done
	echo "TLS test server did not start" >&2
	return 1
}

run_server_case()
{
	mode=$1
	cipher=$2
	client_mode=$3
	rm -f "$TMP/port" "$TMP/result"
	python3 "$ROOT/tests/tls_test_server.py" "$mode" "$TMP/port" \
		"$TMP/server.crt" "$TMP/server.key" "$TMP/result" "$cipher" &
	SERVER_PID=$!
	wait_for_server
	port=$(cat "$TMP/port")
	case "$client_mode" in
	webhook)
		"$TMP/test-tls" webhook \
			"https://127.0.0.1:$port/hook?case=bearssl"
		;;
	starttls|tls)
		"$TMP/test-tls" smtp 127.0.0.1 "$port" "$client_mode"
		;;
	*)
		echo "unknown test client mode: $client_mode" >&2
		exit 1
		;;
	esac
	wait "$SERVER_PID"
	SERVER_PID=
	test "$(cat "$TMP/result")" = ok
}

. "$BEARSSL_PROFILE"
set -- "$ROOT/tests/test_tls_paths.c" "$ROOT/src/bearssl_transport.c"
for source in $BEARSSL_PUSHER_SOURCES; do
	set -- "$@" "$BEARSSL_DIR/$source"
done
"$HOST_CC" -std=gnu99 -O1 -g -Wall -Wextra \
	-I"$ROOT/src" -I"$BEARSSL_DIR/inc" -I"$BEARSSL_DIR/src" \
	"$@" -pthread -o "$TMP/test-tls"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
	-subj /CN=localhost -keyout "$TMP/server.key" -out "$TMP/server.crt" \
	>/dev/null 2>&1

run_server_case webhook AES128-GCM-SHA256 webhook
run_server_case webhook AES128-SHA256 webhook
run_server_case webhook AES128-SHA webhook
run_server_case smtp-starttls AES128-GCM-SHA256 starttls
run_server_case smtp-tls AES128-SHA256 tls

echo "BearSSL webhook and SMTP tests: ok"
