#!/bin/sh
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
	echo "usage: $0 INPUT OUTPUT [RUNTIME_DIR]" >&2
	exit 2
fi

input=$1
output=$2
runtime_dir=${3:-}

if [ ! -f "$input" ]; then
	echo "missing input: $input" >&2
	exit 1
fi
if [ -n "$runtime_dir" ] && [ ! -d "$runtime_dir" ]; then
	echo "missing runtime directory: $runtime_dir" >&2
	exit 1
fi

runtime_enabled=0
if [ -n "$runtime_dir" ]; then
	runtime_enabled=1
fi

tmp="${output}.tmp"
zip_tmp="${output}.ziptmp"
rm -f "$tmp" "$zip_tmp"

app_size=$(wc -c <"$input" | tr -d ' ')
app_stamp=$(cksum "$input" | awk '{ print $1 "-" $2 }')

python3 - "$input" "$zip_tmp" "$runtime_dir" <<'PY'
import os
import sys
import zipfile

src, dst, runtime_dir = sys.argv[1], sys.argv[2], sys.argv[3]
with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.write(src, "alice-pusher-bot")
    if runtime_dir:
        for name in sorted(os.listdir(runtime_dir)):
            path = os.path.join(runtime_dir, name)
            if os.path.isfile(path):
                zf.write(path, "lib/" + name)
PY

cat >"$tmp" <<SCRIPT
#!/bin/sh
set -eu

app_size=$app_size
app_stamp=$app_stamp
runtime_enabled=$runtime_enabled
SCRIPT

cat >>"$tmp" <<'SCRIPT'
self=$0
if [ "${self#/}" = "$self" ]; then
	case "$self" in
	*/*)
		self_dir=${self%/*}
		self_base=${self##*/}
		abs_dir=$(cd "$self_dir" 2>/dev/null && pwd) && self=$abs_dir/$self_base
		;;
	*)
		self=$(pwd)/$self
		;;
	esac
fi
out=${ALICE_PUSHER_EXTRACT:-/tmp/alice-pusher-bot}
tmp="${out}.$$"
zip="${out}.$$.zip"
stamp="${out}.stamp"
lib_out="${out}.lib"
lib_tmp="${lib_out}.$$"
marker="__ALICE_PUSHER_ZIP_PAYLOAD_BELOW__"

trap '' HUP
mount -o remount,exec /tmp 2>/dev/null || true
rm -f "$tmp" "$zip"
rm -rf "$lib_tmp"

runtime_ready()
{
	if [ "$runtime_enabled" = 0 ]; then
		return 0
	fi
	[ -f "$lib_out/libmbedcrypto.so.0" ] &&
	[ -f "$lib_out/libmbedx509.so.0" ] &&
	[ -f "$lib_out/libmbedtls.so.10" ]
}

run_app()
{
	if [ "$runtime_enabled" = 1 ]; then
		LD_LIBRARY_PATH="$lib_out${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
			ALICE_PUSHER_RUN_SOURCE="$self" exec "$out" "$@"
	fi
	ALICE_PUSHER_RUN_SOURCE="$self" exec "$out" "$@"
}

file_size()
{
	set -- $(wc -c <"$1" 2>/dev/null || echo 0)
	echo "${1:-0}"
}

if [ "${ALICE_PUSHER_FORCE_EXTRACT:-0}" != 1 ] && [ -x "$out" ] && [ "$(file_size "$out")" = "$app_size" ] && runtime_ready; then
	if [ "$(cat "$stamp" 2>/dev/null || true)" = "$app_stamp" ]; then
		run_app "$@"
		echo "exec failed: $out" >&2
		exit 127
	fi
fi

if ! command -v sed >/dev/null 2>&1; then
	echo "need sed" >&2
	exit 1
fi
if ! command -v unzip >/dev/null 2>&1; then
	echo "need unzip" >&2
	exit 1
fi

sed "1,/^$marker$/d" "$self" >"$zip"
if [ ! -s "$zip" ]; then
	rm -f "$zip"
	echo "missing zip payload" >&2
	exit 1
fi

if [ "$runtime_enabled" = 1 ]; then
	mkdir -p "$lib_tmp"
	if ! unzip -q "$zip" 'lib/*' -d "$lib_tmp"; then
		rm -rf "$tmp" "$zip" "$lib_tmp"
		echo "runtime library extraction failed" >&2
		exit 1
	fi
	if [ ! -f "$lib_tmp/lib/libmbedcrypto.so.0" ] ||
	   [ ! -f "$lib_tmp/lib/libmbedx509.so.0" ] ||
	   [ ! -f "$lib_tmp/lib/libmbedtls.so.10" ]; then
		rm -rf "$tmp" "$zip" "$lib_tmp"
		echo "runtime libraries missing from payload" >&2
		exit 1
	fi
fi

if ! unzip -p "$zip" alice-pusher-bot >"$tmp"; then
	rm -rf "$tmp" "$zip" "$lib_tmp"
	echo "extract failed" >&2
	exit 1
fi
rm -f "$zip"

if [ ! -s "$tmp" ]; then
	rm -rf "$tmp" "$lib_tmp"
	echo "extract failed" >&2
	exit 1
fi

chmod 755 "$tmp"
mv "$tmp" "$out"
if [ "$runtime_enabled" = 1 ]; then
	rm -rf "$lib_out"
	mv "$lib_tmp/lib" "$lib_out"
	rmdir "$lib_tmp" 2>/dev/null || true
fi
echo "$app_stamp" >"$stamp" 2>/dev/null || true
run_app "$@"
echo "exec failed: $out" >&2
exit 127

__ALICE_PUSHER_ZIP_PAYLOAD_BELOW__
SCRIPT

cat "$zip_tmp" >>"$tmp"
rm -f "$zip_tmp"
chmod 755 "$tmp"
mv "$tmp" "$output"
