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

trace_helper_enabled=0
if [ -n "$runtime_dir" ] && [ -x "$runtime_dir/sms-ptrace" ]; then
	trace_helper_enabled=1
fi
tls_library_name=libbearssl.so.0
tls_runtime_enabled=0
if [ -n "$runtime_dir" ] && [ -f "$runtime_dir/$tls_library_name" ]; then
	tls_runtime_enabled=1
fi

tmp="${output}.tmp"
zip_tmp="${output}.ziptmp"
rm -f "$tmp" "$zip_tmp"

app_size=$(wc -c <"$input" | tr -d ' ')
app_stamp=$(cksum "$input" | awk '{ print $1 "-" $2 }')
if [ "$tls_runtime_enabled" = 1 ]; then
	tls_stamp=$(cksum "$runtime_dir/$tls_library_name" | awk '{ print $1 "-" $2 }')
	app_stamp="$app_stamp-$tls_stamp"
fi
if [ "$trace_helper_enabled" = 1 ]; then
	helper_stamp=$(cksum "$runtime_dir/sms-ptrace" | awk '{ print $1 "-" $2 }')
	app_stamp="$app_stamp-$helper_stamp"
fi

python3 - "$input" "$zip_tmp" "$runtime_dir" <<'PY'
import os
import sys
import zipfile

src, dst, runtime_dir = sys.argv[1], sys.argv[2], sys.argv[3]
with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.write(src, "alice-pusher-bot")
    if runtime_dir:
        tls_library = os.path.join(runtime_dir, "libbearssl.so.0")
        if os.path.isfile(tls_library):
            zf.write(tls_library, "lib/libbearssl.so.0")
        helper = os.path.join(runtime_dir, "sms-ptrace")
        if os.path.isfile(helper):
            zf.write(helper, "sms-ptrace")
PY

cat >"$tmp" <<SCRIPT
#!/bin/sh
set -eu

app_size=$app_size
app_stamp=$app_stamp
trace_helper_enabled=$trace_helper_enabled
tls_runtime_enabled=$tls_runtime_enabled
tls_library_name=$tls_library_name
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
trace_helper_out="${out}.sms-ptrace"
trace_helper_tmp="${trace_helper_out}.$$"
marker="__ALICE_PUSHER_ZIP_PAYLOAD_BELOW__"

trap '' HUP
mount -o remount,exec /tmp 2>/dev/null || true
rm -f "$tmp" "$zip"
rm -rf "$lib_tmp"
rm -f "$trace_helper_tmp"

runtime_ready()
{
	if [ "$tls_runtime_enabled" = 1 ] &&
	   [ ! -s "$lib_out/$tls_library_name" ]; then
		return 1
	fi
	if [ "$trace_helper_enabled" = 1 ]; then
		[ -x "$trace_helper_out" ]
		return
	fi
	return 0
}

run_app()
{
	if [ "$tls_runtime_enabled" = 1 ]; then
		if [ "$trace_helper_enabled" = 1 ]; then
			ALICE_PUSHER_TRACE_HELPER="$trace_helper_out" \
			LD_LIBRARY_PATH="$lib_out${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
			ALICE_PUSHER_RUN_SOURCE="$self" exec "$out" "$@"
		fi
		LD_LIBRARY_PATH="$lib_out${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
			ALICE_PUSHER_RUN_SOURCE="$self" exec "$out" "$@"
	fi
	if [ "$trace_helper_enabled" = 1 ]; then
		ALICE_PUSHER_TRACE_HELPER="$trace_helper_out" \
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

if [ "$tls_runtime_enabled" = 1 ]; then
	mkdir -p "$lib_tmp"
	if ! unzip -p "$zip" "lib/$tls_library_name" >"$lib_tmp/$tls_library_name"; then
		rm -rf "$tmp" "$zip" "$lib_tmp" "$trace_helper_tmp"
		echo "BearSSL runtime extraction failed" >&2
		exit 1
	fi
	if [ ! -s "$lib_tmp/$tls_library_name" ]; then
		rm -rf "$tmp" "$zip" "$lib_tmp" "$trace_helper_tmp"
		echo "BearSSL runtime missing from payload" >&2
		exit 1
	fi
	chmod 755 "$lib_tmp/$tls_library_name"
fi

if [ "$trace_helper_enabled" = 1 ]; then
	if ! unzip -p "$zip" sms-ptrace >"$trace_helper_tmp"; then
		rm -rf "$tmp" "$zip" "$lib_tmp" "$trace_helper_tmp"
		echo "sms-ptrace extraction failed" >&2
		exit 1
	fi
	if [ ! -s "$trace_helper_tmp" ]; then
		rm -rf "$tmp" "$zip" "$lib_tmp" "$trace_helper_tmp"
		echo "sms-ptrace missing from payload" >&2
		exit 1
	fi
	chmod 755 "$trace_helper_tmp"
fi

if ! unzip -p "$zip" alice-pusher-bot >"$tmp"; then
	rm -rf "$tmp" "$zip" "$lib_tmp" "$trace_helper_tmp"
	echo "extract failed" >&2
	exit 1
fi
rm -f "$zip"

if [ ! -s "$tmp" ]; then
	rm -rf "$tmp" "$lib_tmp" "$trace_helper_tmp"
	echo "extract failed" >&2
	exit 1
fi

chmod 755 "$tmp"
mv "$tmp" "$out"
if [ "$tls_runtime_enabled" = 1 ]; then
	rm -rf "$lib_out"
	mv "$lib_tmp" "$lib_out"
fi
if [ "$trace_helper_enabled" = 1 ]; then
	mv "$trace_helper_tmp" "$trace_helper_out"
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
