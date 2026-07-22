#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ALICE_BUILDROOT_OUTPUT="${ALICE_BUILDROOT_OUTPUT:-$ROOT_DIR/../alice-buildroot/output-target}"
if [ -x "$ALICE_BUILDROOT_OUTPUT/host/usr/bin/arm-buildroot-linux-uclibcgnueabi-gcc" ]; then
	TOOLCHAIN_DIR="$ALICE_BUILDROOT_OUTPUT/host/usr/bin"
	TOOLCHAIN_SOURCE="$ALICE_BUILDROOT_OUTPUT"
else
	TOOLCHAIN_DIR="$ROOT_DIR/toolchain/host/usr/bin"
	TOOLCHAIN_SOURCE="$ROOT_DIR/toolchain"
fi
CROSS_PREFIX="$TOOLCHAIN_DIR/arm-buildroot-linux-uclibcgnueabi-"
CC="${CC:-${CROSS_PREFIX}gcc}"
STRIP="${STRIP:-${CROSS_PREFIX}strip}"
CFLAGS="${CFLAGS:--O0 -ffunction-sections -fdata-sections}"
ENGINE_CFLAGS="${ENGINE_CFLAGS:--Os -ffunction-sections -fdata-sections}"
LDFLAGS="${LDFLAGS:--Wl,--gc-sections}"
MBEDTLS_DIR="$ROOT_DIR/lib-src/mbedtls-2.1.14"
WEBUI_SRC="$ROOT_DIR/src/webui.c"
ENGINE_SRC="$ROOT_DIR/src/alice-pusher-bot.c"
BUILD_DIR="$ROOT_DIR/.build"
OUTPUT_DIR="$ROOT_DIR/output"
WEBUI_OBJECT="$BUILD_DIR/webui.o"
ENGINE_OBJECT="$BUILD_DIR/alice-pusher-bot.o"
RUNTIME_DIR="$OUTPUT_DIR/lib"
MBEDTLS_BUILD_STAMP="$BUILD_DIR/mbedtls-build.stamp"
TARGET="$OUTPUT_DIR/alice-pusher-bot"
TARGET_RUN="$OUTPUT_DIR/alice-pusher-bot.run"
EMBED_ASSET="$ROOT_DIR/tools/embed_asset.py"
SELF_EXTRACT="$ROOT_DIR/tools/make_self_extract.sh"
AVATAR_SRC="$ROOT_DIR/pic/miku_compressed.jpg"
SPONSOR_SRC="$ROOT_DIR/pic/sponsor_clean.jpg"
TRACE_HELPER_SRC="$ROOT_DIR/tools/sms-ptrace-helper.c"
TRACE_HELPER_TARGET="$BUILD_DIR/sms-ptrace"
MBEDTLS_CRYPTO_SO="$MBEDTLS_DIR/library/libmbedcrypto.so.0"
MBEDTLS_X509_SO="$MBEDTLS_DIR/library/libmbedx509.so.0"
MBEDTLS_TLS_SO="$MBEDTLS_DIR/library/libmbedtls.so.10"
RPATH_FLAGS="${RPATH_FLAGS:--Wl,-rpath,\$ORIGIN/lib}"

need_file() {
	if [ ! -f "$1" ]; then
		echo "错误：缺少文件: $1" >&2
		exit 1
	fi
}

need_exec() {
	if [ ! -x "$1" ]; then
		echo "错误：缺少可执行文件: $1" >&2
		exit 1
	fi
}

build_mbedtls_if_needed() {
	stamp=$(printf '%s\n%s\n%s\n%s' \
		"$(cksum "$MBEDTLS_DIR/include/mbedtls/config.h")" \
		"$($CC -dumpmachine)" \
		"$($CC -dumpversion)" \
		"$CFLAGS")
	if [ -f "$MBEDTLS_TLS_SO" ] &&
	   [ -f "$MBEDTLS_X509_SO" ] &&
	   [ -f "$MBEDTLS_CRYPTO_SO" ] &&
	   [ -f "$MBEDTLS_BUILD_STAMP" ] &&
	   [ "$(cat "$MBEDTLS_BUILD_STAMP")" = "$stamp" ]; then
		return
	fi

	if ! command -v cmake >/dev/null 2>&1; then
		echo "错误：mbedtls 动态库不存在，且当前环境没有 cmake，无法重建库。" >&2
		exit 1
	fi

	(
		cd "$MBEDTLS_DIR"
		rm -rf CMakeCache.txt CMakeFiles library/CMakeFiles
		cmake -DCMAKE_C_COMPILER="$CC" \
			-DCMAKE_C_FLAGS="$CFLAGS -fPIC" \
			-DCMAKE_SHARED_LINKER_FLAGS="$LDFLAGS" \
			-DUSE_SHARED_MBEDTLS_LIBRARY=ON \
			-DUSE_STATIC_MBEDTLS_LIBRARY=OFF \
			-DMBEDTLS_BUILD_TESTS=OFF \
			-DMBEDTLS_BUILD_PROGRAMS=OFF \
			.
		make -j"$(nproc)" lib
	)
	printf '%s\n' "$stamp" > "$MBEDTLS_BUILD_STAMP"
}

copy_mbedtls_runtime() {
	mkdir -p "$RUNTIME_DIR"
	for lib in "$MBEDTLS_CRYPTO_SO" "$MBEDTLS_X509_SO" "$MBEDTLS_TLS_SO"; do
		need_file "$lib"
		cp -Lf "$lib" "$RUNTIME_DIR/$(basename "$lib")"
		"$STRIP" --strip-unneeded "$RUNTIME_DIR/$(basename "$lib")"
	done
}

build_trace_helper() {
	need_file "$TRACE_HELPER_SRC"
	"$CC" $ENGINE_CFLAGS "$TRACE_HELPER_SRC" -o "$TRACE_HELPER_TARGET" \
		$LDFLAGS
	"$STRIP" --strip-all "$TRACE_HELPER_TARGET"
	cp -Lf "$TRACE_HELPER_TARGET" "$RUNTIME_DIR/sms-ptrace"
	chmod 755 "$RUNTIME_DIR/sms-ptrace"
	find "$RUNTIME_DIR" -maxdepth 1 -type f -name strace -delete
}

need_exec "$CC"
need_exec "$STRIP"
need_file "$WEBUI_SRC"
need_file "$ENGINE_SRC"
need_file "$EMBED_ASSET"
need_file "$SELF_EXTRACT"
need_file "$AVATAR_SRC"
need_file "$SPONSOR_SRC"
need_file "$TRACE_HELPER_SRC"
need_file "$MBEDTLS_DIR/include/mbedtls/ssl.h"

mkdir -p "$BUILD_DIR" "$OUTPUT_DIR"
echo "使用工具链：$CC"
echo "工具链 sysroot：$TOOLCHAIN_SOURCE"
python3 "$EMBED_ASSET" "$AVATAR_SRC" "$BUILD_DIR/avatar_asset.h" avatar_image image/jpeg
python3 "$EMBED_ASSET" "$SPONSOR_SRC" "$BUILD_DIR/sponsor_asset.h" sponsor_image image/jpeg

build_mbedtls_if_needed
copy_mbedtls_runtime
build_trace_helper

# GCC 4.7.2 crashes while optimizing webui.c; optimize the smaller engine separately.
"$CC" $CFLAGS -I"$MBEDTLS_DIR/include" -c "$WEBUI_SRC" -o "$WEBUI_OBJECT"
"$CC" $ENGINE_CFLAGS -I"$MBEDTLS_DIR/include" -c "$ENGINE_SRC" -o "$ENGINE_OBJECT"
"$CC" "$WEBUI_OBJECT" "$ENGINE_OBJECT" -o "$TARGET" \
	$LDFLAGS $RPATH_FLAGS -L"$MBEDTLS_DIR/library" \
	-lmbedtls -lmbedx509 -lmbedcrypto -pthread
"$STRIP" --strip-all "$TARGET"
"$SELF_EXTRACT" "$TARGET" "$TARGET_RUN" "$RUNTIME_DIR"

echo "构建完成："
ls -lh "$TARGET" "$TARGET_RUN"
