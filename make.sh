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
SDK_CC="${SDK_CC:-${CROSS_PREFIX}gcc}"
CC="${CC:-arm-linux-gnueabi-gcc}"
STRIP="${STRIP:-${CROSS_PREFIX}strip}"
CFLAGS="${CFLAGS:--Os -flto -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables}"
ENGINE_CFLAGS="${ENGINE_CFLAGS:--Os -flto -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables}"
TARGET_CFLAGS="${TARGET_CFLAGS:--march=armv7-a -mfloat-abi=soft}"
LDFLAGS="${LDFLAGS:--flto -Wl,--gc-sections}"
BEARSSL_DIR="${BEARSSL_DIR:-$ROOT_DIR/third_party/bearssl}"
BEARSSL_PROFILE="$ROOT_DIR/tools/bearssl_sources.sh"
WEBUI_SRC="$ROOT_DIR/src/webui.c"
ENGINE_SRC="$ROOT_DIR/src/alice-pusher-bot.c"
TRANSPORT_SRC="$ROOT_DIR/src/bearssl_transport.c"
BUILD_DIR="$ROOT_DIR/.build"
OUTPUT_DIR="$ROOT_DIR/output"
WEBUI_OBJECT="$BUILD_DIR/webui.o"
ENGINE_OBJECT="$BUILD_DIR/alice-pusher-bot.o"
TRANSPORT_OBJECT="$BUILD_DIR/bearssl-transport.o"
RUNTIME_DIR="$OUTPUT_DIR/lib"
TLS_LIBRARY_NAME="libalice-bearssl.so.0"
TLS_LIBRARY_BUILD="$BUILD_DIR/$TLS_LIBRARY_NAME"
TLS_LIBRARY="$RUNTIME_DIR/$TLS_LIBRARY_NAME"
TLS_EXPORT_MAP="$ROOT_DIR/tools/bearssl_exports.map"
TARGET="$OUTPUT_DIR/alice-pusher-bot"
TARGET_RUN="$OUTPUT_DIR/alice-pusher-bot.run"
EMBED_ASSET="$ROOT_DIR/tools/embed_asset.py"
SELF_EXTRACT="$ROOT_DIR/tools/make_self_extract.sh"
AVATAR_SRC="$ROOT_DIR/pic/miku_compressed.jpg"
SPONSOR_SRC="$ROOT_DIR/pic/sponsor_clean.jpg"
TRACE_HELPER_SRC="$ROOT_DIR/tools/sms-ptrace-helper.c"
TRACE_HELPER_TARGET="$BUILD_DIR/sms-ptrace"

if [ ! -f "$BEARSSL_PROFILE" ]; then
	echo "错误：缺少 BearSSL 源文件清单: $BEARSSL_PROFILE" >&2
	exit 1
fi
. "$BEARSSL_PROFILE"

need_file() {
	if [ ! -f "$1" ]; then
		echo "错误：缺少文件: $1" >&2
		exit 1
	fi
}

need_exec() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "错误：缺少可执行命令: $1" >&2
		exit 1
	fi
}

build_trace_helper() {
	need_file "$TRACE_HELPER_SRC"
	mkdir -p "$RUNTIME_DIR"
	"$CC" $ENGINE_CFLAGS "$TRACE_HELPER_SRC" -o "$TRACE_HELPER_TARGET" \
		$PROGRAM_LDFLAGS
	"$STRIP" --strip-all "$TRACE_HELPER_TARGET"
	cp -Lf "$TRACE_HELPER_TARGET" "$RUNTIME_DIR/sms-ptrace"
	chmod 755 "$RUNTIME_DIR/sms-ptrace"
	find "$RUNTIME_DIR" -maxdepth 1 -type f -name strace -delete
	find "$RUNTIME_DIR" -maxdepth 1 -type f -name 'libmbed*.so*' -delete
	find "$RUNTIME_DIR" -maxdepth 1 -type f -name 'libalice-bearssl.so*' -delete
}

need_exec "$CC"
need_exec "$SDK_CC"
need_exec "$STRIP"
need_exec readelf
need_file "$WEBUI_SRC"
need_file "$ENGINE_SRC"
need_file "$TRANSPORT_SRC"
need_file "$EMBED_ASSET"
need_file "$SELF_EXTRACT"
need_file "$AVATAR_SRC"
need_file "$SPONSOR_SRC"
need_file "$TRACE_HELPER_SRC"
need_file "$TLS_EXPORT_MAP"
need_file "$BEARSSL_DIR/inc/bearssl.h"
for source in $BEARSSL_PUSHER_SOURCES; do
	need_file "$BEARSSL_DIR/$source"
done

UCLIBC_SYSROOT="${UCLIBC_SYSROOT:-$($SDK_CC -print-sysroot)}"
UCLIBC_RUNTIME_DIR="${UCLIBC_RUNTIME_DIR:-$(dirname -- "$($SDK_CC -print-libgcc-file-name)")}"
CC_INCLUDE_DIR=$($CC -print-file-name=include)
need_file "$UCLIBC_SYSROOT/lib/ld-uClibc.so.0"
need_file "$UCLIBC_SYSROOT/lib/libc.so.0"
need_file "$UCLIBC_SYSROOT/lib/libgcc_s.so.1"
need_file "$UCLIBC_RUNTIME_DIR/libgcc.a"
if [ ! -d "$CC_INCLUDE_DIR" ]; then
	echo "错误：找不到编译器内部头文件目录: $CC_INCLUDE_DIR" >&2
	exit 1
fi
SYSROOT_CFLAGS="--sysroot=$UCLIBC_SYSROOT -nostdinc -isystem $CC_INCLUDE_DIR -isystem $UCLIBC_SYSROOT/usr/include -B$UCLIBC_SYSROOT/usr/lib/ -B$UCLIBC_RUNTIME_DIR/"
CFLAGS="$CFLAGS $TARGET_CFLAGS $SYSROOT_CFLAGS -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fno-stack-protector -std=gnu99"
ENGINE_CFLAGS="$ENGINE_CFLAGS $TARGET_CFLAGS $SYSROOT_CFLAGS -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fno-stack-protector -std=gnu99"
LDFLAGS="$LDFLAGS --sysroot=$UCLIBC_SYSROOT -B$UCLIBC_SYSROOT/usr/lib/ -B$UCLIBC_RUNTIME_DIR/ -Wl,--hash-style=both"
DYNAMIC_LIBGCC_FLAGS="-L$UCLIBC_SYSROOT/lib -Wl,-rpath-link,$UCLIBC_SYSROOT/lib -Wl,--as-needed -Wl,-l:libgcc_s.so.1 -Wl,--no-as-needed"
PROGRAM_LDFLAGS="$LDFLAGS -Wl,--dynamic-linker=/lib/ld-uClibc.so.0 $DYNAMIC_LIBGCC_FLAGS"

mkdir -p "$BUILD_DIR" "$OUTPUT_DIR"
echo "使用工具链：$CC"
echo "目标 SDK：$TOOLCHAIN_SOURCE"
echo "目标 sysroot：$UCLIBC_SYSROOT"
python3 "$EMBED_ASSET" "$AVATAR_SRC" "$BUILD_DIR/avatar_asset.h" avatar_image image/jpeg
python3 "$EMBED_ASSET" "$SPONSOR_SRC" "$BUILD_DIR/sponsor_asset.h" sponsor_image image/jpeg

build_trace_helper

# The SDK GCC 4.7 cannot optimize these sources reliably, so compilation uses
# a newer GCC frontend while retaining the SDK's uClibc ABI and sysroot.
"$CC" $CFLAGS -I"$ROOT_DIR/src" -c "$WEBUI_SRC" -o "$WEBUI_OBJECT"
"$CC" $ENGINE_CFLAGS -I"$ROOT_DIR/src" -I"$BEARSSL_DIR/inc" \
	-c "$ENGINE_SRC" -o "$ENGINE_OBJECT"
"$CC" $ENGINE_CFLAGS -I"$ROOT_DIR/src" -I"$BEARSSL_DIR/inc" \
	-fPIC -c "$TRANSPORT_SRC" -o "$TRANSPORT_OBJECT"

BEARSSL_OBJECTS=""
for source in $BEARSSL_PUSHER_SOURCES; do
	object="$BUILD_DIR/bearssl/${source%.c}.o"
	mkdir -p "$(dirname -- "$object")"
	"$CC" $ENGINE_CFLAGS -fPIC -I"$BEARSSL_DIR/inc" -I"$BEARSSL_DIR/src" \
		-c "$BEARSSL_DIR/$source" -o "$object"
	BEARSSL_OBJECTS="$BEARSSL_OBJECTS $object"
done

"$CC" -shared "$TRANSPORT_OBJECT" $BEARSSL_OBJECTS \
	-o "$TLS_LIBRARY_BUILD" $LDFLAGS $DYNAMIC_LIBGCC_FLAGS \
	-Wl,-soname,"$TLS_LIBRARY_NAME" \
	-Wl,--version-script="$TLS_EXPORT_MAP"
"$STRIP" --strip-unneeded "$TLS_LIBRARY_BUILD"
cp -Lf "$TLS_LIBRARY_BUILD" "$TLS_LIBRARY"
chmod 755 "$TLS_LIBRARY"

"$CC" "$WEBUI_OBJECT" "$ENGINE_OBJECT" -o "$TARGET" \
	$PROGRAM_LDFLAGS -pthread -L"$RUNTIME_DIR" \
	-Wl,-rpath-link,"$RUNTIME_DIR" -Wl,-l:"$TLS_LIBRARY_NAME"
"$STRIP" --strip-all "$TARGET"

if ! readelf -h "$TARGET" 2>/dev/null | grep -E 'Class:[[:space:]]+ELF32' >/dev/null ||
	! readelf -h "$TARGET" 2>/dev/null | grep -E 'Machine:[[:space:]]+ARM' >/dev/null ||
	! readelf -l "$TARGET" 2>/dev/null | grep -F '/lib/ld-uClibc.so.0' >/dev/null ||
	! readelf -d "$TARGET" 2>/dev/null | grep -F 'Shared library: [libc.so.0]' >/dev/null; then
	echo "错误：产物不是预期的 ARM/uClibc 动态程序。" >&2
	exit 1
fi
if ! readelf -d "$TARGET" 2>/dev/null | grep -F "Shared library: [$TLS_LIBRARY_NAME]" >/dev/null; then
	echo "错误：主程序没有声明私有 BearSSL 动态库。" >&2
	exit 1
fi
if ! readelf -d "$TARGET" 2>/dev/null | grep -F 'Shared library: [libgcc_s.so.1]' >/dev/null ||
	! readelf -d "$TLS_LIBRARY" 2>/dev/null | grep -F 'Shared library: [libgcc_s.so.1]' >/dev/null; then
	echo "错误：产物没有使用目标系统的动态 libgcc_s。" >&2
	exit 1
fi
if ! readelf -h "$TLS_LIBRARY" 2>/dev/null | grep -E 'Class:[[:space:]]+ELF32' >/dev/null ||
	! readelf -h "$TLS_LIBRARY" 2>/dev/null | grep -E 'Machine:[[:space:]]+ARM' >/dev/null ||
	! readelf -d "$TLS_LIBRARY" 2>/dev/null | grep -F "Library soname: [$TLS_LIBRARY_NAME]" >/dev/null ||
	! readelf -S "$TLS_LIBRARY" 2>/dev/null | grep -E '[[:space:]]\.hash[[:space:]]' >/dev/null; then
	echo "错误：BearSSL 动态库不是预期的 ARM ELF32/SONAME。" >&2
	exit 1
fi
if readelf -d "$TARGET" "$TLS_LIBRARY" 2>/dev/null | grep -E 'libmbed(tls|x509|crypto)|libc\.so\.6|ld-linux' >/dev/null; then
	echo "错误：产物包含禁止的 mbedTLS/glibc 运行时依赖。" >&2
	exit 1
fi
if readelf --wide --dyn-syms "$TLS_LIBRARY" 2>/dev/null | grep -E '[[:space:]]br_[A-Za-z0-9_]*$' >/dev/null; then
	echo "错误：BearSSL 内部符号被意外导出。" >&2
	exit 1
fi
"$SELF_EXTRACT" "$TARGET" "$TARGET_RUN" "$RUNTIME_DIR"

echo "构建完成："
ls -lh "$TARGET" "$TLS_LIBRARY" "$TARGET_RUN"
