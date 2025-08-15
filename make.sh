#!/bin/bash 

# 设置交叉编译工具链（当前目录的toolchain） 
export CROSS_COMPILE=$(pwd)/toolchain/host/usr/bin/arm-buildroot-linux-uclibcgnueabi- 
export CC=${CROSS_COMPILE}gcc 
export STRIP=${CROSS_COMPILE}strip 

 export CFLAGS="-Os -ffunction-sections -fdata-sections" 
export LDFLAGS="-Wl,--gc-sections" 

# 设置mbedtls库目录（当前目录的lib-src/mbedtls-2.1.14） 
MBEDTLS_DIR=$(pwd)/lib-src/mbedtls-2.1.14 

# 检查mbedtls目录是否存在 
if [ ! -d "${MBEDTLS_DIR}" ]; then 
    echo "错误：mbedtls目录不存在: ${MBEDTLS_DIR}" 
    exit 1 
fi 

# 设置源文件路径（当前目录的src/alice-sms-webhook_mbedtls.c） 
SRC_FILE=$(pwd)/src/alice-sms-pusher.c

# 检查源文件是否存在 
if [ ! -f "${SRC_FILE}" ]; then 
    echo "错误：源文件不存在: ${SRC_FILE}" 
    exit 1 
fi 

# 设置输出目录 
OUTPUT_DIR=$(pwd)/output 
mkdir -p ${OUTPUT_DIR} 

# 进入mbedtls目录进行编译（只编译不安装） 
cd "${MBEDTLS_DIR}" 

# 清理之前的构建 
make clean 2>/dev/null 
rm -rf CMakeCache.txt CMakeFiles 

# 配置mbedtls，禁用不必要的功能以减小体积 
if [ -f "CMakeLists.txt" ]; then 
    # 使用CMake配置 
    cmake -DCMAKE_C_COMPILER="${CC}" \
          -DCMAKE_C_FLAGS="${CFLAGS}" \
          -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS}" \
          -DUSE_SHARED_MBEDTLS_LIBRARY=OFF \
          -DUSE_STATIC_MBEDTLS_LIBRARY=ON \
          -DMBEDTLS_BUILD_TESTS=OFF \
          -DMBEDTLS_BUILD_PROGRAMS=OFF \
          . 
elif [ -f "configure" ]; then 
    # 使用autotools配置 
    ./configure --host=arm-buildroot-linux-uclibcgnueabi \
                --disable-shared \
                --enable-static \
                --disable-tests \
                --disable-programs \
                CFLAGS="${CFLAGS}" \
                LDFLAGS="${LDFLAGS}" 
else 
    echo "错误：无法识别mbedtls的构建系统" 
    exit 1 
fi 

# 编译mbedtls 
make -j$(nproc) 

# 返回原目录 
cd .. 

# 编译指定的C文件，使用优化选项 
${CC} ${CFLAGS} -I${MBEDTLS_DIR}/include ${SRC_FILE} -o ${OUTPUT_DIR}/alice-sms-pusher \
    ${LDFLAGS} -L${MBEDTLS_DIR}/library -lmbedtls -lmbedx509 -lmbedcrypto -pthread

# 检查是否生成了可执行文件 
if [ -f "${OUTPUT_DIR}/alice-sms-pusher" ]; then 
    # 使用strip移除符号表和调试信息 
    ${STRIP} --strip-all ${OUTPUT_DIR}/alice-sms-pusher
    echo "编译完成！" 
    echo "可执行文件位置: ${OUTPUT_DIR}/alice-sms-pusher" 
    echo "优化后文件大小: $(du -h ${OUTPUT_DIR}/alice-sms-pusher| cut -f1)" 
else 
    echo "编译失败：未能生成可执行文件" 
    exit 1 
fi