#!/bin/bash 

# 设置交叉编译工具链（当前目录的toolchain） 
export CROSS_COMPILE=$(pwd)/toolchain/host/usr/bin/arm-buildroot-linux-uclibcgnueabi- 
export CC=${CROSS_COMPILE}gcc 
export STRIP=${CROSS_COMPILE}strip 

# 优化选项：-Os优化大小，-s移除所有符号，-ffunction-sections/-fdata-sections配合链接器垃圾回收
 export CFLAGS="-Os -s -ffunction-sections -fdata-sections -flto -fwhole-program" 
# 链接器选项：--gc-sections启用垃圾回收，-static强制静态链接
 export LDFLAGS="-Wl,--gc-sections -static -Wl,--exclude-libs,ALL" 

# 设置polarssl库目录（当前目录的lib-src/polarssl-1.2.14） 
POLARSSL_DIR=$(pwd)/lib-src/polarssl-1.2.14 

# 检查polarssl目录是否存在 
if [ ! -d "${POLARSSL_DIR}" ]; then 
    echo "错误：polarssl目录不存在: ${POLARSSL_DIR}" 
    exit 1 
fi 

# 设置源文件目录（当前目录的src） 
SRC_DIR=$(pwd)/src 

# 设置输出目录 
OUTPUT_DIR=$(pwd)/output 
mkdir -p ${OUTPUT_DIR} 

# 进入polarssl目录进行编译（只编译不安装） 
cd "${POLARSSL_DIR}" 

# 清理之前的构建 
make clean 2>/dev/null 
rm -rf CMakeCache.txt CMakeFiles 

# 配置polarssl，禁用不必要的功能以减小体积 
if [ -f "configure" ]; then 
    # 使用autotools配置 
    ./configure --host=arm-buildroot-linux-uclibcgnueabi \
                --disable-shared \
                --enable-static \
                --disable-tests \
                --disable-programs \
                --without-pthread \
                --enable-small \
                CFLAGS="${CFLAGS}" \
                LDFLAGS="${LDFLAGS}" 
elif [ -f "CMakeLists.txt" ]; then 
    # 使用CMake配置 
    cmake -DCMAKE_C_COMPILER="${CC}" \
          -DCMAKE_C_FLAGS="${CFLAGS}" \
          -DCMAKE_EXE_LINKER_FLAGS="${LDFLAGS}" \
          -DUSE_SHARED_POLARSSL_LIBRARY=OFF \
          -DUSE_STATIC_POLARSSL_LIBRARY=ON \
          -DPOLARSSL_BUILD_TESTS=OFF \
          -DPOLARSSL_BUILD_PROGRAMS=OFF \
          -DENABLE_SMALL=ON \
          . 
else 
    echo "错误：无法识别polarssl的构建系统" 
    exit 1 
fi 

# 编译polarssl 
make -j$(nproc) 

# 返回原目录 
cd .. 

# 编译指定的C文件，使用优化选项 
${CC} ${CFLAGS} -I${POLARSSL_DIR}/include ${SRC_DIR}/alice-sms-webhook_polarssl.c -o ${OUTPUT_DIR}/alice-sms-webhook_polarssl \
    ${LDFLAGS} -L${POLARSSL_DIR}/library -lpolarssl 

# 检查是否生成了可执行文件 
if [ -f "${OUTPUT_DIR}/alice-sms-webhook_polarssl" ]; then 
    # 使用strip移除符号表和调试信息（即使已用-s选项，再次strip确保最小化）
    ${STRIP} --strip-all --strip-debug ${OUTPUT_DIR}/alice-sms-webhook_polarssl 
    echo "编译完成！" 
    echo "可执行文件位置: ${OUTPUT_DIR}/alice-sms-webhook_polarssl" 
    echo "优化后文件大小: $(du -h ${OUTPUT_DIR}/alice-sms-webhook_polarssl | cut -f1)" 
else 
    echo "编译失败：未能生成可执行文件" 
    exit 1 
fi