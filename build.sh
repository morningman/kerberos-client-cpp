#!/bin/bash

# 设置错误时退出
set -e

# 显示执行的命令
set -x

# 设置项目根目录
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 设置krb5安装路径 (根据实际情况修改)
KRB5_ROOT="/mnt/disk1/yy/git/doris/thirdparty/installed/"

# 创建并进入构建目录
mkdir -p "${PROJECT_ROOT}/build"
cd "${PROJECT_ROOT}/build"

# 配置CMake项目
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DKRB5_ROOT="${KRB5_ROOT}"

# 编译
make -j$(nproc)

echo "Build completed successfully!" 
