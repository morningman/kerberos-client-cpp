#!/bin/bash

# 设置错误时退出
set -e

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 检查参数
if [ $# -ne 2 ]; then
    echo "Usage: $0 <keytab_path> <principal>"
    echo "Example: $0 /path/to/user.keytab user@REALM.COM"
    exit 1
fi

KEYTAB_PATH="$1"
PRINCIPAL="$2"

# 检查keytab文件是否存在
if [ ! -f "${KEYTAB_PATH}" ]; then
    echo "Error: Keytab file not found: ${KEYTAB_PATH}"
    exit 1
fi

# 检查keytab文件权限
KEYTAB_PERMS=$(stat -c %a "${KEYTAB_PATH}")
if [ "${KEYTAB_PERMS}" != "600" ]; then
    echo "Warning: Keytab file permissions should be 600 (current: ${KEYTAB_PERMS})"
    read -p "Do you want to fix the permissions? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        chmod 600 "${KEYTAB_PATH}"
    fi
fi

# 设置环境变量（如果需要）
export KRB5_CONFIG="${SCRIPT_DIR}/krb5.conf"  # 如果你有自定义的krb5.conf
export KRB5_TRACE=/dev/stderr  # 启用调试输出，需要时取消注释

# 运行程序
echo "Starting Kerberos client..."
"${SCRIPT_DIR}/build/kerberos_client_demo" "${KEYTAB_PATH}" "${PRINCIPAL}" 