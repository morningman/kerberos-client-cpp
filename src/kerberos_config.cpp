#include "kerberos/kerberos_config.h"

namespace kerberos {

KerberosConfig::KerberosConfig()
    : refresh_interval_(std::chrono::seconds(300))      // 默认5分钟刷新一次
    , min_time_before_refresh_(std::chrono::seconds(600)) // 默认剩余10分钟时刷新
{
}

} // namespace kerberos 