#pragma once

#include "kerberos_config.h"
#include <krb5.h>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <functional>

namespace kerberos {

class KerberosTicketCache {
public:
    explicit KerberosTicketCache(const KerberosConfig& config);
    ~KerberosTicketCache();

    // 禁用拷贝
    KerberosTicketCache(const KerberosTicketCache&) = delete;
    KerberosTicketCache& operator=(const KerberosTicketCache&) = delete;

    // 初始化和登录
    void initialize();
    void login();
    void loginWithCache();

    // 票据管理
    void writeTicketCache();
    void refreshTickets();
    
    // 执行需要Kerberos认证的操作
    template<typename Func>
    auto doAs(Func&& func) -> decltype(func());

    // 开始定期刷新
    void startPeriodicRefresh();
    void stopPeriodicRefresh();

private:
    void initializeContext();
    void cleanupContext();
    void checkError(krb5_error_code code, const char* message);
    bool needsRefresh() const;

    KerberosConfig config_;
    krb5_context context_{nullptr};
    krb5_ccache ccache_{nullptr};
    krb5_principal principal_{nullptr};

    std::unique_ptr<std::thread> refresh_thread_;
    std::mutex mutex_;
    std::atomic<bool> should_stop_refresh_{false};
};

} // namespace kerberos 