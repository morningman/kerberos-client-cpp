#include "kerberos/kerberos_ticket_cache.h"
#include "kerberos/kerberos_exception.h"
#include <chrono>
#include <thread>
#include <sstream>

namespace kerberos {

KerberosTicketCache::KerberosTicketCache(const KerberosConfig& config)
    : config_(config) {
    initializeContext();
}

KerberosTicketCache::KerberosTicketCache(const KerberosConfig& config, const std::string& krb5_conf_path)
    : config_(config), krb5_conf_path_(krb5_conf_path) {
    initializeContext();
}

KerberosTicketCache::~KerberosTicketCache() {
    stopPeriodicRefresh();
    cleanupContext();
}

void KerberosTicketCache::initialize() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    krb5_error_code code = krb5_parse_name(context_, config_.getPrincipal().c_str(), &principal_);
    checkError(code, "Failed to parse principal name");
}

void KerberosTicketCache::login() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    krb5_keytab keytab = nullptr;
    krb5_error_code code;
    
    try {
        // 打开keytab文件
        code = krb5_kt_resolve(context_, config_.getKeytabPath().c_str(), &keytab);
        checkError(code, "Failed to resolve keytab");

        // 初始化凭证缓存
        code = krb5_cc_resolve(context_, config_.getCacheFilePath().c_str(), &ccache_);
        checkError(code, "Failed to resolve credential cache");

        // 获取初始凭证
        krb5_get_init_creds_opt* opts = nullptr;
        code = krb5_get_init_creds_opt_alloc(context_, &opts);
        checkError(code, "Failed to allocate get_init_creds_opt");

        krb5_creds creds;
        code = krb5_get_init_creds_keytab(
            context_,
            &creds,
            principal_,
            keytab,
            0,      // start time
            nullptr,// TKT service name
            opts
        );
        checkError(code, "Failed to get initial credentials");

        // 初始化凭证缓存
        code = krb5_cc_initialize(context_, ccache_, principal_);
        checkError(code, "Failed to initialize credential cache");

        // 存储凭证
        code = krb5_cc_store_cred(context_, ccache_, &creds);
        checkError(code, "Failed to store credentials");

        // 清理
        krb5_free_cred_contents(context_, &creds);
        krb5_get_init_creds_opt_free(context_, opts);
        krb5_kt_close(context_, keytab);
    }
    catch (...) {
        if (keytab) krb5_kt_close(context_, keytab);
        throw;
    }
}

void KerberosTicketCache::loginWithCache() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    krb5_error_code code = krb5_cc_resolve(context_, config_.getCacheFilePath().c_str(), &ccache_);
    checkError(code, "Failed to resolve credential cache");
}

void KerberosTicketCache::writeTicketCache() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!ccache_) {
        throw KerberosException("No credentials cache available");
    }
    
    // MIT Kerberos automatically writes to the cache file
    // when using the FILE: cache type
}

void KerberosTicketCache::refreshTickets() {
    if (!needsRefresh()) {
        return;
    }

    try {
        login();
    } catch (const std::exception& e) {
        std::stringstream ss;
        ss << "Failed to refresh tickets: " << e.what();
        throw KerberosException(ss.str());
    }
}

void KerberosTicketCache::startPeriodicRefresh() {
    should_stop_refresh_ = false;
    refresh_thread_ = std::make_unique<std::thread>([this]() {
        while (!should_stop_refresh_) {
            try {
                if (needsRefresh()) {
                    refreshTickets();
                }
            } catch (const std::exception& e) {
                // Log error but continue running
            }
            std::this_thread::sleep_for(config_.getRefreshInterval());
        }
    });
}

void KerberosTicketCache::stopPeriodicRefresh() {
    if (refresh_thread_) {
        should_stop_refresh_ = true;
        refresh_thread_->join();
        refresh_thread_.reset();
    }
}

void KerberosTicketCache::initializeContext() {
    krb5_error_code code;
    
    if (!krb5_conf_path_.empty()) {
        // 设置环境变量以指定 krb5.conf 路径
        if (setenv("KRB5_CONFIG", krb5_conf_path_.c_str(), 1) != 0) {
            throw std::runtime_error("Failed to set KRB5_CONFIG environment variable");
        }
        std::cerr << "Using custom krb5.conf: " << krb5_conf_path_ << std::endl;
    }

    code = krb5_init_context(&context_);
    checkError(code, "Failed to initialize krb5 context");

    code = krb5_parse_name(context_, config_.getPrincipal().c_str(), &principal_);
    checkError(code, "Failed to parse principal name");
}

void KerberosTicketCache::cleanupContext() {
    if (principal_) {
        krb5_free_principal(context_, principal_);
    }
    if (ccache_) {
        krb5_cc_close(context_, ccache_);
    }
    if (context_) {
        krb5_free_context(context_);
    }
}

void KerberosTicketCache::checkError(krb5_error_code code, const char* message) {
    if (code) {
        const char* err_message = krb5_get_error_message(context_, code);
        std::string full_message = std::string(message) + ": " + err_message;
        krb5_free_error_message(context_, err_message);
        throw KerberosException(full_message);
    }
}

bool KerberosTicketCache::needsRefresh() const {
    if (!ccache_) {
        return true;
    }

    krb5_timestamp now;
    if (krb5_timeofday(context_, &now) != 0) {
        return true;
    }

    krb5_cc_cursor cursor;
    if (krb5_cc_start_seq_get(context_, ccache_, &cursor) != 0) {
        return true;
    }

    bool needs_refresh = true;
    krb5_creds creds;
    while (krb5_cc_next_cred(context_, ccache_, &cursor, &creds) == 0) {
        if (creds.times.endtime - now > config_.getMinTimeBeforeRefresh().count()) {
            needs_refresh = false;
        }
        krb5_free_cred_contents(context_, &creds);
    }

    krb5_cc_end_seq_get(context_, ccache_, &cursor);
    return needs_refresh;
}

} // namespace kerberos 
