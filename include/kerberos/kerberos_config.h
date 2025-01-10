#pragma once

#include <string>
#include <chrono>

namespace kerberos {

class KerberosConfig {
public:
    KerberosConfig();

    void setKeytabPath(const std::string& path) { keytab_path_ = path; }
    void setPrincipal(const std::string& principal) { principal_ = principal; }
    void setCacheFilePath(const std::string& path) { cache_file_path_ = path; }
    void setRefreshInterval(std::chrono::seconds interval) { refresh_interval_ = interval; }
    void setMinTimeBeforeRefresh(std::chrono::seconds time) { min_time_before_refresh_ = time; }

    const std::string& getKeytabPath() const { return keytab_path_; }
    const std::string& getPrincipal() const { return principal_; }
    const std::string& getCacheFilePath() const { return cache_file_path_; }
    std::chrono::seconds getRefreshInterval() const { return refresh_interval_; }
    std::chrono::seconds getMinTimeBeforeRefresh() const { return min_time_before_refresh_; }

private:
    std::string keytab_path_;
    std::string principal_;
    std::string cache_file_path_;
    std::chrono::seconds refresh_interval_;
    std::chrono::seconds min_time_before_refresh_;
};

} // namespace kerberos 