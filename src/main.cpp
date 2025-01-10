#include "kerberos/kerberos_ticket_cache.h"
#include "kerberos/kerberos_config.h"
#include <iostream>
#include <string>
#include <thread>

int main(int argc, char* argv[]) {
    try {
        // 检查命令行参数
        if (argc != 3) {
            std::cerr << "Usage: " << argv[0] << " <keytab_path> <principal>" << std::endl;
            return 1;
        }

        // 配置Kerberos参数
        kerberos::KerberosConfig config;
        config.setKeytabPath(argv[1]);
        config.setPrincipal(argv[2]);
        config.setCacheFilePath("FILE:/tmp/krb5cc_test");  // 设置票据缓存文件路径
        config.setRefreshInterval(std::chrono::seconds(5));  // 5分钟刷新一次
        config.setMinTimeBeforeRefresh(std::chrono::seconds(10));  // 剩余10分钟时刷新

        // 创建票据缓存管理器
        kerberos::KerberosTicketCache ticket_cache(config, "/mnt/disk1/yy/ali-emr/krb5.conf");

        // 初始化
        std::cout << "Initializing Kerberos ticket cache..." << std::endl;
        ticket_cache.initialize();

        // 登录并获取票据
        std::cout << "Logging in using keytab..." << std::endl;
        ticket_cache.login();

        // 写入票据缓存
        std::cout << "Writing ticket cache..." << std::endl;
        ticket_cache.writeTicketCache();

        // 启动自动刷新
        std::cout << "Starting periodic refresh..." << std::endl;
        ticket_cache.startPeriodicRefresh();

        // 示例：使用doAs执行需要Kerberos认证的操作
        std::cout << "Executing authenticated operation..." << std::endl;
        ticket_cache.doAs([]() {
            // 这里放置需要Kerberos认证的操作
            std::cout << "Performing authenticated operation..." << std::endl;
            return true;
        });

        // 保持程序运行一段时间以观察票据刷新
        std::cout << "Running... (Press Ctrl+C to exit)" << std::endl;
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
} 
