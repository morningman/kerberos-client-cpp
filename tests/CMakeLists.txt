find_package(GTest REQUIRED)

add_executable(kerberos_tests
    kerberos_ticket_cache_test.cpp
)

target_link_libraries(kerberos_tests
    PRIVATE
        kerberos_client
        GTest::GTest
        GTest::Main
)

add_test(NAME kerberos_tests COMMAND kerberos_tests) 