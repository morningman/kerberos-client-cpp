cmake_minimum_required(VERSION 3.14)
project(kerberos_client VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set KRB5 custom path
set(KRB5_ROOT "/mnt/disk1/yy/git/doris/thirdparty/installed/")
set(CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH} ${KRB5_ROOT})

# Help CMake find KRB5
set(KRB5_INCLUDE_DIRS "${KRB5_ROOT}/include")
set(KRB5_LIBRARIES 
    "${KRB5_ROOT}/lib/libkrb5.a"
    "${KRB5_ROOT}/lib/libk5crypto.a"
    "${KRB5_ROOT}/lib/libcom_err.a"
    "${KRB5_ROOT}/lib/libkrb5support.a"
)

# Find required packages
find_package(OpenSSL REQUIRED)

# 设置静态链接
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")

# Add library target
add_library(kerberos_client
    src/kerberos_ticket_cache.cpp
    src/kerberos_config.cpp
)

# 设置为静态库
set_target_properties(kerberos_client PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)

target_include_directories(kerberos_client
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        ${KRB5_INCLUDE_DIRS}
)

target_link_libraries(kerberos_client
    PRIVATE
        ${KRB5_LIBRARIES}
        OpenSSL::SSL
        OpenSSL::Crypto
        -ldl      # 可能需要链接动态加载库
        -lresolv  # 可能需要链接解析库
)

# Add executable
add_executable(kerberos_client_demo
    src/main.cpp
)

target_link_libraries(kerberos_client_demo
    PRIVATE
        kerberos_client
        -lresolv
)

# Installation rules
install(TARGETS kerberos_client
    EXPORT kerberos_client-targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

install(DIRECTORY include/kerberos
    DESTINATION include
) 
