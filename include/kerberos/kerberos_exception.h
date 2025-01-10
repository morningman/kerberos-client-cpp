#pragma once

#include <stdexcept>
#include <string>

namespace kerberos {

class KerberosException : public std::runtime_error {
public:
    explicit KerberosException(const std::string& message) 
        : std::runtime_error(message) {}
    
    explicit KerberosException(const char* message) 
        : std::runtime_error(message) {}
};

} // namespace kerberos 