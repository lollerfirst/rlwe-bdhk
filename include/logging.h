#ifndef LOGGING_H
#define LOGGING_H

#include <iostream>
#include <string>
#include <sstream>
#include <vector>

class Logger {
public:
    static bool enable_logging;
    static std::ostream* out;

    static void log(const std::string& message) {
        if (enable_logging && out) {
            *out << message << std::endl;
        }
    }

    template<typename T>
    static std::string vectorToString(const std::vector<T>& vec, const std::string& prefix = "") {
        std::stringstream ss;
        ss << prefix << "[";
        for (size_t i = 0; i < vec.size(); ++i) {
            if (i > 0) ss << ", ";
            ss << vec[i];
        }
        ss << "]";
        return ss.str();
    }

    static void setOutputStream(std::ostream& stream) {
        out = &stream;
    }
};

// Initialize static members
inline bool Logger::enable_logging = false;
inline std::ostream* Logger::out = &std::cout;

#endif // LOGGING_H
