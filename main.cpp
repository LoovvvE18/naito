#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include "naito_arm64.h"

int main() {
    using namespace naito;

    // 1. 初始化哈希实例
    NaitoHashArm64 hasher;
    
    // 2. 准备测试数据
    std::vector<std::string> messages = {
        "This is a test message for Naito Hash Algorithm.",
        "This is a test message for Naito Hash Algorithm.",
        "Another message to hash using Naito Hash.",
        "Yet another message for testing Naito Hash.",
        "Short msg.",
        "", // Empty string test
        "A very long message string to see how the Naito Hash handles larger inputs that might span multiple blocks in the internal processing logic of the algorithm.",
        "1234567890",
        "!@#$%^&*()_+"
    };
    
    // 3. 计算并打印哈希结果
    for (size_t i = 0; i < messages.size(); ++i) {
        auto digest = hasher.oneshot({reinterpret_cast<const uint8_t*>(messages[i].data()), messages[i].size()});
        
        std::cout << "Message" << (i + 1) << ": " << messages[i] << std::endl;
        std::cout << "Hash" << (i + 1) << " (Hex): ";
        for (uint8_t b : digest) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        std::cout << std::dec << "\n" << std::endl;
    }

    return 0;
}