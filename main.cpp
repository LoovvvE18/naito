#include <iostream>
#include <iomanip>
#include <string>
#include "naito_arm64.h"

int main() {
    using namespace naito;

    // 1. 初始化哈希实例
    NaitoHashArm64 hasher;
    
    // 2. 准备测试数据
    std::string message = "This is a test message for Naito Hash Algorithm.";
    
    // 3. 计算哈希
    auto digest = hasher.oneshot({reinterpret_cast<const uint8_t*>(message.data()), message.size()});

    // 4. 打印结果
    std::cout << "Message: " << message << std::endl;
    std::cout << "Hash (Hex): ";
    for (uint8_t b : digest) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    std::cout << std::dec << std::endl;

    return 0;
}