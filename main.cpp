#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <array>
#include <span>
#include <cstdint>

#include "naito_arm64.h"
#include "naito_aesni.h"

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#include <intrin.h>
#elif (defined(__x86_64__) || defined(__i386__)) && !defined(_MSC_VER)
#include <cpuid.h>
#endif

namespace {

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
bool has_aesni() {
    int info[4];
    __cpuid(info, 1);
    return (info[2] & (1 << 25)) != 0; // ECX bit 25 = AES
}
#elif (defined(__x86_64__) || defined(__i386__)) && !defined(_MSC_VER)
bool has_aesni() {
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return false;
    }
    return (ecx & bit_AES) != 0;
}
#else
bool has_aesni() { return false; }
#endif

} // namespace

int main() {
    using namespace naito;

    std::vector<std::string> messages = {
        "This is a test message for Naito Hash Algorithm.",
        "This is a test message for Naito Hash Algorithm.",
        "Another message to hash using Naito Hash.",
        "Yet another message for testing Naito Hash.",
        "Short msg.",
        "",
        "A very long message string to see how the Naito Hash handles larger inputs that might span multiple blocks in the internal processing logic of the algorithm.",
        "1234567890",
        "!@#$%^&*()_+"
    };

    auto run_tests = [&](auto& hasher) {
        for (size_t i = 0; i < messages.size(); ++i) {
            auto data = std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(messages[i].data()),
                messages[i].size());

            auto digest = hasher.oneshot(data);

            std::cout << "Message" << (i + 1) << ": " << messages[i] << std::endl;
            std::cout << "Hash" << (i + 1) << " (Hex): ";
            for (uint8_t b : digest) {
                std::cout << std::hex << std::setw(2) << std::setfill('0')
                          << static_cast<int>(b);
            }
            std::cout << std::dec << "\n" << std::endl;
        }
    };

#if defined(__aarch64__) || defined(_M_ARM64)
    std::cout << "[naito] detected ARM64, using NaitoHashArm64\n";
    NaitoHashArm64 hasher;
    run_tests(hasher);

#elif defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    if (has_aesni()) {
        std::cout << "[naito] detected x86 with AES-NI, using NaitoHashAesni\n";
        NaitoHashAesni hasher;
        run_tests(hasher);
    } else {
        std::cerr << "[naito] x86 CPU without AES-NI is not supported.\n";
        return 1;
    }

#else
    std::cerr << "[naito] unsupported architecture.\n";
    return 1;
#endif

    return 0;
}