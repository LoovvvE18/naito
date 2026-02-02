/*
 * Based on the benchmark from: https://github.com/pauldreik/lemac
 * Adapted for Naito Hash (AES-based DBL)
 */
#include <chrono>
#include <cstdio>
#include <string>
#include <vector>
#include <array>
#include <iostream>

// 引入 Naito 的头文件
#include "naito_arm64.h"

enum class Strategy { update_and_finalize, oneshot };

std::string_view to_string(Strategy s) {
  using enum Strategy;
  switch (s) {
  case update_and_finalize:
    return "update_and_finalize";
  case oneshot:
    return "oneshot";
  default:
    throw std::runtime_error("oops, did not recognize strategy");
  }
}

struct options {
  Strategy strategy{Strategy::update_and_finalize};
  std::size_t hashsize{123}; // 默认数据大小
  std::chrono::nanoseconds runlength{std::chrono::seconds{1}}; // 运行时间
};

struct results {
  std::size_t total_data_bytes{};
  std::size_t total_iterations{};
  std::chrono::duration<double> elapsed{};
  
  ///@return data speed in byte/s
  double data_rate() const { return total_data_bytes / elapsed.count(); }
  ///@return hash rate in hashes per second
  double hash_rate() const { return elapsed.count() / total_iterations; }
  
  // 防止编译器优化掉计算过程
  int dummy;
};

results hash(const options& opt) {
  // 1. 实例化 Naito 哈希对象
  naito::NaitoHashArm64 hasher;

  // 准备输入数据
  std::vector<std::uint8_t> data(opt.hashsize);

  // 2. 适配 Naito 的接口：
  // - 输出大小为 digest_size (32字节)
  // - 不需要 nonce
  std::array<std::uint8_t, naito::NaitoHashArm64::digest_size> out;

  results ret{};
  std::size_t iterations = 2;
  
  const auto t0 = std::chrono::steady_clock::now();
  const auto deadline = t0 + opt.runlength;
  
  // 动态调整迭代次数的循环
  while (std::chrono::steady_clock::now() < deadline) {
    for (std::size_t i = 0; i < iterations; ++i) {
      hasher.reset();
      switch (opt.strategy) {
      case Strategy::update_and_finalize:
        hasher.update(data);
        // Naito 的 finalize_to 不需要 nonce
        hasher.finalize_to(out);
        break;
      case Strategy::oneshot:
        // Naito 的 oneshot 不需要 nonce
        out = hasher.oneshot(data);
        break;
      }
      // 防止优化：使用结果的第一个字节
      ret.dummy = out[0];
    }
    ret.total_iterations += iterations;
    iterations = iterations * 3 / 2; // 增加迭代次数以逼近 deadline
  }
  const auto t1 = std::chrono::steady_clock::now();
  
  ret.elapsed = t1 - t0;
  ret.total_data_bytes = ret.total_iterations * opt.hashsize;
  
  return ret;
}

void run_testcase(const options& opt) {
  const auto speed = hash(opt);
  std::printf("Naito | %7ld byte | %20s: ",
              static_cast<long>(opt.hashsize),
              std::string{to_string(opt.strategy)}.c_str());
  std::printf("%6.3f GiB/s %6.3f µs/hash\n",
              speed.data_rate() * 1e-9, speed.hash_rate() * 1e6);
}

auto get_compiler() {
#if defined(__clang__)
  return "clang";
#elif defined(__GNUC__)
  return "gcc";
#elif defined(_MSC_VER)
  return "msvc";
#else
  return "unknown";
#endif
}

void run_all() {
  options opt{};
  
  // 测试两种策略
  for (auto strat : {Strategy::update_and_finalize, Strategy::oneshot}) {
    opt.strategy = strat;
    std::cout << "--- Strategy: " << to_string(strat) << " ---\n";
    
    // 测试不同数据大小 (从1字节到1MB)
    for (auto size : {1, 1024, 16 * 1024, 256 * 1024, 1024 * 1024}) {
      opt.hashsize = size;
      run_testcase(opt);
    }
    std::cout << "\n";
  }
}

int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[]) {
  std::printf("Benchmark for NaitoHashArm64\n");
  std::printf("Compiler: %s\n", get_compiler());
  std::printf("Digest Size: %zu bytes\n", naito::NaitoHashArm64::digest_size);
  std::printf("------------------------------------------------------------\n");
  run_all();
}