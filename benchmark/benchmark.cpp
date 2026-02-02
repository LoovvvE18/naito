#include <chrono>
#include <cstdio>
#include <string>
#include <vector>
#include <array>
#include <type_traits> 
#include <cstring>

#include <lemac.h>
#include <naito_arm64.h>

enum class Strategy { update_and_finalize, oneshot };

std::string_view to_string(Strategy s) {
  using enum Strategy;
  switch (s) {
  case update_and_finalize: return "update_and_finalize";
  case oneshot: return "oneshot";
  default: throw std::runtime_error("unknown strategy");
  }
}

struct options {
  Strategy strategy{Strategy::update_and_finalize};
  std::size_t hashsize{123};
  std::chrono::nanoseconds runlength{std::chrono::seconds{1}};
};

struct results {
  std::size_t total_data_bytes{};
  std::size_t total_iterations{};
  std::chrono::duration<double> elapsed{};
  double data_rate() const { return total_data_bytes / elapsed.count(); }
  double hash_rate() const { return elapsed.count() / total_iterations; }
  volatile int dummy; // volatile 防止优化
};

template <typename Hasher>
results run_hash_loop(const options& opt) {
  Hasher hasher;
  std::vector<std::uint8_t> data(opt.hashsize);
  std::array<std::uint8_t, 32> out; // 足够大以容纳 naito (32) 和 lemac (16)
  std::array<std::uint8_t, 16> nonce{};
  
  results ret{};
  std::size_t iterations = 1000; // 初始迭代次数稍微给大一点
  
  const auto t0 = std::chrono::steady_clock::now();
  const auto deadline = t0 + opt.runlength;
  
  while (std::chrono::steady_clock::now() < deadline) {
    for (std::size_t i = 0; i < iterations; ++i) {
      hasher.reset();
      
      if (opt.strategy == Strategy::update_and_finalize) {
          hasher.update(data);
          if constexpr (std::is_same_v<Hasher, lemac::LeMac>) {
              std::span<std::uint8_t, 16> target(out.data(), 16);
              hasher.finalize_to(nonce, target);
          } else {
              std::span<std::uint8_t, 32> target(out.data(), 32);
              hasher.finalize_to(target);
          }
      } else { // oneshot
          if constexpr (std::is_same_v<Hasher, lemac::LeMac>) {
               auto res = hasher.oneshot(data, nonce);
               std::memcpy(out.data(), res.data(), 16);
          } else {
               auto res = hasher.oneshot(data);
               std::memcpy(out.data(), res.data(), 32);
          }
      }
      nonce[0] = out[0]; // 简单的依赖链防止优化
    }
    ret.total_iterations += iterations;
    // 动态调整迭代次数，避免检查时间太频繁
    if(ret.total_iterations < 1000000) iterations *= 2; 
  }
  
  const auto t1 = std::chrono::steady_clock::now();
  ret.elapsed = t1 - t0;
  ret.total_data_bytes = ret.total_iterations * opt.hashsize;
  ret.dummy = out[0];
  return ret;
}

template <typename Hasher>
void run_testcase(const options& opt, const char* name) {
  const auto speed = run_hash_loop<Hasher>(opt);
  std::printf("[%s] %7ld bytes | %s: %6.3f GiB/s  %6.3f µs/hash\n",
              name,
              static_cast<long>(opt.hashsize),
              std::string{to_string(opt.strategy)}.c_str(),
              speed.data_rate() * 1e-9, 
              speed.hash_rate() * 1e6);
}

void run_all() {
  options opt{};
  auto sizes = {64, 1024, 16 * 1024, 1024 * 1024}; // 测试不同数据包大小
  
  for (auto strat : {Strategy::update_and_finalize, Strategy::oneshot}) {
    opt.strategy = strat;
    std::printf("\n--- Strategy: %s ---\n", std::string{to_string(strat)}.c_str());
    for (auto size : sizes) {
      opt.hashsize = size;
      run_testcase<lemac::LeMac>(opt, "LeMac");
      run_testcase<naito::NaitoHashArm64>(opt, "Naito");
    }
  }
}

int main() {
  run_all();
  return 0;
}