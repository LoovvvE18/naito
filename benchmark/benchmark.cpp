/*
 * Benchmark for naito hash
 *
 * Strategy:
 *  - update_and_finalize: reset() + update(data) + finalize_to(out)
 *  - oneshot: out = oneshot(data)
 *
 * Runs time-based loops (default ~1s per testcase) and reports:
 *  - throughput in GiB/s
 *  - time per hash in µs/hash
 */
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#if defined(__aarch64__) || defined(_M_ARM64)
  #include <naito_arm64.h>
  namespace naito_bench_detail {
    using Hash = naito::v1::NaitoHashArm64;
    static constexpr std::string_view impl_name = "arm64";
  }
#elif defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
  #include <naito_aesni.h>
  namespace naito_bench_detail {
    using Hash = naito::v1::NaitoHashAesni;
    static constexpr std::string_view impl_name = "aesni";
  }
#else
  #error "No supported naito backend for this architecture (need ARM64 or x86 with AES-NI code enabled)."
#endif

enum class Strategy { update_and_finalize, oneshot };

static std::string_view to_string(Strategy s) {
  switch (s) {
  case Strategy::update_and_finalize:
    return "update_and_finalize";
  case Strategy::oneshot:
    return "oneshot";
  default:
    throw std::runtime_error("unrecognized strategy");
  }
}

struct options {
  Strategy strategy{Strategy::update_and_finalize};
  std::size_t msgsize{123};
  std::chrono::nanoseconds runlength{std::chrono::seconds{1}};
};

struct results {
  std::size_t total_data_bytes{};
  std::size_t total_iterations{};
  std::chrono::duration<double> elapsed{};
  double data_rate() const { return total_data_bytes / elapsed.count(); } // B/s
  double hash_rate() const { return total_iterations / elapsed.count(); } // hashes/s
  int dummy{};
};

static results hash_one_case(const options& opt) {
  using Hash = naito_bench_detail::Hash;

  Hash h;
  std::vector<std::uint8_t> data(opt.msgsize, 0);

  // Fill data with something deterministic, to avoid “all zero” special-casing (if any)
  for (std::size_t i = 0; i < data.size(); ++i) {
    data[i] = static_cast<std::uint8_t>(i * 131u + 7u);
  }

  std::array<std::uint8_t, Hash::digest_size> out{};
  results ret{};

  std::size_t iterations = 2;
  const auto t0 = std::chrono::steady_clock::now();
  const auto deadline = t0 + opt.runlength;

  while (std::chrono::steady_clock::now() < deadline) {
    for (std::size_t i = 0; i < iterations; ++i) {
      h.reset();
      switch (opt.strategy) {
      case Strategy::update_and_finalize:
        h.update(data);
        h.finalize_to(out);
        break;
      case Strategy::oneshot:
        out = h.oneshot(data);
        break;
      }
      // prevent optimizer from removing the computation
      data[0] = out[0];
    }
    ret.total_iterations += iterations;
    iterations = iterations * 3 / 2;
  }

  const auto t1 = std::chrono::steady_clock::now();
  ret.elapsed = t1 - t0;
  ret.total_data_bytes = ret.total_iterations * opt.msgsize;
  ret.dummy = out[0];
  return ret;
}

static void run_testcase(const options& opt) {
  const auto r = hash_one_case(opt);
  std::printf("impl=%s, msg=%7ld, strat=%20s: ",
              std::string(naito_bench_detail::impl_name).c_str(),
              static_cast<long>(opt.msgsize),
              std::string(to_string(opt.strategy)).c_str());

  std::printf("%6.3f GiB/s  %6.3f µs/hash\n",
              r.data_rate() * 1e-9,
              (1.0 / r.hash_rate()) * 1e6);
}

static const char* get_compiler() {
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

static void run_all() {
  options opt{};
  for (auto strat : {Strategy::update_and_finalize, Strategy::oneshot}) {
    opt.strategy = strat;
    for (auto size : {1, 1024, 16 * 1024, 256 * 1024, 1024 * 1024}) {
      opt.msgsize = static_cast<std::size_t>(size);
      run_testcase(opt);
    }
  }
}

int main() {
  std::printf("compiler: %s\n", get_compiler());
  std::printf("naito backend: %s\n", std::string(naito_bench_detail::impl_name).c_str());
  run_all();
  return 0;
}