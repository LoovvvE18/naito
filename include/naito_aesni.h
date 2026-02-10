#pragma once

// 只有在 x86 平台下才编译此内容
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <array>
#include <cstdint>
#include <memory>
#include <span>

// x86 AES-NI intrinsics
#include <immintrin.h>

namespace naito::inline v1 {

// internal detail namespace
namespace aesnidetail {

struct NaitoState {
  __m128i t;
  __m128i b;
};

struct Constants {
  static const __m128i C1;
  static const __m128i C2;
  static const __m128i C3;
};

} // namespace aesnidetail

class NaitoHashAesni final {
public:
  static constexpr std::size_t block_size = 16;
  static constexpr std::size_t digest_size = 32;

  NaitoHashAesni() noexcept;

  NaitoHashAesni(const NaitoHashAesni&) = default;
  NaitoHashAesni(NaitoHashAesni&&) = default;
  NaitoHashAesni& operator=(const NaitoHashAesni&) = default;
  NaitoHashAesni& operator=(NaitoHashAesni&&) = default;

  void update(std::span<const std::uint8_t> data) noexcept;
  void finalize_to(std::span<std::uint8_t, digest_size> target) noexcept;

  std::array<std::uint8_t, digest_size>
  oneshot(std::span<const std::uint8_t> data) const noexcept;

  void reset() noexcept;

private:
  aesnidetail::NaitoState m_state;
  std::array<std::uint8_t, block_size> m_buf{};
  std::size_t m_bufsize{};
};

std::unique_ptr<NaitoHashAesni> make_naito_hash_aesni();

} // namespace naito::inline v1
#endif