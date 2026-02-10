#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include "naito_aesni.h"

#include <array>
#include <cassert>
#include <cstring>
#include <algorithm>

namespace naito::inline v1 {

namespace aesnidetail {

// construct 128-bit constant with only last byte = val
static inline __m128i make_const(std::uint8_t val) {
  alignas(16) std::array<std::uint8_t, 16> tmp{};
  tmp[15] = val;
  return _mm_loadu_si128(reinterpret_cast<const __m128i*>(tmp.data()));
}

const __m128i Constants::C1 = make_const(1);
const __m128i Constants::C2 = make_const(2);
const __m128i Constants::C3 = make_const(3);

} // namespace aesnidetail

namespace {

// AES-256 key expansion helpers (AES-NI style)
static inline __m128i aes256_keyassist1(__m128i a, __m128i b) {
  b = _mm_shuffle_epi32(b, 0xff);
  __m128i c = _mm_slli_si128(a, 0x4);
  a = _mm_xor_si128(a, c);
  c = _mm_slli_si128(c, 0x4);
  a = _mm_xor_si128(a, c);
  c = _mm_slli_si128(c, 0x4);
  a = _mm_xor_si128(a, c);
  a = _mm_xor_si128(a, b);
  return a;
}

static inline __m128i aes256_keyassist2(__m128i a, __m128i b) {
  b = _mm_shuffle_epi32(b, 0xaa);
  __m128i c = _mm_slli_si128(a, 0x4);
  a = _mm_xor_si128(a, c);
  c = _mm_slli_si128(c, 0x4);
  a = _mm_xor_si128(a, c);
  c = _mm_slli_si128(c, 0x4);
  a = _mm_xor_si128(a, c);
  a = _mm_xor_si128(a, b);
  return a;
}

// Expand AES-256 key into 15 roundkeys
static inline void AES256_keyschedule(__m128i K0, __m128i K1,
                                      std::span<__m128i, 15> roundkeys) {
  roundkeys[0] = K0;
  roundkeys[1] = K1;

  __m128i tmp1 = K0;
  __m128i tmp2 = K1;

  tmp2 = _mm_aeskeygenassist_si128(tmp2, 0x01);
  tmp1 = aes256_keyassist1(tmp1, tmp2);
  roundkeys[2] = tmp1;

  tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x00);
  tmp2 = aes256_keyassist2(tmp2, tmp1);
  roundkeys[3] = tmp2;

  tmp2 = _mm_aeskeygenassist_si128(tmp2, 0x02);
  tmp1 = aes256_keyassist1(tmp1, tmp2);
  roundkeys[4] = tmp1;

  tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x00);
  tmp2 = aes256_keyassist2(tmp2, tmp1);
  roundkeys[5] = tmp2;

  tmp2 = _mm_aeskeygenassist_si128(tmp2, 0x04);
  tmp1 = aes256_keyassist1(tmp1, tmp2);
  roundkeys[6] = tmp1;

  tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x00);
  tmp2 = aes256_keyassist2(tmp2, tmp1);
  roundkeys[7] = tmp2;

  tmp2 = _mm_aeskeygenassist_si128(tmp2, 0x08);
  tmp1 = aes256_keyassist1(tmp1, tmp2);
  roundkeys[8] = tmp1;

  tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x00);
  tmp2 = aes256_keyassist2(tmp2, tmp1);
  roundkeys[9] = tmp2;

  tmp2 = _mm_aeskeygenassist_si128(tmp2, 0x10);
  tmp1 = aes256_keyassist1(tmp1, tmp2);
  roundkeys[10] = tmp1;

  tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x00);
  tmp2 = aes256_keyassist2(tmp2, tmp1);
  roundkeys[11] = tmp2;

  tmp2 = _mm_aeskeygenassist_si128(tmp2, 0x20);
  tmp1 = aes256_keyassist1(tmp1, tmp2);
  roundkeys[12] = tmp1;

  tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x00);
  tmp2 = aes256_keyassist2(tmp2, tmp1);
  roundkeys[13] = tmp2;

  tmp2 = _mm_aeskeygenassist_si128(tmp2, 0x40);
  tmp1 = aes256_keyassist1(tmp1, tmp2);
  roundkeys[14] = tmp1;
}

static inline __m128i AES256_encrypt(std::span<const __m128i, 15> roundkeys,
                                     __m128i x) {
  x = _mm_xor_si128(x, roundkeys[0]);
  for (int r = 1; r < 14; ++r) {
    x = _mm_aesenc_si128(x, roundkeys[r]);
  }
  x = _mm_aesenclast_si128(x, roundkeys[14]);
  return x;
}

static inline void compress_block(aesnidetail::NaitoState& state,
                                  __m128i M) {
  using namespace aesnidetail;

  __m128i K0 = M;
  __m128i K1 = state.b;

  __m128i roundkeys[15];
  AES256_keyschedule(K0, K1, roundkeys);

  __m128i next_t = AES256_encrypt(roundkeys, state.t);
  __m128i t_xor_c1 = _mm_xor_si128(state.t, Constants::C1);
  __m128i next_b = AES256_encrypt(roundkeys, t_xor_c1);

  state.t = next_t;
  state.b = next_b;
}

static inline void finalize_state(const aesnidetail::NaitoState& state,
                                  std::span<std::uint8_t, 32> target) {
  using namespace aesnidetail;

  __m128i K0 = state.t;
  __m128i K1 = state.b;

  __m128i roundkeys[15];
  AES256_keyschedule(K0, K1, roundkeys);

  __m128i h1 = AES256_encrypt(roundkeys, Constants::C2);
  __m128i h2 = AES256_encrypt(roundkeys, Constants::C3);

  _mm_storeu_si128(reinterpret_cast<__m128i*>(target.data()), h1);
  _mm_storeu_si128(reinterpret_cast<__m128i*>(target.data() + 16), h2);
}

} // namespace

NaitoHashAesni::NaitoHashAesni() noexcept {
  reset();
}

void NaitoHashAesni::reset() noexcept {
  m_state.t = _mm_setzero_si128();
  m_state.b = _mm_setzero_si128();
  m_bufsize = 0;
  std::fill(m_buf.begin(), m_buf.end(), 0);
}

std::unique_ptr<NaitoHashAesni> make_naito_hash_aesni() {
  return std::make_unique<NaitoHashAesni>();
}

std::array<std::uint8_t, NaitoHashAesni::digest_size>
NaitoHashAesni::oneshot(std::span<const std::uint8_t> data) const noexcept {
  auto copy = *this;
  copy.reset();
  copy.update(data);
  std::array<std::uint8_t, digest_size> ret;
  copy.finalize_to(ret);
  return ret;
}

void NaitoHashAesni::update(std::span<const std::uint8_t> data) noexcept {
  bool process_entire_m_buf = false;
  std::size_t remaining_to_full_block;

  if (m_bufsize != 0) {
    assert(m_bufsize < block_size);
    remaining_to_full_block = block_size - m_bufsize;

    if (data.size() < remaining_to_full_block) {
      std::memcpy(&m_buf[m_bufsize], data.data(), data.size());
      m_bufsize += data.size();
      return;
    }
    process_entire_m_buf = true;
  }

  if (process_entire_m_buf) {
    std::memcpy(&m_buf[m_bufsize], data.data(), remaining_to_full_block);
    __m128i M = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_buf.data()));
    compress_block(m_state, M);

    m_bufsize = 0;
    data = data.subspan(remaining_to_full_block);
  }

  const auto whole_blocks = data.size() / block_size;
  const auto block_end = data.data() + whole_blocks * block_size;

  auto ptr = data.data();
  for (; ptr != block_end; ptr += block_size) {
    __m128i M = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ptr));
    compress_block(m_state, M);
  }

  m_bufsize = data.size() - whole_blocks * block_size;
  if (m_bufsize) {
    std::memcpy(m_buf.data(), ptr, m_bufsize);
  }
}

void NaitoHashAesni::finalize_to(
    std::span<std::uint8_t, digest_size> target) noexcept {
  assert(m_bufsize < m_buf.size());

  for (std::size_t i = m_bufsize; i < m_buf.size(); ++i) {
    m_buf[i] = 0;
  }

  __m128i M = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_buf.data()));
  compress_block(m_state, M);

  finalize_state(m_state, target);
}

} // namespace naito::inline v1