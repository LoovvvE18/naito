#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
/**
 * @file naito_aesni.cpp
 * @brief 使用 x86 AES-NI 指令集实现的 Naito 哈希算法。
 * 
 * 该实现利用硬件加速的 AES 指令来实现高性能的哈希运算。
 * 主要用于支持 AES-NI 的现代 x86_64 处理器。
 */
#include "naito_aesni.h"

#include <array>
#include <cassert>
#include <cstring>
#include <algorithm>

namespace naito::inline v1 {

namespace aesnidetail {

/**
 * @brief 构造一个 128 位的常量，其中仅最后一个字节为指定值。
 * 
 * @param val 要设置在最后一个字节的值。
 * @return __m128i 包含该值的 128 位向量。
 */
static inline __m128i make_const(std::uint8_t val) {
  alignas(16) std::array<std::uint8_t, 16> tmp{};
  tmp[15] = val;
  return _mm_loadu_si128(reinterpret_cast<const __m128i*>(tmp.data()));
}

// 算法中使用的域常量
const __m128i Constants::C1 = make_const(1);
const __m128i Constants::C2 = make_const(2);
const __m128i Constants::C3 = make_const(3);

} // namespace aesnidetail

namespace {

/**
 * @brief AES-256 密钥扩展辅助函数 1。
 * 处理偶数索引路径的密钥扩展。
 * 
 * @param a 前一个子密钥部分。
 * @param b 经过 _mm_aeskeygenassist_si128 处理后的部分。
 * @return __m128i 生成的新子密钥。
 */
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

/**
 * @brief AES-256 密钥扩展辅助函数 2。
 * 处理奇数索引路径的密钥扩展（针对 AES-256 特有的 S-box 变换）。
 * 
 * @param a 前一个子密钥部分。
 * @param b 经过 _mm_aeskeygenassist_si128 处理后的部分。
 * @return __m128i 生成的新子密钥。
 */
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

/**
 * @brief 将 AES-256 原始密钥扩展为 15 个轮密钥。
 * 
 * AES-256 包含 14 轮加密，因此需要 15 个轮密钥（包括初始 Xor）。
 * 
 * @param K0 原始密钥的前 128 位。
 * @param K1 原始密钥的后 128 位。
 * @param roundkeys 存储 15 个扩展轮密钥的缓冲区。
 */
static inline void AES256_keyschedule(__m128i K0, __m128i K1,
                                      std::span<__m128i, 15> roundkeys) {
  roundkeys[0] = K0;
  roundkeys[1] = K1;

  __m128i tmp1 = K0;
  __m128i tmp2 = K1;

  // 密钥轮 1 & 2
  tmp2 = _mm_aeskeygenassist_si128(tmp2, 0x01);
  tmp1 = aes256_keyassist1(tmp1, tmp2);
  roundkeys[2] = tmp1;

  tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x00);
  tmp2 = aes256_keyassist2(tmp2, tmp1);
  roundkeys[3] = tmp2;

  // 密钥轮 3 & 4
  tmp2 = _mm_aeskeygenassist_si128(tmp2, 0x02);
  tmp1 = aes256_keyassist1(tmp1, tmp2);
  roundkeys[4] = tmp1;

  tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x00);
  tmp2 = aes256_keyassist2(tmp2, tmp1);
  roundkeys[5] = tmp2;

  // 密钥轮 5 & 6
  tmp2 = _mm_aeskeygenassist_si128(tmp2, 0x04);
  tmp1 = aes256_keyassist1(tmp1, tmp2);
  roundkeys[6] = tmp1;

  tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x00);
  tmp2 = aes256_keyassist2(tmp2, tmp1);
  roundkeys[7] = tmp2;

  // 密钥轮 7 & 8
  tmp2 = _mm_aeskeygenassist_si128(tmp2, 0x08);
  tmp1 = aes256_keyassist1(tmp1, tmp2);
  roundkeys[8] = tmp1;

  tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x00);
  tmp2 = aes256_keyassist2(tmp2, tmp1);
  roundkeys[9] = tmp2;

  // 密钥轮 9 & 10
  tmp2 = _mm_aeskeygenassist_si128(tmp2, 0x10);
  tmp1 = aes256_keyassist1(tmp1, tmp2);
  roundkeys[10] = tmp1;

  tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x00);
  tmp2 = aes256_keyassist2(tmp2, tmp1);
  roundkeys[11] = tmp2;

  // 密钥轮 11 & 12
  tmp2 = _mm_aeskeygenassist_si128(tmp2, 0x20);
  tmp1 = aes256_keyassist1(tmp1, tmp2);
  roundkeys[12] = tmp1;

  tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x00);
  tmp2 = aes256_keyassist2(tmp2, tmp1);
  roundkeys[13] = tmp2;

  // 密钥轮 13 & 14 (最后一轮)
  tmp2 = _mm_aeskeygenassist_si128(tmp2, 0x40);
  tmp1 = aes256_keyassist1(tmp1, tmp2);
  roundkeys[14] = tmp1;
}

/**
 * @brief 执行 AES-256 加密。
 * 
 * @param roundkeys 已生成的 15 个轮密钥。
 * @param x 要加密的 128 位数据。
 * @return __m128i 加密后的数据。
 */
static inline __m128i AES256_encrypt(std::span<const __m128i, 15> roundkeys,
                                     __m128i x) {
  x = _mm_xor_si128(x, roundkeys[0]); // 初始轮密钥加
  for (int r = 1; r < 14; ++r) {
    x = _mm_aesenc_si128(x, roundkeys[r]); // 中间轮加密
  }
  x = _mm_aesenclast_si128(x, roundkeys[14]); // 最后一轮加密（不含 MixColumns）
  return x;
}

/**
 * @brief 压缩单个数据块并更新哈希状态。
 * 
 * 使用 AES-256 加密作为核心。输入块 M 作为密钥 K0，
 * 当前状态中的 b 作为密钥 K1。状态 t 被加密更新，
 * 状态 b 则被 (t XOR C1) 的加密结果更新。
 * 
 * @param state 当前哈希状态（包含 t 和 b）。
 * @param M 128 位的数据块。
 */
static inline void compress_block(aesnidetail::NaitoState& state,
                                  __m128i M) {
  using namespace aesnidetail;

  __m128i K0 = M;
  __m128i K1 = state.b;

  // 使用数据块和当前状态生成 256 位密钥的扩展轮密钥
  __m128i roundkeys[15];
  AES256_keyschedule(K0, K1, roundkeys);

  // 更新状态 t: t = E_{M,b}(t)
  __m128i next_t = AES256_encrypt(roundkeys, state.t);
  
  // 更新状态 b: b = E_{M,b}(t XOR C1)
  __m128i t_xor_c1 = _mm_xor_si128(state.t, Constants::C1);
  __m128i next_b = AES256_encrypt(roundkeys, t_xor_c1);

  state.t = next_t;
  state.b = next_b;
}

/**
 * @brief 最终化状态并生成摘要。
 * 
 * 将最终的状态 t 和 b 作为 AES-256 密钥，对常量 C2 和 C3 进行加密，
 * 结果串联形成 32 字节（256 位）的哈希结果。
 * 
 * @param state 最终计算出的内部状态。
 * @param target 存储生成的 32 字节摘要。
 */
static inline void finalize_state(const aesnidetail::NaitoState& state,
                                  std::span<std::uint8_t, 32> target) {
  using namespace aesnidetail;

  __m128i K0 = state.t;
  __m128i K1 = state.b;

  __m128i roundkeys[15];
  AES256_keyschedule(K0, K1, roundkeys);

  // 生成摘要的高 16 字节和低 16 字节
  __m128i h1 = AES256_encrypt(roundkeys, Constants::C2);
  __m128i h2 = AES256_encrypt(roundkeys, Constants::C3);

  _mm_storeu_si128(reinterpret_cast<__m128i*>(target.data()), h1);
  _mm_storeu_si128(reinterpret_cast<__m128i*>(target.data() + 16), h2);
}

} // namespace

NaitoHashAesni::NaitoHashAesni() noexcept {
  reset();
}

/**
 * @brief 重置哈希对象到初始状态。
 */
void NaitoHashAesni::reset() noexcept {
  m_state.t = _mm_setzero_si128();
  m_state.b = _mm_setzero_si128();
  m_bufsize = 0;
  std::fill(m_buf.begin(), m_buf.end(), 0);
}

/**
 * @brief 创建一个新的 NaitoHashAesni 实例的唯一指针。
 */
std::unique_ptr<NaitoHashAesni> make_naito_hash_aesni() {
  return std::make_unique<NaitoHashAesni>();
}

/**
 * @brief 一次性计算数据的哈希摘要。
 * 
 * @param data 输入数据。
 * @return std::array<std::uint8_t, digest_size> 计算出的摘要。
 */
std::array<std::uint8_t, NaitoHashAesni::digest_size>
NaitoHashAesni::oneshot(std::span<const std::uint8_t> data) const noexcept {
  auto copy = *this;
  copy.reset();
  copy.update(data);
  std::array<std::uint8_t, digest_size> ret;
  copy.finalize_to(ret);
  return ret;
}

/**
 * @brief 更新哈希状态，处理任意长度的输入数据。
 * 
 * @param data 输入的数据片段。
 */
void NaitoHashAesni::update(std::span<const std::uint8_t> data) noexcept {
  bool process_entire_m_buf = false;
  std::size_t remaining_to_full_block;

  // 处理之前剩余在缓冲区中的不完整数据块
  if (m_bufsize != 0) {
    assert(m_bufsize < block_size);
    remaining_to_full_block = block_size - m_bufsize;

    if (data.size() < remaining_to_full_block) {
      // 仍然不足一个完整块，继续填充
      std::memcpy(&m_buf[m_bufsize], data.data(), data.size());
      m_bufsize += data.size();
      return;
    }
    process_entire_m_buf = true;
  }

  // 凑成一个完整块后进行压缩
  if (process_entire_m_buf) {
    std::memcpy(&m_buf[m_bufsize], data.data(), remaining_to_full_block);
    __m128i M = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_buf.data()));
    compress_block(m_state, M);

    m_bufsize = 0;
    data = data.subspan(remaining_to_full_block);
  }

  // 批量处理大量完整数据块
  const auto whole_blocks = data.size() / block_size;
  const auto block_end = data.data() + whole_blocks * block_size;

  auto ptr = data.data();
  for (; ptr != block_end; ptr += block_size) {
    __m128i M = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ptr));
    compress_block(m_state, M);
  }

  // 将剩余数据存入缓冲区待下次处理
  m_bufsize = data.size() - whole_blocks * block_size;
  if (m_bufsize) {
    std::memcpy(m_buf.data(), ptr, m_bufsize);
  }
}

/**
 * @brief 结束哈希计算并将结果写入目标缓冲区。
 * 
 * 如果有剩余数据，会进行零填充后处理最后一块。
 * 
 * @param target 摘要写入的目标。
 */
void NaitoHashAesni::finalize_to(
    std::span<std::uint8_t, digest_size> target) noexcept {
  assert(m_bufsize < m_buf.size());

  // 简单的零填充补全最后一个 16 字节数据块
  for (std::size_t i = m_bufsize; i < m_buf.size(); ++i) {
    m_buf[i] = 0;
  }

  __m128i M = _mm_loadu_si128(reinterpret_cast<const __m128i*>(m_buf.data()));
  compress_block(m_state, M);

  // 计算并输出最终结果
  finalize_state(m_state, target);
}

} // namespace naito::inline v1
#endif