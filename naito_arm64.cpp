#include "naito_arm64.h"

#include <bit>
#include <cassert>
#include <cstring>
#include <iostream>
#include <cstdio>
#include <algorithm>

namespace naito::inline v1 {

namespace arm64v8detail {
    
    // ----------------------------------------------------------------------
    // 常数初始化逻辑
    // ----------------------------------------------------------------------
    
    // 辅助函数：构造只有最后一个字节为 val 的 128 位向量
    // 例如 make_const(1) 生成: 00 00 ... 01 (大端序数值 1)
    static const uint8x16_t make_const(uint8_t val) {
        std::array<uint8_t, 16> arr{};
        // 在内存的最后一个字节写入值，这在加载到寄存器后对应数学上的整数值
        arr[15] = val; 
        return vld1q_u8(arr.data());
    }

    // 初始化域分离常数
    const uint8x16_t Constants::C1 = make_const(1);
    const uint8x16_t Constants::C2 = make_const(2);
    const uint8x16_t Constants::C3 = make_const(3);
}

// 使用匿名命名空间隐藏内部辅助函数，相当于 C 语言的 static 函数
namespace {

static constexpr std::array<uint8_t, 256> sbox = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};


// 辅助宏：字旋转 (RotWord)
std::uint32_t ROTWORD(std::uint32_t x) { return std::rotl(x, 8); }

// 辅助宏：字代换 (SubWord) 使用查表法
std::uint32_t SUBWORD(std::uint32_t x) {
  return ((sbox[x >> 0 & 0xFF]) << 0) | ((sbox[x >> 8 & 0xFF]) << 8) |
         ((sbox[x >> 16 & 0xFF]) << 16) | ((sbox[x >> 24 & 0xFF]) << 24);
}

// ==========================================
// 2. AES-256 核心逻辑 (NEON 加速)
// ==========================================

/**
 * @brief AES-256 密钥扩展算法 (Key Schedule)
 * 
 * 将 256 位的输入密钥 (K0, K1) 扩展为 15 个 128 位的轮密钥。
 * 注意：由于 Naito 算法每一轮压缩都会改变密钥，因此这里是性能热点。
 * 
 * @param K0 密钥的前 128 位
 * @param K1 密钥的后 128 位
 * @param roundkeys 输出参数，存储 15 个轮密钥
 */
void AES256_keyschedule(const uint8x16_t K0, const uint8x16_t K1,
                        std::span<uint8x16_t, 15> roundkeys) {
  
  constexpr auto Nk = 8; // 256位密钥包含 8 个 32位字
  constexpr auto R = 15; // AES-256 需要 14 轮加密，共 15 个子密钥
  
  // 将 NEON 向量转换为 32 位整数视图，方便字操作
  const auto K0_le = vreinterpretq_u32_u8(vrev32q_u8(K0));
  const auto K1_le = vreinterpretq_u32_u8(vrev32q_u8(K1));

  // 轮常数 (Round Constants)
  static constexpr std::array<std::uint8_t, 11> Rcon{
      0x0, 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

  // 临时缓冲区 W，存储扩展后的字
  std::array<std::uint32_t, 4 * R> W;

  // 1. 初始化前 8 个字 (直接来自主密钥)
  for (int i = 0; i < 4 * R; ++i) {
        std::uint32_t& Wi = W[i];
        if (i == 0) Wi = vgetq_lane_u32(K0_le, 0);
        else if (i == 1) Wi = vgetq_lane_u32(K0_le, 1);
        else if (i == 2) Wi = vgetq_lane_u32(K0_le, 2);
        else if (i == 3) Wi = vgetq_lane_u32(K0_le, 3);
        else if (i == 4) Wi = vgetq_lane_u32(K1_le, 0);
        else if (i == 5) Wi = vgetq_lane_u32(K1_le, 1);
        else if (i == 6) Wi = vgetq_lane_u32(K1_le, 2);
        else if (i == 7) Wi = vgetq_lane_u32(K1_le, 3);
        else {
            auto temp = W[i - 1];
            if (i % Nk == 0) {
                const auto after_rotword = ROTWORD(temp);
                const auto after_subword = SUBWORD(after_rotword);
                const auto after_rcon = after_subword ^ (Rcon[i / Nk] << 24);
                temp = after_rcon;
            } else if (i % Nk == 4) {
                temp = SUBWORD(temp);
            }
            Wi = W[i - Nk] ^ temp;
        }
    }

  // 3. 将生成的字重组为 NEON 向量
  for (int i = 0; i < 4 * R; i += 4) {
    // vld1q_u8 加载数据，vrev32q_u8 处理端序问题
    roundkeys[i / 4] =vrev32q_u8(vld1q_u8(reinterpret_cast<const std::uint8_t*>(&W[i])));
  }
}

// AES-256 加密单块
uint8x16_t AES256_encrypt(std::span<const uint8x16_t, 15> roundkeys, uint8x16_t x) {
    // 轮 1-13
    for (int round = 1; round < 14; ++round) {
        x = vaeseq_u8(x, roundkeys[round - 1]);
        x = vaesmcq_u8(x);
    }
    // 最后一轮
    x = vaeseq_u8(x, roundkeys[13]);
    x = veorq_u8(x, roundkeys[14]);
    return x;
}

// ==========================================
// 3. Naito 哈希特定逻辑
// ==========================================

/**
 * @brief 压缩函数 (Compression Function)
 * 
 * 逻辑：
 * 1. 使用当前消息块 M 和低位链值 b 构造 256 位密钥 K。
 * 2. 分支 1：加密高位链值 t。
 * 3. 分支 2：加密 (t ^ C1)。
 * 
 * @param state 当前的链值状态 (t, b)，将被原地更新
 * @param M 当前输入的消息块 (128-bit)
 */
void compress_block(arm64v8detail::NaitoState& state, const uint8x16_t M) {
    using namespace arm64v8detail;

    // 1. 构造密钥 K = M || b
    // K0 取自消息 M，K1 取自上一轮的 b
    uint8x16_t K0 = M;
    uint8x16_t K1 = state.b;

    // 2. 扩展密钥 (这是最耗时的步骤)
    // 每次压缩都必须重新生成轮密钥，因为 Key 随消息变化
    uint8x16_t roundkeys[15];
    AES256_keyschedule(K0, K1, roundkeys);

    // 3. 计算分支 1: next_t = AES_Encrypt(Key, t)
    uint8x16_t next_t = AES256_encrypt(roundkeys, state.t);

    // 4. 计算分支 2: next_b = AES_Encrypt(Key, t ^ C1)
    // veorq_u8: 向量异或指令 (Vector XOR)
    uint8x16_t t_xor_c1 = veorq_u8(state.t, Constants::C1);
    uint8x16_t next_b = AES256_encrypt(roundkeys, t_xor_c1);

    // 5. 更新状态
    state.t = next_t;
    state.b = next_b;
}

/**
 * @brief 终结函数 (Finalization Function)
 * 
 * 逻辑：
 * 1. 使用最终状态 (t || b) 作为 AES 密钥。
 * 2. 加密常数 C2 得到高位输出。
 * 3. 加密常数 C3 得到低位输出。
 * 
 * @param state 最终的链值状态
 * @param target 输出缓冲区
 */
void finalize_state(const arm64v8detail::NaitoState& state, std::span<uint8_t, 32> target) {
    using namespace arm64v8detail;

    // 1. 构造密钥 K = t || b
    uint8x16_t K0 = state.t;
    uint8x16_t K1 = state.b;

    uint8x16_t roundkeys[15];
    AES256_keyschedule(K0, K1, roundkeys);

    // 2. 计算输出高位: h1 = AES_Encrypt(K, C2)
    uint8x16_t h1 = AES256_encrypt(roundkeys, Constants::C2);

    // 3. 计算输出低位: h2 = AES_Encrypt(K, C3)
    uint8x16_t h2 = AES256_encrypt(roundkeys, Constants::C3);

    // 4. 存储结果到内存
    // vst1q_u8: 将 NEON 寄存器内容存储到内存
    vst1q_u8(target.data(), h1);
    vst1q_u8(target.data() + 16, h2);
}

} // anonymous namespace

// ==========================================
// 4. 类成员函数实现
// ==========================================

NaitoHashArm64::NaitoHashArm64() noexcept {
    reset();
}

void NaitoHashArm64::reset() noexcept {
    // 初始化状态为全零向量
    // vdupq_n_u8(0): 将向量所有 lane 设为 0
    m_state.t = vdupq_n_u8(0);
    m_state.b = vdupq_n_u8(0);
    m_bufsize = 0;
    std::fill(m_buf.begin(), m_buf.end(), 0);
}

std::unique_ptr<NaitoHashArm64> make_naito_hash() {
    return std::make_unique<NaitoHashArm64>();
}

std::array<uint8_t, NaitoHashArm64::digest_size> 
NaitoHashArm64::oneshot(std::span<const uint8_t> data) const noexcept {
    // 创建当前对象的副本以保证 const 语义 (不修改自身状态)
    auto copy = *this;
    copy.reset();
    copy.update(data);
    std::array<uint8_t, digest_size> ret;
    copy.finalize_to(ret);
    return ret;
}

void NaitoHashArm64::update(std::span<const uint8_t> data) noexcept {
    bool process_entire_m_buf = false;
    std::size_t remaining_to_full_block;

    // 1. 处理缓冲区中已有的数据
    if (m_bufsize != 0) {
        assert(m_bufsize < block_size);
        remaining_to_full_block = block_size - m_bufsize;
        
        // 如果输入数据不足以填满缓冲区，则直接追加并返回
        if (data.size() < remaining_to_full_block) {
            std::memcpy(&m_buf[m_bufsize], data.data(), data.size());
            m_bufsize += data.size();
            return;
        }
        // 标记缓冲区已满，需要处理
        process_entire_m_buf = true;
    }

    // 2. 如果缓冲区满了，先处理缓冲区数据
    if (process_entire_m_buf) {
        // 填满缓冲区
        std::memcpy(&m_buf[m_bufsize], data.data(), remaining_to_full_block);
        
        // 加载并压缩
        uint8x16_t M = vld1q_u8(m_buf.data());
        compress_block(m_state, M);

        // 重置缓冲区
        m_bufsize = 0;
        // 调整输入数据视图，跳过已处理部分
        data = data.subspan(remaining_to_full_block);
    }

    // 3. 直接处理输入数据中的完整块 (Zero-Copy)
    const auto whole_blocks = data.size() / block_size;
    const auto block_end = data.data() + whole_blocks * block_size;
    
    auto ptr = data.data();
    for (; ptr != block_end; ptr += block_size) {
        // 直接从输入内存加载到 NEON 寄存器
        uint8x16_t M = vld1q_u8(ptr);
        compress_block(m_state, M);
    }

    // 4. 将剩余的尾部数据存入缓冲区
    m_bufsize = data.size() - whole_blocks * block_size;
    if (m_bufsize) {
        std::memcpy(m_buf.data(), ptr, m_bufsize);
    }
}

void NaitoHashArm64::finalize_to(std::span<uint8_t, digest_size> target) noexcept {
    assert(m_bufsize < m_buf.size());

    // 应用 ISO/IEC 7816-4 Padding
    // 规则：追加一个 '0x80' 字节，后续全部填 '0x00' 直到块结束
    m_buf[m_bufsize] = 0x80;
    for (std::size_t i = m_bufsize + 1; i < m_buf.size(); ++i) {
        m_buf[i] = 0;
    }

    // 压缩最后一个包含 Padding 的块
    uint8x16_t M = vld1q_u8(m_buf.data());
    compress_block(m_state, M);

    // 执行终结函数，生成最终摘要
    finalize_state(m_state, target);
}
