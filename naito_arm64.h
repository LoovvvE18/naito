#pragma once

#include <array>
#include <vector>
#include <span>
#include <cstdint>
#include <memory>
#include <string>

// 引入 ARM NEON 内建函数库，这是实现硬件加速的核心依赖
#include "arm_neon.h"

// 使用内联命名空间版本控制，防止 ABI 冲突
namespace naito::inline v1 {

// 内部实现细节命名空间，对用户隐藏
namespace arm64v8detail {

/**
 * @brief Naito 哈希算法的内部链值状态 (Chain Value)
 * 
 * 该算法是双倍块长 (Double-Block-Length) 结构，
 * 意味着它维护两个 128-bit 的状态变量 t 和 b。
 * 总状态大小为 256 bits。
 */
struct NaitoState {
  uint8x16_t t; // Top part of chain value (高位链值)
  uint8x16_t b; // Bottom part of chain value (低位链值)
};

/**
 * @brief 域分离常数 (Domain Separation Constants)
 * 
 * 用于区分压缩函数的分支和终结函数的分支。
 * 对应论文定义中的 [1]_n, [2]_n, [3]_n。
 */
struct Constants {
    // 在 cpp 文件中定义，避免 ODR (One Definition Rule) 违规
    static const uint8x16_t C1; // 用于压缩函数
    static const uint8x16_t C2; // 用于终结函数输出高位
    static const uint8x16_t C3; // 用于终结函数输出低位
};

} // namespace arm64v8detail

/**
 * @brief Naito 哈希算法 (基于 AES-256 的双倍块长哈希)
 * 
 * **算法结构**:
 * 1. **压缩函数 (Compression)**: 
 *    CF(t, b, m) -> (E(K, t), E(K, t ^ 1))，其中 K = m || b。
 *    这是一个无前馈 (Feed-Forwardless) 的 Hirose 变体结构。
 * 
 * 2. **终结函数 (Finalization)**:
 *    g(t, b) -> E(K_final, 2) || E(K_final, 3)，其中 K_final = t || b。
 *    通过加密常数来保证不可逆性。
 * 
 * **硬件加速**:
 * 使用 ARMv8 Crypto Extensions (AES + NEON) 进行指令级并行加速。
 */
class NaitoHashArm64 final {
public:
  // 定义块大小为 16 字节 (128 bits)，对应 AES 的块长
  static constexpr std::size_t block_size = 16;
  
  // 定义摘要输出大小为 32 字节 (256 bits)，实现两倍于 AES 块长的安全性
  static constexpr std::size_t digest_size = 32;

  // 构造函数：初始化内部状态
  NaitoHashArm64() noexcept;

  // 支持默认的拷贝和移动语义
  NaitoHashArm64(const NaitoHashArm64&) = default;
  NaitoHashArm64(NaitoHashArm64&&) = default;
  NaitoHashArm64& operator=(const NaitoHashArm64&) = default;
  NaitoHashArm64& operator=(NaitoHashArm64&&) = default;

  /**
   * @brief 更新哈希状态
   * 
   * 处理输入的任意长度数据。如果数据长度不是块大小的倍数，
   * 剩余部分将暂存在内部缓冲区 m_buf 中。
   * 
   * @param data 输入数据的视图 (std::span 避免了不必要的拷贝)
   */
  void update(std::span<const uint8_t> data) noexcept;

  /**
   * @brief 结束哈希计算并输出结果
   * 
   * 1. 填充
   * 2. 处理最后一个填充块。
   * 3. 执行终结函数生成最终摘要。
   * 
   * @param target 用于写入 32 字节哈希值的缓冲区
   */
  void finalize_to(std::span<uint8_t, digest_size> target) noexcept;

  /**
   * @brief 一次性计算哈希 (便捷函数)
   * 
   * 等价于：reset() -> update() -> finalize_to()
   */
  std::array<uint8_t, digest_size>
  oneshot(std::span<const uint8_t> data) const noexcept;

  // 重置状态为初始值 (t=0, b=0)，以便复用对象
  void reset() noexcept;

private:
  // 核心状态变量 (t, b)
  arm64v8detail::NaitoState m_state;

  // 内部缓冲区：用于暂存未满 16 字节的数据片段
  std::array<std::uint8_t, block_size> m_buf{};
  
  // 当前缓冲区已使用的字节数
  std::size_t m_bufsize{};
};

// 工厂函数：创建哈希实例
std::unique_ptr<NaitoHashArm64> make_naito_hash();

} // namespace naito::inline v1