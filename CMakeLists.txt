cmake_minimum_required(VERSION 3.23)

project(lemac_naito_benchmark LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# === 关键修改 1: 强制设置为 Release 模式 ===
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# === 关键修改 2: 显式添加优化参数 (双重保险) ===
add_compile_options(-O3 -DNDEBUG) 
# -O3: 最高级代码优化
# -DNDEBUG: 禁用 assert() 断言 (lemac 源码里有很多 assert，如果不关掉会严重拖慢速度)

add_compile_definitions(LEMAC_ARCH_IS_ARM64=1)

# 创建库
add_library(lemac_core
    include/lemac.h
    include/naito_arm64.h
    src/impl_interface.h
    src/lemac.cpp
    src/lemac_arm64_v8A.cpp
    src/lemac_arm64_v8A.h
    src/arm64_capabilities.cpp
    src/arm64_capabilities.h
    src/naito_arm64.cpp
)

target_include_directories(lemac_core PUBLIC include src)

# 针对 ARM 平台开启 Crypto 扩展
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # === 关键修改 3: 确保架构参数正确 ===
    # march=native 可以让编译器针对当前 CPU 自动开启所有支持的指令集
    target_compile_options(lemac_core PRIVATE -march=native -mtune=native)
    # 如果 native 不行，退回到明确指定: -march=armv8-a+crypto
endif()

add_executable(benchmark benchmark/benchmark.cpp)
target_link_libraries(benchmark PRIVATE lemac_core)