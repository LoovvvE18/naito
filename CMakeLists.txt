cmake_minimum_required(VERSION 3.23)

project(lemac_naito_benchmark LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 强制 Release 模式和优化
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# 开启 O3 优化和禁用断言
add_compile_options(-O3 -DNDEBUG)

# 跳过架构检测代码
add_compile_definitions(LEMAC_ARCH_IS_ARM64=1)

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

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # === 关键修改在这里 ===
    # 删除 -march=native，改为强制指定 armv8-a+crypto
    # 这会告诉编译器：“不管你检测到什么，都给我开启 AES 和 SHA 指令支持”
    target_compile_options(lemac_core PRIVATE -march=armv8-a+crypto)
endif()

add_executable(benchmark benchmark/benchmark.cpp)
target_link_libraries(benchmark PRIVATE lemac_core)