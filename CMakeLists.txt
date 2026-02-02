cmake_minimum_required(VERSION 3.23)

project(lemac_naito_benchmark LANGUAGES CXX)

# 强制使用 C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 强制定义宏，跳过代码中的架构检测逻辑
add_compile_definitions(LEMAC_ARCH_IS_ARM64=1)

# 创建库
add_library(lemac_core
    # 接口
    include/lemac.h
    include/naito_arm64.h
    src/impl_interface.h
    # 实现
    src/lemac.cpp
    src/lemac_arm64_v8A.cpp
    src/lemac_arm64_v8A.h
    src/arm64_capabilities.cpp
    src/arm64_capabilities.h
    src/naito_arm64.cpp
)

# 指定头文件包含路径
target_include_directories(lemac_core PUBLIC include src)

# 针对 ARM 平台开启 Crypto 扩展
# 注意：如果在苹果 M1/M2/M3 上，通常不需要额外 flag 或只需 -march=armv8-a+crypto
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(lemac_core PRIVATE -march=armv8-a+crypto)
endif()

# 创建 benchmark 可执行文件
add_executable(benchmark benchmark/benchmark.cpp)

# 链接库
target_link_libraries(benchmark PRIVATE lemac_core)