# benchmark/CMakeLists.txt

# 1. 定义源文件变量，方便复用
# 注意：这里假设 CMakeLists.txt 在 benchmark 目录下
# 所以 ../src 指向项目根目录的 src
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(NAITO_SOURCES 
    ../src/naito_arm64.cpp
)

# 2. 添加可执行文件
add_executable(naito_benchmark naito_benchmark.cpp ${NAITO_SOURCES})

# 3. 设置头文件包含路径
# 这样 cpp 文件里才能 #include "naito_arm64.h"
target_include_directories(naito_benchmark PRIVATE ../include)

# 4. 设置编译选项 (非常重要！)
# Naito 依赖 ARM NEON Crypto 扩展，必须开启
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)")
        target_compile_options(naito_benchmark PRIVATE -march=armv8-a+crypto)
    endif()
endif()

# 5. 如果需要链接其他通用库（这里可能不需要，因为是独立的实现）
# target_link_libraries(naito_benchmark PRIVATE ...)