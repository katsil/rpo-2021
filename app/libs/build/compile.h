#!/bin/bash

ABI=x86

ANDRPID_NDK=${HOME}/Library/Android/sdk/ndk/22.0.7026061
TOOL_CHAIN=${ANDRPID_NDK}/build/cmake/android.toolchain.cmake
CMAKE=${HOME}/Library/Android/sdk/cmake/3.10.2.4988404/bin/cmake

mkdir -p ${ABI}
cd ${ABI}

${CMAKE} ../../spdlog -DCMAKE_SYSTEM_NAME=Android -DCMAKE_SYSTEM_VERSION=21 \
-DANDROID_ABI=${ABI} -DCMAKE_TOOLCHAIN_FILE=${TOOL_CHAIN}

${CMAKE} --build .
