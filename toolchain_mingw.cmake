set(MINGW_PATH "" CACHE STRING "Path to an extracted llvm-mingw installation")
set(MINGW_PREFIX "" CACHE STRING "MINGW compiler architecture prefix")

set(CMAKE_RC_COMPILER ${MINGW_PATH}/bin/${MINGW_PREFIX}-windres)
set(CMAKE_C_COMPILER ${MINGW_PATH}/bin/${MINGW_PREFIX}-clang)
set(CMAKE_CXX_COMPILER ${MINGW_PATH}/bin/${MINGW_PREFIX}-clang++)
set(CMAKE_SHARED_LINKER_FLAGS "-static -static-libgcc -static-libstdc++ -Wl,--file-alignment=4096")
set(CMAKE_EXE_LINKER_FLAGS "-static -static-libgcc -static-libstdc++ -Wl,--file-alignment=4096")

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR ${MINGW_PREFIX})

set(CMAKE_FIND_ROOT_PATH ${MINGW_PATH}/${MINGW_PREFIX})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

