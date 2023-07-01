add_library(hofex SHARED
    FEXLoader.cpp
)
target_include_directories(hofex
  PRIVATE
    ${CMAKE_BINARY_DIR}/generated
)
target_link_libraries(hofex
  PRIVATE
    FEXCore
    Common
)
