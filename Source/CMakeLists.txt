add_subdirectory(Common/)
add_subdirectory(Tools/)

if (NOT MINGW_BUILD)
  add_subdirectory(Linux/)
else()
  add_subdirectory(Windows/)
endif()
