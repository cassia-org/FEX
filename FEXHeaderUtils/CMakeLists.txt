add_library(FEXHeaderUtils INTERFACE)

# Check for syscall support here
check_cxx_source_compiles(
  "
  #include <sched.h>
  int main() {
  return ::getcpu(nullptr, nullptr);
  }"
  compiles)
if (compiles)
  message(STATUS "Has getcpu helper")
  target_compile_definitions(FEXHeaderUtils INTERFACE HAS_SYSCALL_GETCPU=1)
endif ()

check_cxx_source_compiles(
  "
  #include <unistd.h>
  int main() {
  return ::gettid();
  }"
  compiles)
if (compiles)
  message(STATUS "Has gettid helper")
  target_compile_definitions(FEXHeaderUtils INTERFACE HAS_SYSCALL_GETTID=1)
endif ()

check_cxx_source_compiles(
  "
  #include <signal.h>
  int main() {
  return ::tgkill(0, 0, 0);
  }"
  compiles)
if (compiles)
  message(STATUS "Has tgkill helper")
  target_compile_definitions(FEXHeaderUtils INTERFACE HAS_SYSCALL_TGKILL=1)
endif ()

check_cxx_source_compiles(
  "
  #include <sys/stat.h>
  int main() {
  return ::statx(0, nullptr, 0, 0, nullptr);
  }"
  compiles)
if (compiles)
  message(STATUS "Has statx helper")
  target_compile_definitions(FEXHeaderUtils INTERFACE HAS_SYSCALL_STATX=1)
endif ()

check_cxx_source_compiles(
  "
  #include <stdio.h>
  int main() {
  return ::renameat2(0, nullptr, 0, nullptr, 0);
  }"
  compiles)
if (compiles)
  message(STATUS "Has renameat2 helper")
  target_compile_definitions(FEXHeaderUtils INTERFACE HAS_SYSCALL_RENAMEAT2=1)
endif ()

target_include_directories(FEXHeaderUtils INTERFACE .)
