all: libhofex.so

FEXLoader.o: FEXLoader.cpp
	clang++ -DENABLE_JEMALLOC=1 -DFEXLOADER_AS_INTERPRETER=0 -DFEXLoader_EXPORTS -DGLOBAL_DATA_DIRECTORY=\"/usr/local/share/fex-emu/\" -DHAS_SYSCALL_GETCPU=1 -DHAS_SYSCALL_GETTID=1 -DHAS_SYSCALL_RENAMEAT2=1 -DHAS_SYSCALL_STATX=1 -DHAS_SYSCALL_TGKILL=1 -DVIXL_INCLUDE_TARGET_AARCH64=1 -D_M_ARM_64=1 -mcx16 -O3 -DNDEBUG -fomit-frame-pointer -flto=thin -fPIC   -Wno-trigraphs -fdiagnostics-color=always -fcolor-diagnostics -Wno-deprecated-enum-enum-conversion -march=native -Wall -fno-operator-names -Werror=cast-qual -Werror=ignored-qualifiers -Werror=implicit-fallthrough -Wno-trigraphs -fwrapv -std=gnu++2a -c FEXLoader.cpp -I. -I../Source -I../External/FEXCore/include -I../External/fmt/include -I../FEXHeaderUtils -I../Build/include -I../Source/Tests -I../External/robin-map/include -I../Source/Tools/FEXLoader

libhofex.so: FEXLoader.o
	clang++ -Xlinker --gc-sections -Xlinker --strip-all -Xlinker --as-needed -shared -Wl,-soname,libhofex.so -mcx16 -O3 -DNDEBUG -fomit-frame-pointer -flto=thin -fPIC   -Wno-trigraphs -fdiagnostics-color=always -fcolor-diagnostics -Wno-deprecated-enum-enum-conversion -march=native -Wall -fno-operator-names -Werror=cast-qual -Werror=ignored-qualifiers -Werror=implicit-fallthrough -Wno-trigraphs -fwrapv -std=gnu++2a FEXLoader.o -o libhofex.so ../Build/External/FEXCore/Source/libFEXCore.a ../Build/External/FEXCore/Source/libFEXCore_Base.a ../Build/External/tiny-json/libtiny-json.a ../Build/External/fmt/libfmt.a ../Build/External/xxhash/libxxhash.a -lpthread
	du -sh libhofex.so

clean:
	rm -f *.o libhofex.so
