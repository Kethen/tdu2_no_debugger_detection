set -xe

for arch in x86_64 i686
do
	OUT_DIR=dist/${arch}
	rm -rf $OUT_DIR
	mkdir -p $OUT_DIR

	min_hook_lib="MinHook.x86"
	if [ ${arch} == x86_64 ]
	then
		min_hook_lib="MinHook.x64"
	fi
	cp minhook_1.3.3/bin/${min_hook_lib}.dll $OUT_DIR

	CPPC=${arch}-w64-mingw32-g++
	$CPPC -g -fPIC -c tdu2_no_debugger_detection.cpp -Iminhook_1.3.3/include -std=c++20 -o $OUT_DIR/tdu2_no_debugger_detection.o -O0
	$CPPC -g -shared -o $OUT_DIR/tdu2_no_debugger_detection_${arch}.asi $OUT_DIR/tdu2_no_debugger_detection.o -Lminhook_1.3.3/bin -lntdll -lkernel32 -Wl,-Bstatic -lpthread -l${min_hook_lib} -static-libgcc -static-libstdc++

	rm $OUT_DIR/*.o
done
