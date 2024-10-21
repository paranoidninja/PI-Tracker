make:
	nasm -f win64 hook.asm -o hook.o
	x86_64-w64-mingw32-gcc pi_tracker.c hook.o -o PI-Tracker.dll -s -O2 -lntdll -lkernel32 -DBUILD_DLL -shared
	rm hook.o
