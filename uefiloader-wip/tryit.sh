x86_64-w64-mingw32-objcopy -I binary -O pe-x86-64 -B i386 --rename-section '.data'='.kernel' kerntest kerntest.o
#x86_64-w64-mingw32-gcc -o main -Wl,-T,test.x main.o -Wl,-b,pe-x86-64 kerntest.o -Wl,-b,pe-x86-64 -Wl,--no-check-sections
