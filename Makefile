GCC=gcc
CLG=clang

# Disable stack protection, make the stack executable and add debug info
CFLAGS=-g -w -D_FORTIFY_SOURCE=0 -no-pie -fno-stack-protector -z execstack -z norelro ${HARDEN_FLAGS}

all: build/gcc_attack_gen build/clang_attack_gen

build/gcc_attack_gen: ./src/attack_gen.c
	${GCC} ${CFLAGS} ./src/attack_gen.c -o ./build/gcc_attack_gen

build/clang_attack_gen: ./src/attack_gen.c
	${CLG} ${CFLAGS} ./src/attack_gen.c -o ./build/clang_attack_gen

clean:
	rm ./build/*
