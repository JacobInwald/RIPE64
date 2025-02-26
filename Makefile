GCC=gcc
CLG=clang

# Disable stack protection, make the stack executable and add debug info
<<<<<<< HEAD
CFLAGS=-fno-stack-protector -fsanitize=safe-stack
=======
CFLAGS=-fno-stack-protector -z execstack -g ${HARDEN_FLAGS}
>>>>>>> argparse

all: build/gcc_attack_gen build/clang_attack_gen

build/gcc_attack_gen: ./src/attack_gen.c
	${GCC} ${CFLAGS} ./src/attack_gen.c -o ./build/gcc_attack_gen

build/clang_attack_gen: ./src/attack_gen.c
	${CLG} ${CFLAGS} ./src/attack_gen.c -o ./build/clang_attack_gen

clean:
	rm ./build/*
