# ML-KEM-768 test suite
# Run on host (x86/ARM) to validate the integration before flashing
CC ?= gcc
CFLAGS = -std=c99 -O2 -Wall -Wextra -Wno-unused-result -I../.. -I..

all: test_mlkem768

test_mlkem768: test_mlkem768.c ../../mlkem_native/mlkem_native.c
	$(CC) $(CFLAGS) -DMLK_CONFIG_PARAMETER_SET=768 $< ../../mlkem_native/mlkem_native.c -o $@

test: test_mlkem768
	./test_mlkem768

clean:
	rm -f test_mlkem768

.PHONY: all test clean
