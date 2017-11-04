OUT = build

CC = gcc
CFLAGS = \
	-std=c11 -Wall -g3 -I tlsf \
	-Wall -Wextra -Wshadow -Wpointer-arith \
	-Wcast-qual -Wconversion -Wc++-compat \
	-D__USE_MINGW_ANSI_STDIO \
	-DTLSF_CONFIG_ASSERTLDFLAGS \
	-DMEM_DEBUG \
	-DUNICODE \
	-DTLSF_ASSERT \
	-DTLSF_STATS \
	-DTLSF_DEBUG \
	-D__WORDSIZE=64

all:
	$(RM) -rf $(OUT)
	mkdir $(OUT)
	$(CC) $(CFLAGS) winmem.c -c -o $(OUT)/winmem.o
	$(CC) $(CFLAGS) tlsf/tlsf.c -c -o $(OUT)/tlsf.o
	$(CC) $(CFLAGS) test_bed.c $(OUT)/winmem.o $(OUT)/tlsf.o -o $(OUT)/test_bed.exe
	./$(OUT)/test_bed.exe

clean:
	$(RM) -rf $(OUT)

.PHONY: all clean