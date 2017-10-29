OUT = build

CC = gcc
CFLAGS = \
	-std=c99 -Wall -g -I tlsf-bsd/tlsf \
	-D__USE_MINGW_ANSI_STDIO \
	-D TLSF_CONFIG_ASSERTLDFLAGS \
	-D MEM_DEBUG \
	-D UNICODE

all:
	$(RM) -rf $(OUT)
	mkdir $(OUT)
	$(CC) $(CFLAGS) winmem.c -I tlsf-bsd/tlsf/ -c -o $(OUT)/winmem.o

clean:
	$(RM) -rf $(OUT)

.PHONY: all clean