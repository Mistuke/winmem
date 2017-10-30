OUT = build

CC = gcc
CFLAGS = \
	-std=c99 -Wall -g3 -I tlsf-bsd/tlsf \
	-D__USE_MINGW_ANSI_STDIO \
	-D TLSF_CONFIG_ASSERTLDFLAGS \
	-D MEM_DEBUG \
	-D UNICODE \
	-D TLSF_CONFIG_ASSERT

all:
	$(RM) -rf $(OUT)
	mkdir $(OUT)
	$(CC) $(CFLAGS) winmem.c -I tlsf-bsd/tlsf/ -c -o $(OUT)/winmem.o
	$(CC) $(CFLAGS) tlsf-bsd/tlsf/tlsf.c -I tlsf-bsd/tlsf/ -c -o $(OUT)/tlsf.o
	$(CC) $(CFLAGS) test_bed.c $(OUT)/winmem.o $(OUT)/tlsf.o -o $(OUT)/test_bed.exe
	./$(OUT)/test_bed.exe

clean:
	$(RM) -rf $(OUT)

.PHONY: all clean