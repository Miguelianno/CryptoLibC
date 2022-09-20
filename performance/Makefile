SHELL = /bin/sh
CC = gcc
CFLAG = -WALL -g


all: enc_dec_perf hash_perf SHA256 aes

enc_dec_perf: ../common.h ../crypto_common.h
	$(CC) $(CFLAGS) enc_dec_perf.c ../common.c ../crypto_common.c -o enc_dec_perf -L/usr/lib/ -lcryptoauth -I/usr/include/cryptoauthlib/

hash_perf: ../common.h ../crypto_common.h
	$(CC) $(CFLAGS) hash_perf.c ../common.c ../crypto_common.c -o hash_perf -L/usr/lib/ -lcryptoauth -I/usr/include/cryptoauthlib/

SHA256:
	$(CC) $(CFLAGS) SHA256.c -o SHA256

aes:
	$(CC) $(CFLAGS) main.c aes.c -o aes
clean:
	rm -f enc_dec_perf hash_perf aes SHA256
