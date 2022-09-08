SHELL = /bin/sh
CC = gcc
CFLAG = -WALL -g

all: read_write pbkdf2 generate_hash symmetric asymmetric sign_verify
test: common_test crypto_common_test

read_write: ../common.h
	$(CC) $(CFLAGS) ../read_write.c ../common.c -o read_write -L/usr/lib/ -lcryptoauth -I/usr/include/cryptoauthlib/

pbkdf2: ../common.h
	$(CC) $(CFLAGS) ../pbkdf2.c ../common.c -o pbkdf2 -L/usr/lib/ -lcryptoauth -I/usr/include/cryptoauthlib/

generate_hash: ../common.h ../crypto_common.h
	$(CC) $(CFLAGS) ../generate_hash.c ../common.c ../crypto_common.c -o generate_hash -L/usr/lib/ -lcryptoauth -I/usr/include/cryptoauthlib/

symmetric: ../common.h ../crypto_common.h
	$(CC) $(CFLAGS) ../symmetric.c ../common.c ../crypto_common.c -o symmetric -L/usr/lib/ -lcryptoauth -I/usr/include/cryptoauthlib/

asymmetric: ../common.h ../crypto_common.h
	$(CC) $(CFLAGS) ../asymmetric.c ../common.c ../crypto_common.c -o asymmetric -L/usr/lib/ -lcryptoauth -I/usr/include/cryptoauthlib/

sign_verify: ../common.h ../crypto_common.h
	$(CC) $(CFLAGS) ../sign_verify.c ../common.c ../crypto_common.c -o sign_verify -L/usr/lib/ -lcryptoauth -I/usr/include/cryptoauthlib/

common_test: ../common.h 
	$(CC) $(CFLAGS) common_test.c ../common.c -o common_test -L/usr/lib/ -lcryptoauth -I/usr/include/cryptoauthlib/

crypto_common_test: ../common.h ../crypto_common.h 
	$(CC) $(CFLAGS) crypto_common_test.c ../common.c ../crypto_common.c -o crypto_common_test -L/usr/lib/ -lcryptoauth -I/usr/include/cryptoauthlib/

clean:
	rm -f read_write asymmetric symmetric sign_verify pbkdf2 generate_hash common_test crypto_common_test
	rm -f *.o
