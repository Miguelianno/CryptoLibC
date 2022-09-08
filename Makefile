SHELL = /bin/sh
CC = gcc
CFLAG = -WALL -g


install:
	# 1º Git clone en el directorio deseado
	# /usr/lib/ -> crypaotuhlib.so
	# /usr/include/cryptoauthlib/ -> github repository 
	# 2º cd lib/
	# 3º cmake CMakeLists.txt
	# 4º make
	# 5º sudo mv libcryptoauth.so /usr/lib

info: common.h
	$(CC) $(CFLAGS) info.c common.c -o info -L/usr/lib/ -lcryptoauth -I/usr/include/cryptoauthlib/

random: common.h
	$(CC) $(CFLAGS) random.c common.c -o random -L/usr/lib/ -lcryptoauth -I/usr/include/cryptoauthlib/

read_write: common.h
	$(CC) $(CFLAGS) read_write.c common.c -o read_write -L/usr/lib/ -lcryptoauth -I/usr/include/cryptoauthlib/

pbkdf2: common.h
	$(CC) $(CFLAGS) pbkdf2.c common.c -o pbkdf2 -L/usr/lib/ -lcryptoauth -I/usr/include/cryptoauthlib/

generate_hash: common.h crypto_common.h
	$(CC) $(CFLAGS) generate_hash.c common.c crypto_common.c -o generate_hash -L/usr/lib/ -lcryptoauth -I/usr/include/cryptoauthlib/

symmetric: common.h crypto_common.h
	$(CC) $(CFLAGS) symmetric.c common.c crypto_common.c -o symmetric -L/usr/lib/ -lcryptoauth -I/usr/include/cryptoauthlib/

asymmetric: common.h crypto_common.h
	$(CC) $(CFLAGS) asymmetric.c common.c crypto_common.c -o asymmetric -L/usr/lib/ -lcryptoauth -I/usr/include/cryptoauthlib/

sign_verify: common.h crypto_common.h
	$(CC) $(CFLAGS) sign_verify.c common.c crypto_common.c -o sign_verify -L/usr/lib/ -lcryptoauth -I/usr/include/cryptoauthlib/

common: common.h
	$(CC) $(CFLAGS) -o common -L/usr/lib/ -lcryptoauth -I/usr/include/cryptoauthlib/

config: common.h
	$(CC) $(CFLAGS) config.c common.c -o config -L/usr/lib/ -lcryptoauth -I/usr/include/cryptoauthlib/

clean:
	rm -f info config read_write asymmetric symmetric sign_verify pbkdf2 generate_hash random
	rm -f *.o
	rm -rf dec.txt enc.txt
