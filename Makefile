plconfig: plconfig.c md5.c md5.h global.h
	cc -DLINUX -W -Wall -O -o plconfig plconfig.c md5.c

clean:
	rm -f plconfig
