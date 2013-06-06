all:
	clang -o dns main.c dns.c
clean:
	rm -f dns
