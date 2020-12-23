all: hw3.c
	gcc -I/usr/local/opt/libpcap/include -Wall -std=gnu99 \
	-L/usr/local/opt/libpcap/lib hw3.c -o hw3 -lpcap
clean:
	rm -f hw3