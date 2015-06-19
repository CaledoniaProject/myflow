CC     = clang++
SOURCE = main.cpp
TARGET = main
#CFLAGS = libpcap-1.4.0/libpcap.a -lm -static
#CFLAGS = -static libpcap-1.4.0/libpcap.a -lm -std=c++11 
CFLAGS = libpcap-1.4.0/libpcap.a -lm -ggdb -Wall -pg -std=c++11 -static
CFLAGS_MAC = -L/usr/local/homebrew/lib/ -lpcap

default:
	$(CC) $(SOURCE) -o $(TARGET) $(CFLAGS)

mac:
	$(CC) $(SOURCE) -o $(TARGET) $(CFLAGS_MAC)

clean:
	rm -f *.o $(TARGET)

