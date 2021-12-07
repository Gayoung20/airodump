LDLIBS=-lpcap

all: airodump

airodump: main.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -lpthread

clean:
	rm -f airodump *.o