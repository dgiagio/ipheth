CFLAGS += -Wall -O2
LDLIBS += -limobiledevice

all: ipheth-pair

ipheth-pair: ipheth-pair.o

install:
	install -m 0755 ipheth-pair /lib/udev/
	install -m 0644 90-iphone-tether.rules /etc/udev/rules.d
	/sbin/udevadm control --reload-rules

clean:
	rm -f *.o ipheth-pair
