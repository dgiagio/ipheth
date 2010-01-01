all:
	gcc -Wall -O2 ipheth-pair.c -o ipheth-pair -liphone

install:
	install -m 0755 ipheth-pair /lib/udev/
	install -m 0644 90-iphone-tether.rules /etc/udev/rules.d
	/sbin/udevadm control --reload-rules

clean:
	rm -f ipheth-pair

