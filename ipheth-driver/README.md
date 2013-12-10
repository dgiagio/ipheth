# iPhone USB Ethernet Driver for Linux

Compile and install the driver (usually need to be root):

```bash
make
make install
```
## Udev users (especially on Gentoo)

If you use udev and have a `/etc/udev/rules.d/70-persisent-net.rules` file and rule generation working, then this should be plug and play once you have enabled hotspot on your iPhone.

In the file you should have a line similar to (with real values filled in):

```udev
SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", ATTR{address}=="{}", ATTR{dev_id}=="0x0", ATTR{type}=="1", KERNEL=="eth*", NAME="eth0"
```

You can also force the driver to be ipheth here in the `DRIVERS==` section, and give this a special name, like `iphone0`.

On Gentoo, with the iPhone 5, I found no need to use `ipheth-pair` and the connection was immediately set up with NetworkManager.

## For those not using udev (old content)
You also need to copy ipheth-modprobe.conf to /etc/modprobe.d directory. This
will ensure that the device pairing will always take place after module
loading.

For more info: http://giagio.com/wiki/moin.cgi/iPhoneEthernetDriver (link is dead)

