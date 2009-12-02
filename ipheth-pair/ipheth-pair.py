#!/usr/bin/env python

# ipheth-pair.py - Apple iPhone USB Ethernet pairing program
# 
# Copyright (c) 2009 Diego Giagio <diego@giagio.com>
# All rights reserved.

import sys

from libiphone.iPhone import *
from base64 import b64decode
from pyasn1.codec.ber import decoder
from random import randint
from M2Crypto import *

def lockdownd_get_val(lckd, key, string):
    plist = PListNode(PLIST_DICT)
    plist.add_sub_key(key)
    plist.add_sub_string(string)
    plist.add_sub_key("Request")
    plist.add_sub_string("GetValue")

    lckd.send(plist)
    plist = lckd.receive()
    res = plist.get_dict_el_from_key("Result").as_string()
    if res != "Success":
        print "lockdownd_get_val(%s, %s): %s" % (key, string, res)
        return None
    res = plist.get_dict_el_from_key("Value").as_data()
    return res

def lockdownd_validate_pair(lckd, rootcert, devcert, hostcert, hostid):
    plistkeys = PListNode(PLIST_DICT)
    plistkeys.add_sub_key("DeviceCertificate")
    plistkeys.add_sub_data(devcert)
    plistkeys.add_sub_key("HostCertificate")
    plistkeys.add_sub_data(hostcert)
    plistkeys.add_sub_key("HostID")
    plistkeys.add_sub_string(hostid)
    plistkeys.add_sub_key("Rootcertificate")
    plistkeys.add_sub_data(rootcert)

    plist = PListNode(PLIST_DICT)
    plist.add_sub_key("PairRecord")
    plist.add_sub_node(plistkeys)
    plist.add_sub_key("ProtocolVersion")
    plist.add_sub_string("2")
    plist.add_sub_key("Request")
    plist.add_sub_string("ValidatePair")

    lckd.send(plist)
    plist = lckd.receive()
    res = plist.get_dict_el_from_key("Result").as_string()
    return res

def lockdownd_pair(lckd, rootcert, devcert, hostcert, hostid):
    plistkeys = PListNode(PLIST_DICT)
    plistkeys.add_sub_key("DeviceCertificate")
    plistkeys.add_sub_data(devcert)
    plistkeys.add_sub_key("HostCertificate")
    plistkeys.add_sub_data(hostcert)
    plistkeys.add_sub_key("HostID")
    plistkeys.add_sub_string(hostid)
    plistkeys.add_sub_key("Rootcertificate")
    plistkeys.add_sub_data(rootcert)

    plist = PListNode(PLIST_DICT)
    plist.add_sub_key("PairRecord")
    plist.add_sub_node(plistkeys)
    plist.add_sub_key("ProtocolVersion")
    plist.add_sub_string("2")
    plist.add_sub_key("Request")
    plist.add_sub_string("Pair")

    lckd.send(plist)
    plist = lckd.receive()
    res = plist.get_dict_el_from_key("Result").as_string()
    return res

def gen_host_id():
    chars = "ABCDEF0123456789"
    host_id_len = 27
    host_id = []
    for i in range(0, host_id_len):
        if i == 8:
            host_id.append('-')
        else:
            host_id.append(chars[randint(0, len(chars) - 1)])
    return "".join(host_id)

def parse_pkey(pkeystr):
    b64 = []
    for l in pkeystr.split('\n'):
        if l.startswith("---"):
            continue
        b64.append(l)
    return b64decode("".join(b64))

def to_mpint(buf):
    return m2.bn_to_mpi(m2.hex_to_bn(buf))


def main():    
    phone = iPhone()
    if not phone.init_device():
        print "Unable to initialize device. Make sure your device is connected."
        return 1

    lckd = phone.get_lockdown_client()

    # Retrieve device's public key
    dev_pkeystr = lockdownd_get_val(lckd, "Key", "DevicePublicKey")
    dev_asn1 = parse_pkey(dev_pkeystr)
    seq = decoder.decode(dev_asn1)[0]
    m = to_mpint(str(seq.getComponentByPosition(0)))
    e = to_mpint(str(seq.getComponentByPosition(1)))
    pkey = RSA.new_pub_key((e, m))

    # Generate RootCertificate
    root_ca_cert = X509.X509()
    root_pkey = RSA.gen_key(1024, 65537)
    pkroot = EVP.PKey()
    pkroot.assign_rsa(root_pkey)
    root_ca_cert.set_pubkey(pkroot)

    # Generate DeviceCertificate
    dev_cert = X509.X509()
    pkdev = EVP.PKey()
    pkdev.assign_rsa(pkey)
    dev_cert.set_pubkey(pkdev)
    dev_cert.sign(pkroot, "sha1")

    # Generate HostCertificate
    host_pkey = RSA.gen_key(1024, 65537)
    host_cert = X509.X509()
    pkhost = EVP.PKey()
    pkhost.assign_rsa(host_pkey)
    host_cert.set_pubkey(pkhost)
    host_cert.sign(pkroot, "sha1")

    #host_id = gen_host_id()
    host_id = "30020357-993885437260361964"

    # We retry pairing in case of error
    nretry = 3

    # Pair
    for i in range(1, nretry):
        res = lockdownd_pair(lckd, root_ca_cert.as_pem(),
                             dev_cert.as_pem(),
                             host_cert.as_pem(),
                             host_id)
        if res == "Success":
            break

    if res != "Success":
        print "Pair: %s" % res
        return 1

    # Validate Pair
    for i in range(1, nretry):
        res = lockdownd_validate_pair(lckd, root_ca_cert.as_pem(),
                                      dev_cert.as_pem(),
                                      host_cert.as_pem(),
                                      host_id)
        if res == "Success":
            break

    if res != "Success":
        print "ValidatePair: %s" % res
        return 1

    # Success
    print "Device successfully paired"
    return 0

if __name__ == '__main__':
    sys.exit(main())
