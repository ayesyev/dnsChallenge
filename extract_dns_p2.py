#!/usr/bin/env python
# Hack.lu 2010 CTF - Challenge #9 "Bottle"
# Extract iodine DNS tunnel data
# -- StalkR
from scapy.all import *
from subprocess import Popen, PIPE

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP

import zlib

input, output, errout = "resources/challenge_null.pcap", "resources/challenge_extracted.pcap", "resources/errors.bin"
topdomain = ".t.xkjcjk.xyz."
upstream_encoding = 128


# and no downstream encoding (type NULL)

# see encoder.c
def encoder(base, encode="", decode=""):  # base=[32,64,128]
    p = Popen(["./encoder", str(base), "e" if len(encode) > 0 else "d"], stdin=PIPE, stdout=PIPE)
    p.stdin.write(encode if len(encode) > 0 else decode)
    return p.communicate()[0]


# see uncompress.c
def uncompress(s):
    p = Popen(["./uncompress"], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    p.stdin.write(s)
    stdout, stderr = p.communicate()
    if p.wait() == 0:
        return stdout
    else:
        return False


def b32_8to5(a):
    return "abcdefghijklmnopqrstuvwxyz012345".find(a.lower())


def up_header(p):
    return {
        "userid": int(p[0], 16),
        "up_seq": (b32_8to5(p[1]) >> 2) & 7,
        "up_frag": ((b32_8to5(p[1]) & 3) << 2) | ((b32_8to5(p[2]) >> 3) & 3),
        "dn_seq": (b32_8to5(p[2]) & 7),
        "dn_frag": b32_8to5(p[3]) >> 1,
        "lastfrag": b32_8to5(p[3]) & 1
    }


def dn_header(p):
    return {
        "compress": ord(p[0]) >> 7,
        "up_seq": (ord(p[0]) >> 4) & 7,
        "up_frag": ord(p[0]) & 15,
        "dn_seq": (ord(p[1]) >> 1) & 15,
        "dn_frag": (ord(p[1]) >> 5) & 7,
        "lastfrag": ord(p[1]) & 1,
    }


# Extract packets from DNS tunnel
# Note: handles fragmentation, but not packet reordering (sequence numbers)
p = rdpcap(input)
err_file = open(errout, "w")
dn_pkt, up_pkt = '', ''
datasent = False
E = []
for i in range(len(p)):
    if not p[i].haslayer(DNS):
        continue
    if DNSQR in p[i]:
        if DNSRR in p[i] and len(p[i][DNSRR].rdata) > 0:  # downstream/server
            d = p[i][DNSRR].rdata
            if datasent:  # real data and no longer codec/fragment checks
                err_file.write("[S] >> " + d + "\n")
                dn_pkt += d[2:]
                if dn_header(d)['lastfrag'] and len(dn_pkt) > 0:
                    # u = uncompress(dn_pkt)
                    u = zlib.decompress(dn_pkt)
                    if not u:
                        raise Exception("Error dn_pkt %i: %r" % (i, dn_pkt))
                    E += [IP(u[4:])]
                    dn_pkt = ''
        else:  # upstream/client
            d = p[i][DNSQR].qname
            if d[0].lower() in "0123456789abcdef":
                datasent = True
                err_file.write("[C] >> "+d+"\n")
                up_pkt += d[5:-len(topdomain)].replace(".", "")
                print "Fragment %s" % up_header(d)
                if up_header(d)['lastfrag'] and len(up_pkt) > 0:
                    # u = uncompress(encoder(upstream_encoding, decode=up_pkt))
                    decoded = encoder(upstream_encoding, decode=up_pkt)
                    u = uncompress(decoded)
                    if not u:
                        # raise Exception("Error up_pkt %i: %r" % (i, up_pkt))
                        print("Error up_pkt %i: %r" % (i, up_pkt))
                        err_file.write("ERROR ^^ \n")
                    else:
                        E += [IP(u[4:])]
                    up_pkt = ''
                elif up_header(d)['lastfrag'] == 0:
                    pass

wrpcap(output, E)
err_file.close()
print "Successfully extracted %i packets into %s" % (len(E), output)
