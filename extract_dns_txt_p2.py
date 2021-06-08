#!/usr/bin/env python
# Hack.lu 2010 CTF - Challenge #9 "Bottle"
# Extract iodine DNS tunnel data
# -- StalkR
from scapy.all import *
from subprocess import Popen, PIPE

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP

import zlib
import binascii

input, output = "resources/traffic.pcap", "resources/traffic_extracted.pcap"
topdomain = ".t.xkjcjk.xyz."
upstream_encoding = 128


# see encoder.c
def encoder(base, encode="", decode=""):  # base=[32,64,128]
    p = Popen(["./encoder", str(base), "e" if len(encode) > 0 else "d"], stdin=PIPE, stdout=PIPE)
    p.stdin.write(encode if len(encode) > 0 else decode)
    return p.communicate()[0]


# see uncompress.c
def uncompress(s):
    # p = Popen(["./uncompress"], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    # p.stdin.write(s)
    # stdout, stderr = p.communicate()
    # if p.wait() == 0:
    #     return stdout
    # else:
    #     return False
    d = zlib.decompressobj(zlib.MAX_WBITS | 32)
    result_str = ''
    idx = 0
    size = len(s)
    while (idx + 1) * 32 <= size:
        try:
            result_str += d.decompress(dec[idx * 32:(idx + 1) * 32])
            idx = idx + 1
        except:
            break
    return result_str


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
dn_pkt, up_pkt = '', ''
dec_pkt = ''
datasent = False
E = []
err_cnt = 0
fragmented = False
for i in range(len(p)):
    if not p[i].haslayer(DNS):
        continue
    if DNSQR in p[i]:
        if DNSRR in p[i] and len(p[i][DNSRR].rdata) > 0:  # downstream/server
            d = p[i][DNSRR].rdata[0]
            # if datasent:  # real data and no longer codec/fragment checks
                # for bottle.pcap
                # if dn_header(d)['lastfrag'] and len(dn_pkt) > 0:
                #     u = uncompress(dn_pkt)
                #     if not u:
                #         raise Exception("Error dn_pkt %i: %r" % (i, dn_pkt))
                #     E += [IP(u[4:])]
                #     dn_pkt = ''
                # for traffic.pcap
                # if dn_header(d)['lastfrag'] and len(dn_pkt) > 0:
                #     if dn_header(d)['compress']:
                #         u = uncompress(encoder(32, decode=dn_pkt))
                #         if not u:
                #             raise Exception("Error dn_pkt %i: %r" % (i, dn_pkt))
                #     else:
                #         u = encoder(32, decode=dn_pkt)
                #         if not u:
                #             raise Exception("Error dn_pkt %i: %r" % (i, dn_pkt))
                #     E += [IP(u[4:])]
                #     dn_pkt = ''
        else:  # upstream/client
            d = p[i][DNSQR].qname
            if d[0].lower() in "0123456789abcdef":
                datasent = True
                fragment = d[5:-len(topdomain)].replace(".", "")
                dec_pkt += encoder(upstream_encoding, decode=fragment)
                up_pkt += fragment
                # print "Fragment size %i" % len(fragment)
                print "Fragment %s" % up_header(d)
                if not up_header(d)['lastfrag']:
                    # print "Fragment %s" % up_header(d)
                    fragmented = True
                    # fd = open("resources/temp.bin", "ab")
                    # fd.write(d[5:-len(topdomain)].replace(".", ""))
                    # fd.close()
                if up_header(d)['lastfrag'] and len(up_pkt) > 0:
                    # print "Fragment %s" % up_header(d)
                    if fragmented:
                        fragmented = False
                    # print "Total size %i" % len(up_pkt)
                    dec = encoder(upstream_encoding, decode=up_pkt)
                    # fd = open("resources/temp.zip", "wb")
                    # fd.write(dec)
                    # fd.close()
                    # try:
                    #     uu = zlib.decompress(dec)
                    # except:
                    #     binascii.b2a_hex(dec)
                    #     d = zlib.decompressobj(zlib.MAX_WBITS | 32)
                    #     result_str = ''
                    #     idx = 0
                    #     while True:
                    #         try:
                    #             result_str += d.decompress(dec[idx*32:(idx+1)*32])
                    #             idx = idx+1
                    #         except:
                    #             break
                    #     i = 512
                    #     while i>0:
                    #         try:
                    #             uu = zlib.decompress(dec[:i])
                    #             print i
                    #         except:
                    #             i = i-1
                    #             continue
                    u = uncompress(dec)
                    if not u:
                        print "Failed"
                        # fd = open("resources/temp.bin", "ab")
                        # fd.write(d[5:-len(topdomain)].replace(".", ""))
                        # fd.close()
                        up_pkt = ''
                        dec_pkt = ''
                        err_cnt = err_cnt+1
                        continue
                    print "Succes"
                    E += [IP(u[4:])]
                    up_pkt = ''
                    dec_pkt = ''

wrpcap(output, E)
print "Successfully extracted %i packets into %s" % (len(E), output)
print "Error packets %i" % err_cnt
