__version__ = "0.2.1"
__author__ = "Nikolay Nenchev"

'''
Created by: Nikolay Nenchev
Date: 20141230
Filename: rtp2amrwb.py
Version: 0.2.1

Usage: python rtp2amrwb.py -i <inputfile> -o <outputfile>
inputfile - one way or two way rtp stream pcap file,
use Wireshark to filter
outputfile - name of the output amr-wb file(e.g. extension .AWB)

README:
python modules used: bitstring-3.1.3.zip,
pyshark-0.3.3.zip (needs tshark binary)
to install python module
easy_install <module_name> or
download module archive and python setup.py install

Contribution
Original function amrPayload2Storage_EfficientMode taken from
http://pastebin.com/6fSKSJVv
Modification done in order to process properly AMR-WB
'''

import sys
import getopt

from bitstring import BitArray
import pyshark




##################################################################
# convert amr payload to storage format
# according RFC 4867
# http://tools.ietf.org/html/rfc4867
# see http://packages.python.org/bitstring/walkthrough.html
#
# RFC 4867 (Bandwidth-Efficient Mode) p22...
# In the payload, no specific mode is requested (CMR=15), the speech
# frame is not damaged at the IP origin (Q=1), and the coding mode is
# AMR 7.4 kbps (FT=4).  The encoded speech bits, d(0) to d(147), are
# arranged in descending sensitivity order according to [2].  Finally,
#   two padding bits (P) are added to the end as padding to make the
#   payload octet aligned.
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   | CMR=15|0| FT=4  |1|d(0)                                       |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                                                               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                                                               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                                                               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                                                     d(147)|P|P|
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#
# RFC 4867 Section 5.3 (AMR and AMR-WB Storage Format)
#   The following example shows an AMR frame in 5.9 kbps coding mode
#   (with 118 speech bits) in the storage format.
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |P| FT=2  |Q|P|P|                                               |
#   +-+-+-+-+-+-+-+-+                                               +
#   |                                                               |
#   +          Speech bits for frame-block n, channel k             +
#   |                                                               |
#   +                                                           +-+-+
#   |                                                           |P|P|
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
#

def amrPayload2Storage_EfficientMode(payload):
    #AMR-NR
    #bitlen = [95,103,118,134,148,159,204,244,39]
    #AMR-WB TS 26.201 - total bits
    bitlen = [132, 177, 253, 285, 317, 365, 397, 461, 477, 40]
    amr = BitArray(bytes=payload)
    cmr = amr[0:4]
    mode = amr[5:9]
    #print(mode.uint)
    #assert mode.uint >=0 and mode.uint <=8
    if not (mode.uint >= 0 and mode.uint <= 8):
        retrn = ''
    else:
        qual = amr[9:10]
        voice = amr[10:10 + bitlen[mode.uint]]
        #print("cmr=%d\tmod=%d\tqual=%d\tvoicebits=%d" % (cmr.uint,mode.uint,qual.uint,voice.len))
        storage = BitArray(bin='0')
        storage.append(mode)
        storage.append(qual)
        storage.append('0b00')  # padding
        assert storage.len == 8, "check length of storage header is one byte"
        storage.append(voice)
        #return storage.tobytes()
        retrn = storage.tobytes()
    return retrn


def writeBinaryAmrWB(newfile):
    with open(newfile, "w+b") as f:
        f.write("#!AMR-WB\n")
        #f.write("#!AMR\n")


def appendBinaryAmrWB(newfile, nbytes):
    if nbytes != '':
        with open(newfile, "a+b") as f:
            f.write(nbytes)


def dump_rtp_payload(inputfile, outputfile):
    writeBinaryAmrWB(outputfile)
    cap = pyshark.FileCapture(inputfile, display_filter='amr or rtp')
    for i in cap:
        try:
            rtp = i[3]
            if rtp.payload:
                #print(rtp.payload)
                result = rtp.payload.replace(':', '').decode('hex')
                appendBinaryAmrWB(outputfile, amrPayload2Storage_EfficientMode(result))
        except:
            #print("ne razpoznava rtp")
            pass


def main(argv):
    inputfile = ''
    outputfile = ''
    try:
        opts, args = getopt.getopt(argv, "hi:o:", ["ifile=", "ofile="])
    except getopt.GetoptError:
        print 'rtp2amrwb.py -i <inputfile> -o <outputfile>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print 'rtp2amrwb.py -i <inputfile> -o <outputfile>'
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputfile = arg
        elif opt in ("-o", "--ofile"):
            outputfile = arg
    print 'Input file is:', inputfile
    print 'Output file is:', outputfile

    dump_rtp_payload(inputfile, outputfile)


if __name__ == "__main__":
    main(sys.argv[1:])
