rtp2amrwb
=========
pcap rtp streams with AMR WB Bandwidth Efficient audio to amr wb media file script
=========
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
==========
