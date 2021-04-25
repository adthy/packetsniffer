import struct
from socket import *

# Unpack Data


def unpackData(data):
    # get the IP header (the first 20 bytes) and unpack them
    # B - unsigned char (1)
    # H - unsigned short (2)
    # s - string
    unpackedData = struct.unpack("!BBHHHBBH4s4s", data[:20])

    version_IHL = unpackedData[0]
    version = version_IHL >> 4  # version of the IP
    IHL = version_IHL & 0xF  # internet header length
    TOS = unpackedData[1]  # type of service
    totalLength = unpackedData[2]
    ID = unpackedData[3]  # identification
    flags = unpackedData[4]
    fragmentOffset = unpackedData[4] & 0x1FFF
    TTL = unpackedData[5]  # time to live
    protocolNr = unpackedData[6]
    checksum = unpackedData[7]
    sourceAddress = inet_ntoa(unpackedData[8])
    destinationAddress = inet_ntoa(unpackedData[9])

    return version_IHL, version, IHL, TOS, totalLength, ID, flags, fragmentOffset, TTL, protocolNr, checksum, sourceAddress, destinationAddress
