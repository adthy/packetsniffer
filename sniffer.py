from socket import *
from protocolFlags import *
from typeOfService import *
import struct
import sys
import argparse

# Parse Arguments


parser = argparse.ArgumentParser(
    description='Number of Packets to be Captured')
parser.add_argument('numberOfPackets', type=int, help='Number of Packets')
args = parser.parse_args()
packets = args.numberOfPackets

# Receive a Datagram


def receiveData(s):
    data = ""
    try:
        data = s.recvfrom(65565)
    except timeout:
        data = ""
    except:
        print("An error happened: ")
        sys.exc_info()
    return data[0]


while packets > 0:
    # the public network interface
    HOST = gethostbyname(gethostname())

    # create a raw socket and bind it to the public interface
    s = socket(AF_INET, SOCK_RAW, IPPROTO_IP)
    s.bind((HOST, 0))
    # Include IP headers
    s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
    s.ioctl(SIO_RCVALL, RCVALL_ON)
    data = receiveData(s)

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

    print("\n\n\n")
    print("An IP packet with the size %i was captured." % (unpackedData[2]))
    print("Raw data: " + str(data), end="\n\n")
    print("Parsed data")
    print("Version:\t\t" + str(version))
    print("Header Length:\t\t" + str(IHL * 4) + " bytes")
    print("Type of Service:\t" + getTOS(TOS))
    print("Length:\t\t\t" + str(totalLength))
    print("ID:\t\t\t" + str(hex(ID)) + " (" + str(ID) + ")")
    print("Flags:\t\t\t" + getFlags(flags))
    print("Fragment offset:\t" + str(fragmentOffset))
    print("TTL:\t\t\t" + str(TTL))
    print("Protocol:\t\t" + getProtocol(protocolNr))
    print("Checksum:\t\t" + str(checksum))
    print("Source:\t\t\t" + sourceAddress)
    print("Destination:\t\t" + destinationAddress)
    print("Payload:\n" + str(data[20:]))

    packets -= 1
    # disabled promiscuous mode
    s.ioctl(SIO_RCVALL, RCVALL_OFF)
