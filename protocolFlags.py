import re

# get Flags: 3 bits


def getFlags(data):
    flagR = {0: "0 - Reserved bit"}
    flagDF = {0: "0 - Fragment if necessary", 1: "1 - Do not fragment"}
    flagMF = {0: "0 - Last fragment", 1: "1 - More fragments"}

    #   get the 1st bit and shift right
    R = data & 0x8000
    R >>= 15
    #   get the 2nd bit and shift right
    DF = data & 0x4000
    DF >>= 14
    #   get the 3rd bit and shift right
    MF = data & 0x2000
    MF >>= 13

    flags = f"{flagR[R]}\n{flagDF[DF]}\n{flagMF[MF]}"
    return flags


# Get Protocol: 8 bits


def getProtocol(protocolNr):
    protocolFile = open("Protocol.txt", "r")
    protocolData = protocolFile.read()
    protocol = re.findall(r"\n" + str(protocolNr) + " (?:.)+\n", protocolData)
    if protocol:
        protocol = protocol[0]
        protocol = protocol.replace("\n", "")
        protocol = protocol.replace(str(protocolNr), "")
        protocol = protocol.lstrip()
        return protocol

    else:
        return "No such protocol."
