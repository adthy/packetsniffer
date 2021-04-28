# Get Type of Service: 8 bits


def getTOS(data):
    precedence = {
        0: "Routine",
        1: "Priority",
        2: "Immediate",
        3: "Flash",
        4: "Flash override",
        5: "CRITIC/ECP",
        6: "Internetwork control",
        7: "Network control",
    }
    delay = {0: "Normal delay", 1: "Low delay"}
    throughput = {0: "Normal throughput", 1: "High throughput"}
    reliability = {0: "Normal reliability", 1: "High reliability"}
    cost = {0: "Normal monetary cost", 1: "Minimize monetary cost"}

    #   get the 3rd bit and shift right
    D = data & 0x10
    D >>= 4
    #   get the 4th bit and shift right
    T = data & 0x8
    T >>= 3
    #   get the 5th bit and shift right
    R = data & 0x4
    R >>= 2
    #   get the 6th bit and shift right
    M = data & 0x2
    M >>= 1
    #   the 7th bit is empty and shouldn't be analyzed

    tabs = "\n\t\t\t"
    TOS = (
        precedence[data >> 5]
        + tabs
        + delay[D]
        + tabs
        + throughput[T]
        + tabs
        + reliability[R]
        + tabs
        + cost[M]
    )
    return TOS
