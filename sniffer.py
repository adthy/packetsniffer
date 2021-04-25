from socket import *
from protocolFlags import *
from typeOfService import *
from unpackData import *

import struct
import sys
import argparse
import csv

from rich.console import Console
from rich.progress import Progress, BarColumn, TimeElapsedColumn, SpinnerColumn
from rich.table import Table

console = Console()

# Parse Arguments
parser = argparse.ArgumentParser(description="A simple packet sniffer")
parser.add_argument("num", type=int, help="Number of packets to be captured")
parser.add_argument(
    "-v", "--show", help="Display the packets captured", action="store_true"
)
parser.add_argument(
    "-f", "--file", help="CSV file to save the packets to", default="capture.csv"
)
args = parser.parse_args()


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


# the public network interface
HOST = gethostbyname(gethostname())

# create a raw socket and bind it to the public interface
s = socket(AF_INET, SOCK_RAW, IPPROTO_IP)
s.bind((HOST, 0))
# include IP headers
s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
s.ioctl(SIO_RCVALL, RCVALL_ON)

if args.num:
    with open(args.file, "w") as file:
        writer = csv.DictWriter(file, headers, lineterminator="\n")
        writer.writeheader()

        progress = Progress(
            "[progress.description]{task.description}",
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeElapsedColumn(),
            SpinnerColumn("arrow3"),
        )
        task = progress.add_task("Capturing packets...", total=args.num)

        with progress:
            while not progress.finished:
                data = receiveData(s)
                unpacked = unpackData(data)
                writer.writerow(unpacked)
                progress.update(task, advance=1.0)


if args.show:
    with open(args.file, "r") as file:
        reader = csv.DictReader(file)

        for unpacked in reader:
            console.rule(
                f"[bold red]An IP packet with the size {unpacked['totalLength']} was captured."
            )
            console.print(f"[red]Raw Packet[/red]: [white]{unpacked['raw']}[/white]")

            table = Table(title="Parsed Packet")

            table.add_column("Field", style="cyan")
            table.add_column("Value", style="magenta")

            table.add_row("Version", unpacked["version"])
            table.add_row("Header Length", unpacked["IHL"] + " bytes")
            table.add_row("Type of Service", unpacked["TOS"])
            table.add_row("Length", unpacked["totalLength"])
            table.add_row("ID", f"{hex(int(unpacked['ID']))} ({unpacked['ID']})")
            table.add_row("Flags", getFlags(int(unpacked["flags"])))
            table.add_row("Fragment offset", unpacked["fragmentOffset"])
            table.add_row("TTL", unpacked["TTL"])
            table.add_row("Protocol", unpacked["protocolNr"])
            table.add_row("Checksum", unpacked["checksum"])
            table.add_row("Source", unpacked["sourceAddress"])
            table.add_row("Destination", unpacked["destinationAddress"])
            table.add_row("Payload", str(unpacked["payload"]))

            console.print(table)

# disabled promiscuous mode
s.ioctl(SIO_RCVALL, RCVALL_OFF)
