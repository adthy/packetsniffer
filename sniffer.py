from scapy.all import *
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
from rich import box

console = Console()

# Parse Arguments
parser = argparse.ArgumentParser(description="A simple packet sniffer")
parser.add_argument(
    "-v", "--show", help="Display the packets captured"
)
parser.add_argument(
    "-s", "--savefile", help="CSV file to save the packets to", default="capture.csv"
)
parser.add_argument(
    "-f", "--forge", help="Forge a packet", action="store_true"
)
parser.add_argument(
    "-r", "--send", help="Send a forged packet and print response", action="store_true"
)
parser.add_argument(
    "-e", "--ethernet", help="Encapsulate with ethernet frame", nargs='*'
)
parser.add_argument(
    "-p", "--protocol", help="Assigns protocol with settings", nargs='*'
)
parser.add_argument(
    "-o", "--optional", help="Optional IP settings", nargs='*'
)
parser.add_argument(
    "-l", "--payload", help="Assigns payload", nargs='*'
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

if args.forge:
    packet_string = []

    if args.ethernet:
        packet_string.append(f"Ether({','.join(args.ethernet)})")

    if args.optional:
        packet_string.append(f"IP({','.join(args.optional)})")

    if args.protocol:
        packet_string.append(f"{args.protocol[0]}({','.join(args.protocol[1:])})")

    if args.payload:
        formatted = ' '.join(args.payload)
        packet_string.append(f'\"{formatted}\"')

    packet = eval('/'.join(packet_string))
    console.rule(
        f"[bold red]Forged Packet"
    )

    #Print ethernet
    if args.ethernet:
        ETHfields = [field.name for field in Ether.fields_desc]
        ETHtable = Table(title="Ethernet", box=box.HORIZONTALS)
        ETHtable.add_column("Field", style="cyan")
        ETHtable.add_column("Value", style="magenta")
        for field in ETHfields:
            ETHtable.add_row(field, str(getattr(packet['Ether'], field)))
        console.print(ETHtable)

    #Print IP
    IPfields = [field.name for field in IP.fields_desc]
    IPtable = Table(title="IP", box=box.HORIZONTALS)
    IPtable.add_column("Field", style="cyan")
    IPtable.add_column("Value", style="magenta")
    for field in IPfields:
        IPtable.add_row(field, str(getattr(packet['IP'], field)))
    console.print(IPtable)

    #Print protocol layer
    if args.protocol:
        Pfields = eval(f'[field.name for field in {args.protocol[0]}.fields_desc]')
        Ptable = Table(title=args.protocol[0], box=box.HORIZONTALS)
        Ptable.add_column("Field", style="cyan")
        Ptable.add_column("Value", style="magenta")
        for field in Pfields:
            Ptable.add_row(field, str(getattr(packet[args.protocol[0]], field)))
        console.print(Ptable)

    if args.payload:
        table = Table(title="Payload", box=box.HORIZONTALS)
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="magenta")
        table.add_row("Raw", packet_string[-1])
        console.print(table)

    if args.send:
        response = sr1(packet)
        console.rule(
            f"[bold red]Received Response"
        )
        #Print ethernet
        if args.ethernet:
            ETHfields = [field.name for field in Ether.fields_desc]
            ETHtable = Table(title="Ethernet", box=box.HORIZONTALS)
            ETHtable.add_column("Field", style="cyan")
            ETHtable.add_column("Value", style="magenta")
            for field in ETHfields:
                ETHtable.add_row(field, str(getattr(response['Ether'], field)))
            console.print(ETHtable)

        #Print IP
        IPfields = [field.name for field in IP.fields_desc]
        IPtable = Table(title="IP", box=box.HORIZONTALS)
        IPtable.add_column("Field", style="cyan")
        IPtable.add_column("Value", style="magenta")
        for field in IPfields:
            IPtable.add_row(field, str(getattr(response['IP'], field)))
        console.print(IPtable)

        #Print protocol layer
        if args.protocol:
            Pfields = eval(f'[field.name for field in {args.protocol[0]}.fields_desc]')
            Ptable = Table(title=args.protocol[0], box=box.HORIZONTALS)
            Ptable.add_column("Field", style="cyan")
            Ptable.add_column("Value", style="magenta")
            for field in Pfields:
                Ptable.add_row(field, str(getattr(response[args.protocol[0]], field)))
            console.print(Ptable)

        if args.payload:
            fields = [field.name for field in Raw.fields_desc]
            table = Table(title="Payload", box=box.HORIZONTALS)
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="magenta")
            for field in fields:
                table.add_row(field, str(getattr(response[args.protocol[0]], field)))
            console.print(table)


if args.show:
    with open(args.savefile, "w") as file:
        writer = csv.DictWriter(file, headers, lineterminator="\n")
        writer.writeheader()

        progress = Progress(
            "[progress.description]{task.description}",
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeElapsedColumn(),
            SpinnerColumn("arrow3"),
        )
        task = progress.add_task("Capturing packets...", total=int(args.show))

        with progress:
            while not progress.finished:
                data = receiveData(s)
                unpacked = unpackData(data)
                writer.writerow(unpacked)
                progress.update(task, advance=1.0)

    with open(args.savefile, "r") as file:
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