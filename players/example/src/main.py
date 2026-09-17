"""Skeleton, not a stack. It opens tun0 and shows you the packets; everything
above that is yours to write (RULES §4).

What a scoring service has to do from here:
  * parse the IP header, verify the transport checksum against the pseudo-header
  * implement TCP (handshake, seq/ack, retransmit, teardown, TIME_WAIT)
  * implement HTTP for each version you declare, strictly
  * implement docs/NOTE-API.md so the referee can plant and retrieve flags
"""
import fcntl
import os
import struct

TUNSETIFF, IFF_TUN, IFF_NO_PI = 0x400454CA, 0x0001, 0x1000


def open_tun(name="tun0"):
    fd = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI))
    return fd


def main():
    fd = open_tun()
    print(f"tun0 open; answering as {os.environ.get('CTF_ADDR')}", flush=True)
    while True:
        pkt = os.read(fd, 65535)          # one full IP packet, header included
        proto = pkt[9]                    # 1=ICMP 6=TCP 17=UDP
        src = ".".join(str(b) for b in pkt[12:16])
        dst = ".".join(str(b) for b in pkt[16:20])
        print(f"{len(pkt):5d}B proto={proto:<3} {src} -> {dst}", flush=True)
        # os.write(fd, reply)


if __name__ == "__main__":
    main()
