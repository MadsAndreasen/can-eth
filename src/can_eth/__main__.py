import argparse
import logging
import struct
import can
import socket
import asyncio
import signal

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


class Forwarder:
    def __init__(self, can_interface, ip_address, port):
        self.can_interface: str = can_interface
        self.ip_address = ip_address
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

    async def forward(self):
        bus = can.interface.Bus(channel=self.can_interface, interface="socketcan")
        loop = asyncio.get_event_loop()
        while True:
            try:
                message = await loop.run_in_executor(None, bus.recv)
                if message:
                    logger.debug("Received message: %s", message)
                    # Extract CAN ID, DLC, and Data
                    can_id = message.arbitration_id
                    dlc = message.dlc
                    data = message.data

                    # PCAN-Ethernet Header (6 bytes)
                    packet_type = 0x00    # CAN Frame
                    channel = 0x01        # CAN Channel (1)
                    flags = 0x02 if message.is_extended_id else 0x00  # Extended ID flag
                    can_id_bytes = struct.pack(">I", can_id)  # Convert to big-endian 4 bytes

                    # Construct the full PCAN-Ethernet CAN frame
                    pcan_frame = struct.pack("BBB", packet_type, channel, dlc) + bytes([flags]) + can_id_bytes + data
                    self.sock.sendto(pcan_frame, (self.ip_address, self.port))
            except asyncio.CancelledError:
                bus.shutdown()
                break


async def handle_sigint():
    loop = asyncio.get_event_loop()
    stop_event = asyncio.Event()

    def signal_handler():
        stop_event.set()

    loop.add_signal_handler(signal.SIGINT, signal_handler)
    await stop_event.wait()


async def main():
    args = parse_args()
    forwarder = Forwarder(args.can_interface, args.i, args.p)
    forward_task = asyncio.create_task(forwarder.forward())
    sigint_task = asyncio.create_task(handle_sigint())

    await asyncio.wait([forward_task, sigint_task], return_when=asyncio.FIRST_COMPLETED)

    forward_task.cancel()
    await forward_task


def parse_args():
    parser = setup_parser()
    return parser.parse_args()


def setup_parser():
    parser = argparse.ArgumentParser(description="CAN to Ethernet converter")
    parser.add_argument(
        "-c",
        "--can-interface",
        type=str,
        default="can0",
        help="CAN interface to listen to",
    )
    parser.add_argument(
        "-i",
        type=str,
        default="239.255.0.1",
        help="IP address to send the CAN messages to",
    )
    parser.add_argument(
        "-p",
        type=int,
        default=5000,
        help="Port to send the CAN messages to",
    )
    return parser


if __name__ == "__main__":
    asyncio.run(main())
