import argparse
import logging
import struct
import can
import socket
import asyncio
import signal

from can_eth.eth_to_can import EthToCAN

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


class CANToEth:
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
                    pcan_frame = self.can_to_ethernet_bytes(message)
                    self.sock.sendto(pcan_frame, (self.ip_address, self.port))
            except asyncio.CancelledError:
                bus.shutdown()
                break

    def can_to_ethernet_bytes(self, msg: can.Message) -> bytes:
        """
        Convert a python-can Message to PCAN-Gateway Ethernet frame (classic CAN 2.0 frame).

        Returns:
            bytes: Ethernet frame to be sent via UDP/TCP.
        """
        # Packet constants
        MESSAGE_TYPE = 0x80  # classic CAN
        TAG = b"\x00" * 8
        TIMESTAMP_LOW = 0
        TIMESTAMP_HIGH = 0
        CHANNEL = 0x01  # usually ignored
        DLC = msg.dlc
        FLAGS = 0x00
        if msg.is_remote_frame:
            FLAGS |= 0x01
        if msg.is_extended_id:
            FLAGS |= 0x02

        # Prepare ID
        can_id = msg.arbitration_id & 0x1FFFFFFF
        if msg.is_extended_id:
            can_id |= 1 << 31  # extended flag
        if msg.is_remote_frame:
            can_id |= 1 << 30  # RTR bit

        # CAN data must be exactly 8 bytes
        data = msg.data + bytes(8 - len(msg.data))

        # Construct full message
        frame = struct.pack(
            "!HH8sIIBBHI8s",
            36,  # Total length of frame in bytes
            MESSAGE_TYPE,  # Type: 0x80
            TAG,  # Tag (unused)
            TIMESTAMP_LOW,
            TIMESTAMP_HIGH,
            CHANNEL,
            DLC,
            FLAGS,
            can_id,
            data,
        )

        return frame





async def handle_sigint():
    loop = asyncio.get_event_loop()
    stop_event = asyncio.Event()

    def signal_handler():
        stop_event.set()

    loop.add_signal_handler(signal.SIGINT, signal_handler)
    await stop_event.wait()


async def main():
    args = parse_args()

    # Create tasks based on mode
    tasks = []

    # Create and start CAN to Ethernet task if needed
    if args.mode in ["can2eth", "both"]:
        can_to_eth = CANToEth(args.can_interface, args.i, args.p)
        tasks.append(asyncio.create_task(can_to_eth.forward()))

    # Create and start Ethernet to CAN task if needed
    if args.mode in ["eth2can", "both"]:
        eth_to_can = EthToCAN(args.can_interface, args.i, args.p)
        tasks.append(asyncio.create_task(eth_to_can.forward()))

    # Add signal handler
    sigint_task = asyncio.create_task(handle_sigint())
    tasks.append(sigint_task)

    # Wait for any task to complete (usually the sigint handler)
    done, pending = await asyncio.wait(
        tasks, return_when=asyncio.FIRST_COMPLETED
    )

    # Cancel all pending tasks
    for task in pending:
        task.cancel()

    # Await all cancelled tasks to properly clean up
    if pending:
        await asyncio.wait(pending, return_when=asyncio.ALL_COMPLETED)


def parse_args():
    parser = setup_parser()
    return parser.parse_args()


def setup_parser():
    parser = argparse.ArgumentParser(description="CAN to/from Ethernet converter")
    parser.add_argument(
        "-c",
        "--can-interface",
        type=str,
        default="can0",
        help="CAN interface to use",
    )
    parser.add_argument(
        "-i",
        type=str,
        default="239.255.0.1",
        help="IP address for multicast/unicast communication",
    )
    parser.add_argument(
        "-p",
        type=int,
        default=50001,
        help="UDP port for communication",
    )
    parser.add_argument(
        "-m",
        "--mode",
        type=str,
        choices=["can2eth", "eth2can", "both"],
        default="both",
        help="Operation mode: CAN to Ethernet, Ethernet to CAN, or both",
    )
    return parser


if __name__ == "__main__":
    asyncio.run(main())
