import argparse
import logging
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

    async def forward(self):
        bus = can.interface.Bus(channel=self.can_interface, interface='socketcan')
        loop = asyncio.get_event_loop()
        while True:
            try:
                message = await loop.run_in_executor(None, bus.recv)
                if message:
                    logger.debug("Received message: %s", message)
                    self.sock.sendto(message.data, (self.ip_address, self.port))
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
        "-c", "--can-interface",
        type=str,
        default="can0",
        help="CAN interface to listen to",
    )
    parser.add_argument(
        "-i",
        type=str,
        default="127.0.0.1",
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
