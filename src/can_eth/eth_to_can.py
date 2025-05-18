import struct
import can
import socket
import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class EthToCAN:
    def __init__(self, can_interface, ip_address, port, buffer_size=2048):
        self.can_interface: str = can_interface
        self.ip_address = ip_address
        self.port = port
        self.buffer_size = buffer_size
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # For multicast
        if ip_address.startswith('239.'):
            self.sock.bind(('', port))  # Bind to all interfaces
            mreq = socket.inet_aton(ip_address) + socket.inet_aton('0.0.0.0')
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        else:
            self.sock.bind((ip_address, port))

        # Make socket non-blocking
        self.sock.setblocking(False)

    async def forward(self):
        bus = can.interface.Bus(channel=self.can_interface, interface="socketcan")
        loop = asyncio.get_event_loop()

        try:
            while True:
                try:
                    # Use asyncio to receive UDP packets non-blocking
                    raw_data, addr = await loop.sock_recvfrom(self.sock, self.buffer_size)
                    logger.debug(f"Received UDP packet from {addr}, size: {len(raw_data)} bytes")

                    can_msg = self.ethernet_bytes_to_can(raw_data)
                    if can_msg is not None:
                        logger.debug(f"Sending CAN message: {can_msg}")
                        await loop.run_in_executor(None, bus.send, can_msg)
                except (BlockingIOError, asyncio.IncompleteReadError):
                    # No data available yet, yield to other tasks
                    await asyncio.sleep(0.001)
        except asyncio.CancelledError:
            logger.debug("EthToCAN task cancelled, shutting down CAN bus")
            bus.shutdown()
            raise

    def ethernet_bytes_to_can(self, data: bytes) -> Optional[can.Message]:
        """
        Convert PCAN-Gateway Ethernet frame (classic CAN 2.0 frame) to python-can Message.

        Args:
            data: Ethernet frame received via UDP/TCP.

        Returns:
            Optional[can.Message]: CAN message to be sent on the bus, or None if conversion fails.
        """
        try:
            # Unpack the frame based on the PCAN-Gateway protocol
            # Format: !HH8sIIBBHI8s
            # H: length (2 bytes), H: type (2 bytes), 8s: tag (8 bytes),
            # I: timestamp_low (4 bytes), I: timestamp_high (4 bytes),
            # B: channel (1 byte), B: DLC (1 byte), H: flags (2 bytes),
            # I: CAN ID (4 bytes), 8s: data (8 bytes)
            unpacked = struct.unpack("!HH8sIIBBHI8s", data)

            length, msg_type, tag, timestamp_low, timestamp_high, channel, dlc, flags, can_id, raw_data = unpacked

            # Parse flags
            is_remote_frame = bool(flags & 0x01)
            is_extended_id = bool(flags & 0x02)

            # Extract correct ID
            if is_extended_id:
                # Extended ID with mask
                arb_id = can_id & 0x1FFFFFFF
            else:
                # Standard ID with mask
                arb_id = can_id & 0x7FF

            # Create can.Message object
            message = can.Message(
                arbitration_id=arb_id,
                data=raw_data[:dlc],  # Only use the bytes up to DLC
                is_extended_id=is_extended_id,
                is_remote_frame=is_remote_frame,
                dlc=dlc
            )

            return message
        except struct.error as e:
            logger.error(f"Error unpacking Ethernet frame: {e}")
            return None
        except Exception as e:
            logger.error(f"Error converting Ethernet frame to CAN message: {e}")
            return None
