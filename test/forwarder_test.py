import asyncio
import socket
import struct

import can
import pytest
from can_eth.__main__ import CANToEth


async def receive_udp_multicast_package(multicast_ip="239.255.0.1", port=5000):
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", port))

    # Join the multicast group
    mreq = struct.pack("4sl", socket.inet_aton(multicast_ip), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    # Receive data from the multicast group
    loop = asyncio.get_event_loop()
    data, addr = await loop.run_in_executor(None, sock.recvfrom, 1024)
    print(f"Received message from {addr}: {data}")
    return data


def send_message(bus, message_id, data):
    message = can.Message(arbitration_id=message_id, data=data)
    bus.send(message)


async def send_on_can1():
    # create a bus instance
    bus = can.interface.Bus(channel="can1", bustype="socketcan")
    # send a message with id 0x123 and data 0x01, 0x02, 0x03, 0x04
    send_message(bus, 0x123, [0x01, 0x02, 0x03, 0x04])
    # close the bus
    # bus.shutdown()


@pytest.mark.asyncio(loop_scope="module")
async def test_forward_single_frame():
    forwarder = CANToEth("can0", "239.255.0.1", 5000)
    forward_task = asyncio.create_task(forwarder.forward())

    receive_udp_task = asyncio.create_task(receive_udp_multicast_package())
    send_on_can1_task = asyncio.create_task(send_on_can1())
    hest = asyncio.wait([forward_task, receive_udp_task, send_on_can1_task], return_when=asyncio.FIRST_COMPLETED)
    await hest
    print(hest)
