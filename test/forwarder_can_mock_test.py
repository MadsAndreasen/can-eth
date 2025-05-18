import asyncio
import socket
import pytest
from unittest.mock import MagicMock, patch
import can
from can_eth.__main__ import CANToEth
import struct


@pytest.fixture
def mock_can_bus(mocker):
    """
    Creates a mock CAN bus that can be used to inject messages during testing.
    """
    mock_bus = MagicMock()

    # Store messages that will be returned by recv
    mock_bus.messages = []

    # Mock the recv method to return messages from our queue or wait
    def mock_recv(timeout=None):
        if mock_bus.messages:
            return mock_bus.messages.pop(0)
        if timeout is not None:
            # Simulate timeout if specified
            return None
        # Wait indefinitely (should not happen in our tests)
        raise Exception("No messages to return and no timeout specified")

    mock_bus.recv = mock_recv

    # Mock the can.interface.Bus to return our mock bus
    mocker.patch('can.interface.Bus', return_value=mock_bus)

    return mock_bus


async def receive_udp_multicast_package(multicast_ip="239.255.0.1", port=5000, timeout=0.5):
    """
    Helper function to listen for UDP multicast packages.
    Returns a list of received data packets.
    """
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", port))

    # Set timeout for non-blocking operation
    sock.settimeout(timeout)

    # Join the multicast group
    mreq = struct.pack("4sl", socket.inet_aton(multicast_ip), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    received_data = []
    start_time = asyncio.get_event_loop().time()

    while asyncio.get_event_loop().time() - start_time < timeout:
        try:
            data, addr = sock.recvfrom(1024)
            received_data.append((data, addr))
        except socket.timeout:
            break

    sock.close()
    return received_data


@pytest.mark.asyncio
async def test_forward_single_message(mock_can_bus):
    """Test forwarding a single CAN message."""
    # Set up UDP listener first
    multicast_ip = "239.255.0.1"
    port = 5000

    # Create a test message
    test_message = can.Message(
        arbitration_id=0x123,
        data=[0x01, 0x02, 0x03, 0x04],
        is_extended_id=False
    )

    # Add the message to the mock bus
    mock_can_bus.messages.append(test_message)

    # Create the forwarder
    forwarder = CANToEth("vcan0", multicast_ip, port)

    # Start receiving task
    receive_task = asyncio.create_task(receive_udp_multicast_package(multicast_ip, port))

    # Start the forwarder task
    forward_task = asyncio.create_task(forwarder.forward())

    # Allow some time for the message to be processed
    await asyncio.sleep(0.2)

    # Cancel the task
    forward_task.cancel()

    try:
        await forward_task
    except asyncio.CancelledError:
        pass

    # Get received data
    received_data = await receive_task

    # Verify we received a packet
    assert len(received_data) > 0, "No UDP packets received"

    # Check the packet format (partial check)
    data, addr = received_data[0]
    assert addr[0] == multicast_ip
    assert addr[1] == port
    assert len(data) == 36  # Expected length of PCAN-Gateway Ethernet frame


@pytest.mark.asyncio
async def test_forward_multiple_messages(mock_can_bus):
    """Test forwarding multiple CAN messages."""
    # Set up UDP listener first
    multicast_ip = "239.255.0.1"
    port = 5001  # Different port to avoid conflicts

    # Create test messages with different IDs and data
    test_messages = [
        can.Message(arbitration_id=0x100, data=[0x01, 0x02], is_extended_id=False),
        can.Message(arbitration_id=0x200, data=[0x03, 0x04, 0x05], is_extended_id=False),
        can.Message(arbitration_id=0x300, data=[0x06, 0x07, 0x08, 0x09], is_extended_id=True)
    ]

    # Add messages to the mock bus
    mock_can_bus.messages.extend(test_messages)

    # Create the forwarder
    forwarder = CANToEth("vcan0", multicast_ip, port)

    # Start receiving task
    receive_task = asyncio.create_task(receive_udp_multicast_package(multicast_ip, port, timeout=1.0))

    # Start the forwarder task
    forward_task = asyncio.create_task(forwarder.forward())

    # Allow time for all messages to be processed
    await asyncio.sleep(0.5)

    # Cancel the task
    forward_task.cancel()

    try:
        await forward_task
    except asyncio.CancelledError:
        pass

    # Get received data
    received_data = await receive_task

    # Check that all messages were sent
    assert len(received_data) == 3, f"Expected 3 UDP packets, received {len(received_data)}"


@pytest.mark.asyncio
async def test_extended_id_message(mock_can_bus):
    """Test forwarding a message with extended ID."""
    # Set up UDP listener first
    multicast_ip = "239.255.0.1"
    port = 5002  # Different port to avoid conflicts

    # Create a test message with extended ID
    test_message = can.Message(
        arbitration_id=0x1FFFFFFF,  # max extended ID
        data=[0xAA, 0xBB],
        is_extended_id=True
    )

    # Add the message to the mock bus
    mock_can_bus.messages.append(test_message)

    # Create the forwarder
    forwarder = CANToEth("vcan0", multicast_ip, port)

    # Start receiving task
    receive_task = asyncio.create_task(receive_udp_multicast_package(multicast_ip, port))

    # Start the forwarder task
    forward_task = asyncio.create_task(forwarder.forward())

    # Allow some time for the message to be processed
    await asyncio.sleep(0.2)

    # Cancel the task
    forward_task.cancel()

    try:
        await forward_task
    except asyncio.CancelledError:
        pass

    # Get received data
    received_data = await receive_task

    # Check that the message was sent
    assert len(received_data) > 0, "No UDP packets received"

    # Additional verification of extended ID could be added here
    data, addr = received_data[0]
    assert len(data) == 36  # Expected length of PCAN-Gateway Ethernet frame