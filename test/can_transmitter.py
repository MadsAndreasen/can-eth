import can


def send_message(bus, message_id, data):
    message = can.Message(arbitration_id=message_id, data=data)
    bus.send(message)

# next function will open can1 and send a message with id 0x123 and data 0x01, 0x02, 0x03, 0x04
def send_on_can1():
    # create a bus instance
    bus = can.interface.Bus(channel='can1', bustype='socketcan')
    # send a message with id 0x123 and data 0x01, 0x02, 0x03, 0x04
    send_message(bus, 0x123, [0x01, 0x02, 0x03, 0x04])
    # close the bus
    bus.shutdown()
