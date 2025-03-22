# CAN to Ethernet Forwarder

This project provides a CAN to Ethernet forwarder that listens to a CAN interface and forwards the messages to a specified UDP multicast address.

## Features

- Listens to a specified CAN interface.
- Forwards CAN messages to a specified UDP multicast address and port.
- Handles `Ctrl-C` (SIGINT) gracefully to stop the forwarding process.

## Requirements

- Python 3.7+
- `python-can` library
- `asyncio` library

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/can-eth.git
    cd can-eth
    ```

2. Install the required Python packages:
    ```sh
    pip install python-can
    ```

## Usage

Run the script with the default settings:
```sh
python -m can_eth                   