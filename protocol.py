import struct
import socket


MAX_MESSAGE_SIZE = 10 * 1024 * 1024


def send_message(sock: socket.socket, data: bytes) -> None:
    """
    Send a length-prefixed message.

    Format:
        [4-byte length][payload]
    """

    if len(data) > MAX_MESSAGE_SIZE:
        raise ValueError(
            f"Message is too large: {len(data)} bytes"
        )

    header = struct.pack("!I", len(data))
    sock.sendall(header + data)


def receive_exactly(
        sock: socket.socket,
        size: int,
) -> bytes:
    """Receive exactly `size` bytes from a TCP socket."""

    data = bytearray()

    while len(data) < size:
        chunk = sock.recv(size - len(data))

        if not chunk:
            raise ConnectionError(
                "Connection closed before receiving "
                "the expected amount of data"
            )

        data.extend(chunk)

    return bytes(data)


def receive_message(
        sock: socket.socket,
) -> bytes | None:
    """
    Receive a length-prefixed message.

    A zero-length message means transmission is finished.
    """

    header = receive_exactly(sock, 4)

    message_size = struct.unpack("!I", header)[0]

    if message_size == 0:
        return None

    if message_size > MAX_MESSAGE_SIZE:
        raise ValueError(
            f"Message is too large: {message_size} bytes"
        )

    return receive_exactly(sock, message_size)
