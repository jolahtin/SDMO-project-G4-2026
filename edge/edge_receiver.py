import logging 
import socket 
import struct 

from common.crypto import load_key, decrypt 

HOST = "127.0.0.1" 
PORT = 5000 
MAX_MESSAGE_SIZE = 1024 * 1024 

logging.basicConfig( 
    level=logging.INFO, 
    format="%(asctime)s [EDGE] %(levelname)s: %(message)s" 
) 
logger = logging.getLogger(__name__) 


def receive_exactly(sock: socket.socket, size: int) -> bytes: 
    """ 
    Receive exactly `size` bytes from a TCP socket. 

    TCP does not guarantee that one recv() call returns 
    one complete application message. 

    """ 
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

 

 

def receive_message(sock: socket.socket) -> bytes | None: 
    """ 
    Receive one length-prefixed encrypted message. 
    Returns: 

        bytes: encrypted message 

        None: end-of-stream marker 

    """ 
    
    header = receive_exactly(sock, 4) 
    message_size = struct.unpack("!I", header)[0] 

    # Zero means that the sensor has finished. 
    if message_size == 0: 
        return None 
    if message_size > MAX_MESSAGE_SIZE: 
        raise ValueError( 
            f"Message is too large: {message_size} bytes" 
        ) 
    return receive_exactly(sock, message_size) 


def handle_sensor_connection( 
    connection: socket.socket, 
    address: tuple[str, int], 
    key: bytes, 
) -> None: 

    """Receive and decrypt sensor data.""" 
    logger.info("Sensor connected: %s:%d", address[0], address[1]) 
    total_bytes = 0 
    chunk_number = 0 
    
    try: 
        while True: 
            encrypted_data = receive_message(connection) 
            if encrypted_data is None: 
                logger.info("Sensor finished transmission") 
                break 
            try: 
                raw_data = decrypt(encrypted_data, key) 
            except ValueError: 
                logger.error( 
                    "Failed to decrypt chunk %d", 
                    chunk_number + 1, 
                ) 
                continue 
            chunk_number += 1 
            total_bytes += len(raw_data) 
            logger.info( 
                "Received chunk %d: %d encrypted bytes -> " 
                "%d decrypted bytes", 
                chunk_number, 
                len(encrypted_data), 
                len(raw_data), 
            ) 
            # In a real system, this is where the edge would process 

            # the sensor data. 

            # 

            # For this demonstration we only count the data. 
            
            logger.debug( 
                "First bytes of decrypted data: %s", 
                raw_data[:16].hex(), 
            ) 
    except ConnectionError as exc: 
        logger.warning("Sensor connection interrupted: %s", exc) 
    except Exception: 
        logger.exception("Error while processing sensor data") 
    finally: 
        logger.info( 
            "Connection finished. Received %d chunks / %d bytes", 
            chunk_number, 
            total_bytes, 
        ) 


def run_server() -> None: 
    """Start the edge receiver.""" 
    key = load_key() 
    logger.info("Starting legacy edge receiver") 
    logger.info("Listening on %s:%d", HOST, PORT) 
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server: 
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        server.bind((HOST, PORT)) 
        server.listen(5) 
        logger.info("Waiting for sensor connection...") 
        while True: 
            connection, address = server.accept() 
            with connection: 
                handle_sensor_connection( 
                    connection, 
                    address, 
                    key, 
                ) 


def main() -> None: 
    try: 
        run_server() 
    except KeyboardInterrupt: 
        logger.info("Edge receiver stopped") 
    except Exception: 
        logger.exception("Edge receiver failed") 

if __name__ == "__main__": 
    main() 
