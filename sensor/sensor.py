import argparse 
import logging 
import socket 
import struct 
import time 
import wave 
from pathlib import Path 
from common.crypto import load_key, encrypt 

HOST = "127.0.0.1" 
PORT = 5000 
CHUNK_SIZE = 4096 
SEND_DELAY = 0.05 

logging.basicConfig( 
    level=logging.INFO, 
    format="%(asctime)s [SENSOR] %(levelname)s: %(message)s" 
) 
logger = logging.getLogger(__name__) 

def send_message(sock: socket.socket, data: bytes) -> None: 
    """ 

    Send one encrypted message. 

 

    A 4-byte length header is sent before the encrypted payload. 

    """ 
    header = struct.pack("!I", len(data)) 
    sock.sendall(header + data) 

def run_sensor(audio_file: Path) -> None: 
    """Read audio data and send encrypted chunks to the edge.""" 
    key = load_key() 
    logger.info("Using audio file: %s", audio_file) 
    with wave.open(str(audio_file), "rb") as audio: 
        sample_rate = audio.getframerate() 
        channels = audio.getnchannels() 
        sample_width = audio.getsampwidth() 
        total_frames = audio.getnframes() 
        logger.info( 
            "Audio: %d Hz, %d channel(s), %d byte sample width", 
            sample_rate, 
            channels, 
            sample_width, 
        ) 
        logger.info("Total audio frames: %d", total_frames) 
        with socket.create_connection((HOST, PORT)) as sock: 
            logger.info( 
                "Connected to edge receiver at %s:%d", 
                HOST, 
                PORT, 
            ) 
            chunk_number = 0 
            while True: 
                raw_data = audio.readframes(CHUNK_SIZE) 
                if not raw_data: 
                    break 
                encrypted_data = encrypt(raw_data, key) 
                send_message(sock, encrypted_data) 
                chunk_number += 1 
                logger.info( 
                    "Sent chunk %d: %d bytes -> %d encrypted bytes", 
                    chunk_number, 
                    len(raw_data), 
                    len(encrypted_data), 
                ) 
                # Simulate sensor transmission speed. 
                time.sleep(SEND_DELAY) 
            # Send a zero-length message to indicate completion. 
            sock.sendall(struct.pack("!I", 0)) 
            logger.info( 
                "Finished sending %d chunks", 
                chunk_number, 
            ) 

def main() -> None: 
    parser = argparse.ArgumentParser( 
        description="Simulated audio sensor" 
    ) 
    parser.add_argument( 
        "audio_file", 
        type=Path, 
        help="Path to a WAV audio file", 
    ) 
    args = parser.parse_args() 
    if not args.audio_file.exists(): 
        logger.error("Audio file does not exist: %s", args.audio_file) 
        return 
    if args.audio_file.suffix.lower() != ".wav": 
        logger.error("Only WAV files are supported") 
        return 
    try: 
        run_sensor(args.audio_file) 
    except ConnectionRefusedError: 
        logger.error( 
            "Could not connect to edge receiver. " 
            "Make sure it is running first." 
        ) 
    except Exception: 
        logger.exception("Sensor failed") 

if __name__ == "__main__": 
    main()
