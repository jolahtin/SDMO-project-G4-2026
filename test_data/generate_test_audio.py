import math
import wave
from pathlib import Path

import struct

OUTPUT = Path(__file__).resolve().parent / "test_audio.wav"
SAMPLE_RATE = 16000
DURATION_SECONDS = 5
FREQUENCY = 440
AMPLITUDE = 12000


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with wave.open(str(OUTPUT), "wb") as audio:
        audio.setnchannels(1)
        audio.setsampwidth(2)
        audio.setframerate(SAMPLE_RATE)

        frames = bytearray()
        for i in range(SAMPLE_RATE * DURATION_SECONDS):
            value = int(
                AMPLITUDE * math.sin(
                    2 * math.pi * FREQUENCY * i / SAMPLE_RATE
                )
            )
            frames.extend(struct.pack("<h", value))

        audio.writeframes(frames)

    print(f"Created test audio: {OUTPUT}")


if __name__ == "__main__":
    main()