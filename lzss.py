import io
from enum import Enum
from typing import List, Generator

class LzssMode(Enum):
    Decompress = 0
    Compress = 1

class LzssSettings:
    def __init__(self):
        self.frame_size = 0x1000
        self.frame_fill = 0
        self.frame_init_pos = 0xFEE

class LzssCoroutine:
    def __init__(self):
        self.input = None
        self.settings = None
        self.buffer = bytearray()
        self.pos = 0
        self.length = 0

    def initialize(self, input_stream):
        self.input = input_stream
        self.settings = LzssSettings()

    def unpack(self) -> Generator[int, None, None]:
        frame = bytearray([self.settings.frame_fill] * self.settings.frame_size)
        frame_pos = self.settings.frame_init_pos
        frame_mask = self.settings.frame_size - 1

        while True:
            ctl = self.input.read(1)
            if not ctl:
                return
            ctl = ord(ctl)

            for bit in range(8):
                if ctl & (1 << bit):
                    b = self.input.read(1)
                    if not b:
                        return
                    b = ord(b)
                    frame[frame_pos & frame_mask] = b
                    frame_pos += 1
                    self.buffer.append(b)
                    self.pos += 1
                    self.length -= 1
                    if self.length == 0:
                        yield self.pos
                else:
                    lo = self.input.read(1)
                    if not lo:
                        return
                    hi = self.input.read(1)
                    if not hi:
                        return
                    lo, hi = ord(lo), ord(hi)
                    offset = ((hi & 0xf0) << 4) | lo
                    for _ in range(3 + (hi & 0xF)):
                        v = frame[offset & frame_mask]
                        offset += 1
                        frame[frame_pos & frame_mask] = v
                        frame_pos += 1
                        self.buffer.append(v)
                        self.pos += 1
                        self.length -= 1
                        if self.length == 0:
                            yield self.pos

class LzssStream:
    def __init__(self, input_stream, mode=LzssMode.Decompress, leave_open=False):
        if mode != LzssMode.Decompress:
            raise NotImplementedError("LzssStream compression not implemented")
        self.reader = LzssCoroutine()
        self.reader.initialize(input_stream)
        self.leave_open = leave_open

    @property
    def config(self):
        return self.reader.settings

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        if not self.leave_open:
            self.reader.input.close()

class LzssReader:
    def __init__(self, input_stream, input_length, output_length):
        self.input = io.BytesIO(input_stream.read(input_length))
        self.output = bytearray(output_length)
        self.size = input_length
        self.frame_size = 0x1000
        self.frame_fill = 0
        self.frame_init_pos = 0xfee

    def unpack(self):
        dst = 0
        frame = bytearray([self.frame_fill] * self.frame_size)
        frame_pos = self.frame_init_pos
        frame_mask = self.frame_size - 1
        remaining = self.size

        while remaining > 0:
            ctl = self.input.read(1)[0]
            remaining -= 1

            for bit in range(8):
                if dst >= len(self.output):
                    return

                if ctl & (1 << bit):
                    if remaining == 0:
                        return
                    b = self.input.read(1)[0]
                    remaining -= 1
                    frame[frame_pos] = b
                    frame_pos = (frame_pos + 1) & frame_mask
                    self.output[dst] = b
                    dst += 1
                else:
                    if remaining < 2:
                        return
                    lo, hi = self.input.read(2)
                    remaining -= 2
                    offset = ((hi & 0xf0) << 4) | lo
                    for _ in range(3 + (hi & 0xF)):
                        if dst >= len(self.output):
                            break
                        v = frame[offset]
                        offset = (offset + 1) & frame_mask
                        frame[frame_pos] = v
                        frame_pos = (frame_pos + 1) & frame_mask
                        self.output[dst] = v
                        dst += 1

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.input.close()
