# coding=utf-8
import struct
import random
from dataclasses import dataclass


@dataclass(repr=True)
class ICMPPackage:
    type: int
    code: int

    @classmethod
    def from_bytes(cls, data):
        return cls(*struct.unpack('!BB', data[:2]))

    def checksum(self):
        package = struct.pack('!2BH', self.type, self.code, 0)
        accum = 0
        for i in range(0, len(package), 2):
            accum += (package[i] << 8) + package[i + 1]
        checksum = (accum >> 16) + (accum & 0xffff)
        return checksum & 0xffff

    def compress(self):
        checksum = self.checksum()
        return struct.pack('!2B3H', self.type, self.code, checksum, 1,
                           random.randint(256, 3000))
