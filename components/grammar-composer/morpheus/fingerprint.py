import struct
import hashlib

from morpheus.utils import token_quality

def hash64(value: int) -> int:
    """Simple 64-bit hash"""
    h = hashlib.md5(value.to_bytes(4, 'little')).digest()
    return int.from_bytes(h[:8], 'little')

class RuleFingerprint:
    # optimize memory usage by avoiding one __dict__ for each instance
    __slots__ = ('bloom', 'xor_hash', 'num_unique', 'num_observations')
    MAX_DISTINCT_OBSERVATIONS = 10

    def __init__(self):
        self.bloom = 0      # 64-bit bloom filter
        self.xor_hash = 0   # XOR of unique value hashes
        self.num_unique = 0      # Unique count
        self.num_observations = 0  # Total observations
        
    def update(self, value: bytes, token_quality_threshold: float = 0.5):
        """Add 4-byte observation"""
        if len(value) != 4:
            # Ensure value is 4 bytes, pad with zeros if necessary
            value = value[:4].ljust(4, b'\x00')

        if token_quality(value) < token_quality_threshold:
            return
        
        self.num_observations += 1
        
        val = struct.unpack('<I', value)[0]
        h = hash64(val)
        
        # Check if potentially new value
        bits = (1 << (h % 64)) | (1 << ((h >> 32) % 64))
        is_new = (self.bloom & bits) != bits
        
        if is_new:
            self.bloom |= bits
            self.xor_hash ^= h
            self.num_unique += 1
            
            # If we exceed the max distinct observations, set count to overflow marker
            if self.num_unique > self.MAX_DISTINCT_OBSERVATIONS:
                self.num_unique = 0xFFFF  # Overflow marker
    
    def to_hex(self) -> str:
        """Get 16-byte fingerprint"""
        if self.num_unique == 0:
            return '00000000000000000000000000000000'
        if self.num_unique > self.MAX_DISTINCT_OBSERVATIONS:
            return 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
        return struct.pack('<QQH', self.xor_hash, self.bloom, self.num_unique)[:16].hex()

    def from_hex(self, hex_str: str):
        """Load from 16-byte hex string"""
        assert len(hex_str) == 32, "Hex string must be 32 characters"
        data = bytes.fromhex(hex_str)
        self.xor_hash, self.bloom, self.num_unique = struct.unpack('<QQH', data)
        
        if self.num_unique > self.MAX_DISTINCT_OBSERVATIONS:
            self.num_unique = 0xFFFF
