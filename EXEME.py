#!/usr/bin/env python3
import os
import sys
import struct
from pathlib import Path
from typing import List, Tuple, Optional
from dataclasses import dataclass
from lzss import decompress, LZSSError

@dataclass
class EmEntry:
    name: str
    offset: int
    size: int
    unpacked_size: int
    lzss_frame_size: int
    lzss_init_pos: int
    sub_type: int
    is_packed: bool

class EmeArchive:
    SIGNATURE = b'RRED'
    
    def __init__(self, filepath: Path):
        self.filepath = filepath
        self.key: Optional[bytes] = None
        self.entries: List[EmEntry] = []
        
    def read_uint32(self, f, offset: int) -> int:
        f.seek(offset)
        return struct.unpack('<I', f.read(4))[0]
    
    def read_uint16(self, f, offset: int) -> int:
        f.seek(offset)
        return struct.unpack('<H', f.read(2))[0]

    def decrypt(self, buffer: bytearray, offset: int, length: int, routine: bytes) -> None:
        data = memoryview(buffer)[offset:offset+length]
        key_index = len(routine)
        
        for i in range(7, -1, -1):
            key_index -= 4
            key = struct.unpack_from("<I", routine, key_index)[0]
            
            if routine[i] == 1:
                for j in range(0, len(data), 4):
                    struct.pack_into("<I", data, j, struct.unpack_from("<I", data, j)[0] ^ key)
            elif routine[i] == 2:
                for j in range(0, len(data), 4):
                    v = struct.unpack_from("<I", data, j)[0]
                    struct.pack_into("<I", data, j, v ^ key)
                    key = v
            elif routine[i] == 4:
                for j in range(0, len(data), 4):
                    v = struct.unpack_from("<I", data, j)[0]
                    struct.pack_into("<I", data, j, self.shift_value(v, key))
            elif routine[i] == 8:
                self.init_table(data, key)

    def shift_value(self, val: int, key: int) -> int:
        shift = 0
        result = 0
        for i in range(32):
            shift += key
            result |= ((val >> i) & 1) << (shift % 32)
        return result

    def init_table(self, buffer: memoryview, key: int) -> None:
        length = len(buffer)
        table = bytearray(length)
        x = 0
        for i in range(length):
            x = (x + key) % length
            table[x] = buffer[i]
        buffer[:] = table

    def get_null_terminated_string(self, data: bytes, offset: int, max_length: int) -> str:
        end = data.find(b'\0', offset, offset + max_length)
        if end == -1:
            end = offset + max_length
        return data[offset:end].decode('utf-8', errors='replace')

    def open(self) -> bool:
        try:
            with open(self.filepath, 'rb') as f:
                # Check signature
                if f.read(4) != self.SIGNATURE:
                    return False
                if f.read(4) != b'ATA ':
                    return False
                
                # Read file size and entry count
                f.seek(0, 2)
                file_size = f.tell()
                f.seek(file_size - 4)
                entry_count = struct.unpack('<I', f.read(4))[0]
                
                if entry_count > 10000:  # Sanity check
                    return False
                
                # Read key and index
                index_size = entry_count * 0x60
                index_offset = file_size - 4 - index_size
                
                f.seek(index_offset - 40)
                self.key = f.read(40)
                
                f.seek(index_offset)
                index_data = bytearray(f.read(index_size))
                
                # Parse entries
                current_offset = 0
                for _ in range(entry_count):
                    self.decrypt(index_data, current_offset, 0x60, self.key)
                    
                    name = self.get_null_terminated_string(index_data, current_offset, 0x40)
                    lzss_frame_size = struct.unpack_from('<H', index_data, current_offset + 0x40)[0]
                    lzss_init_pos = struct.unpack_from('<H', index_data, current_offset + 0x42)[0]
                    
                    if lzss_frame_size != 0:
                        lzss_init_pos = (lzss_frame_size - lzss_init_pos) % lzss_frame_size
                        
                    sub_type = struct.unpack_from('<I', index_data, current_offset + 0x48)[0]
                    size = struct.unpack_from('<I', index_data, current_offset + 0x4C)[0]
                    unpacked_size = struct.unpack_from('<I', index_data, current_offset + 0x50)[0]
                    offset = struct.unpack_from('<I', index_data, current_offset + 0x54)[0]
                    
                    entry = EmEntry(
                        name=name,
                        offset=offset,
                        size=size,
                        unpacked_size=unpacked_size,
                        lzss_frame_size=lzss_frame_size,
                        lzss_init_pos=lzss_init_pos,
                        sub_type=sub_type,
                        is_packed=unpacked_size != size
                    )
                    
                    self.entries.append(entry)
                    current_offset += 0x60
                
                return True
                
        except Exception as e:
            print(f"Error opening archive: {e}", file=sys.stderr)
            return False

    def extract(self, output_dir: Path) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        
        with open(self.filepath, 'rb') as f:
            for entry in self.entries:
                try:
                    output_path = output_dir / entry.name
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    print(f"Extracting: {entry.name}")
                    
                    if entry.sub_type == 3:  # Script
                        self._extract_script(f, entry, output_path)
                    else:
                        self._extract_regular(f, entry, output_path)
                        
                except Exception as e:
                    print(f"Error extracting {entry.name}: {e}", file=sys.stderr)

    def _extract_script(self, f, entry: EmEntry, output_path: Path) -> None:
        f.seek(entry.offset)
        header = bytearray(f.read(12))
        self.decrypt(header, 0, 12, self.key)
        
        if entry.lzss_frame_size == 0:
            # Not compressed
            with open(output_path, 'wb') as out:
                out.write(header)
                f.seek(entry.offset + 12)
                out.write(f.read(entry.size))
        else:
            unpacked_size = struct.unpack_from('<I', header, 4)[0]
            if unpacked_size != 0 and unpacked_size < entry.unpacked_size:
                # Split compressed data
                packed_size = struct.unpack_from('<I', header, 0)[0]
                part1_size = entry.unpacked_size - unpacked_size
                
                # Read and decompress first part
                f.seek(entry.offset + 12 + packed_size)
                compressed_part1 = f.read(entry.size - packed_size)
                decompressed_part1, _ = decompress(compressed_part1)
                
                # Read and decompress second part
                f.seek(entry.offset + 12)
                compressed_part2 = f.read(packed_size)
                decompressed_part2, _ = decompress(compressed_part2)
                
                # Combine parts
                with open(output_path, 'wb') as out:
                    out.write(decompressed_part1[:part1_size])
                    out.write(decompressed_part2)
            else:
                # Single compressed data
                f.seek(entry.offset + 12)
                compressed_data = f.read(entry.size)
                decompressed_data, _ = decompress(compressed_data)
                
                with open(output_path, 'wb') as out:
                    out.write(decompressed_data)

    def _extract_regular(self, f, entry: EmEntry, output_path: Path) -> None:
        f.seek(entry.offset)
        data = f.read(entry.size)
        
        if entry.is_packed:
            decompressed_data, _ = decompress(data)
            data = decompressed_data
            
        with open(output_path, 'wb') as out:
            out.write(data)

def main():
    if len(sys.argv) != 3:
        print("Usage: python eme_extract.py <archive.eme> <output_directory>")
        sys.exit(1)
    
    archive_path = Path(sys.argv[1])
    output_dir = Path(sys.argv[2])
    
    if not archive_path.exists():
        print(f"Archive file not found: {archive_path}", file=sys.stderr)
        sys.exit(1)
    
    archive = EmeArchive(archive_path)
    if not archive.open():
        print("Failed to open archive", file=sys.stderr)
        sys.exit(1)
    
    archive.extract(output_dir)
    print("Extraction complete!")

if __name__ == '__main__':
    main()
