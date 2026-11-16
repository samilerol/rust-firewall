"""Create structural seeds plus independent checksum validation fixtures."""
from pathlib import Path
import struct

out = Path(__file__).parent / 'corpus' / 'packet'
out.mkdir(parents=True, exist_ok=True)
for v6 in (False, True):
    for tcp in (False, True):
        offset = 40 if v6 else 20
        size = 20 if tcp else 8
        packet = bytearray(offset + size)
        if v6:
            packet[0] = 0x60
            packet[4:6] = struct.pack('!H', size)
            packet[6] = 6 if tcp else 17
            packet[23], packet[39] = 1, 2
        else:
            packet[0] = 0x45
            packet[2:4] = struct.pack('!H', len(packet))
            packet[9] = 6 if tcp else 17
            packet[12:16] = bytes([10, 0, 0, 1])
            packet[16:20] = bytes([10, 0, 0, 2])
        packet[offset:offset + 4] = struct.pack('!HH', 1234, 443)
        if tcp:
            packet[offset + 12] = 0x50
        else:
            packet[offset + 4:offset + 6] = struct.pack('!H', size)
        (out / f'ipv{6 if v6 else 4}-{"tcp" if tcp else "udp"}').write_bytes(packet)

fixtures = Path(__file__).resolve().parents[1] / 'crates/netscope-packet/tests/fixtures'
for path in fixtures.glob('*.hex'):
    (out / ('checksum-' + path.stem)).write_bytes(bytes.fromhex(path.read_text()))
for path in fixtures.glob('*.bin'):
    (out / ('checksum-' + path.stem)).write_bytes(path.read_bytes())
