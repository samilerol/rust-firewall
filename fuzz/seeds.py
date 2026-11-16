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

dns_out = Path(__file__).parent / 'corpus' / 'dns'
dns_out.mkdir(parents=True, exist_ok=True)
query = bytes.fromhex('123401000001000000000000074578616d706c6503434f4d0000010001')
response = bytearray(query)
response[2:4] = bytes.fromhex('8180')
response[7] = 1
response += bytes.fromhex('c00c000100010000003c000401020304')
(dns_out / 'query').write_bytes(query)
(dns_out / 'compressed-answer').write_bytes(response)
(dns_out / 'compression-cycle').write_bytes(bytes(12) + bytes.fromhex('c00c'))
edns = bytearray(query)
edns[11] = 1
edns += bytes.fromhex('00002904d0000080000004000a0000')
(dns_out / 'edns-query').write_bytes(edns)

tcp_out = Path(__file__).parent / 'corpus' / 'tcp'
tcp_out.mkdir(parents=True, exist_ok=True)
(tcp_out / 'control-pattern').write_bytes(bytes(range(256)))
(tcp_out / 'empty').write_bytes(b'')
(tcp_out / 'fin-reset-pressure').write_bytes(bytes([255]) * 1024)
(tcp_out / 'valid-syn').write_bytes(bytes.fromhex((fixtures / 'v4-tcp-empty.hex').read_text()))
