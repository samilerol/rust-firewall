"""Independent Python big-integer checksum oracle. Regenerate from repository root.
Fixture addresses: RFC 5737/RFC 3849 documentation ranges. No real traffic.
"""
from pathlib import Path
import ipaddress
import struct

OUT = Path(__file__).resolve().parents[1] / 'crates/netscope-packet/tests/fixtures'

def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def datagram(v6, tcp, payload, options=False):
    version = 6 if v6 else 4
    src = ipaddress.ip_address('2001:db8::1' if v6 else '192.0.2.1').packed
    dst = ipaddress.ip_address('2001:db8::2' if v6 else '198.51.100.2').packed
    protocol = 6 if tcp else 17
    if tcp:
        size = 24 if options else 20
        transport = bytearray(struct.pack('!HHIIBBHHH', 12345, 443, 0x12345678, 0, (size // 4) << 4, 2, 4096, 0, 0))
        if options:
            transport += bytes([1, 1, 1, 1])
        checksum_offset = 16
    else:
        transport = bytearray(struct.pack('!HHHH', 12345, 53, 8 + len(payload), 0))
        checksum_offset = 6
    transport += payload
    length = len(transport)
    pseudo = src + dst + (struct.pack('!I3xB', length, protocol) if v6 else struct.pack('!BBH', 0, protocol, length))
    value = checksum(pseudo + transport)
    # UDP calculated zero is represented on wire as all ones, never zero.
    transport[checksum_offset:checksum_offset+2] = struct.pack('!H', value or (0xffff if not tcp else 0))
    if v6:
        header = struct.pack('!IHBB', 6 << 28, length, protocol, 64) + src + dst
    else:
        header = bytearray(struct.pack('!BBHHHBBH', 0x45, 0, 20+length, 0x1234, 0x4000, 64, protocol, 0) + src + dst)
        header[10:12] = struct.pack('!H', checksum(header))
    return bytes(header + transport)

if __name__ == '__main__':
    assert checksum(bytes.fromhex('0001f203f4f5f6f7')) == 0x220d  # RFC 1071
    OUT.mkdir(parents=True, exist_ok=True)
    for v6 in [False, True]:
        for tcp in [False, True]:
            for name, payload in [('empty', b''), ('odd', b'abc'), ('even', b'abcd')]:
                data = datagram(v6, tcp, payload)
                (OUT / f'v{6 if v6 else 4}-{"tcp" if tcp else "udp"}-{name}.hex').write_text(data.hex() + '\n')
    (OUT / 'v6-tcp-options.hex').write_text(datagram(True, True, b'abc', options=True).hex() + '\n')
    # Exercise the largest non-jumbo IPv6 transport length and long carry accumulation.
    (OUT / 'v6-udp-max.bin').write_bytes(datagram(True, False, b'\xff' * (65535 - 8)))
    (OUT / 'v4-tcp-max.bin').write_bytes(datagram(False, True, b'\xff' * (65535 - 40)))
    # Solve the last payload word so the calculated UDP checksum is zero.
    for word in range(65536):
        data = datagram(True, False, struct.pack('!H', word))
        if data[46:48] == b'\xff\xff':
            (OUT / 'v6-udp-negative-zero.hex').write_text(data.hex() + '\n')
            break
    else:
        raise AssertionError('No negative-zero fixture found')

    # Valid IPv4 header but stale TCP pseudo-header after source-address mutation.
    bad = bytearray(datagram(False, True, b'abc'))
    bad[12] ^= 1
    bad[10:12] = b'\x00\x00'
    bad[10:12] = struct.pack('!H', checksum(bad[:20]))
    (OUT / 'v4-tcp-bad-pseudo.hex').write_text(bad.hex() + '\n')
    for word in range(65536):
        data = datagram(True, True, struct.pack('!H', word))
        if data[56:58] == b'\x00\x00':
            (OUT / 'v6-tcp-zero-checksum.hex').write_text(data.hex() + '\n')
            break
    else:
        raise AssertionError('No valid zero TCP checksum fixture found')
