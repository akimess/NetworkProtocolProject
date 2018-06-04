def bitstring_to_bytes(s):
    s = ''.join(str(i) for i in s)
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])

def nb(i, length=0):
    bytes = ""
    for _ in xrange(length):
        bytes = chr(i & 0xff) + bytes
        i >>= 8
    return bytes

def bn(bytes):
    num = 0
    for byte in bytes:
        num <<= 8
        num |= ord(byte)
    return num