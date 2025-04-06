import struct


class CHACHA20():
    key = 0
    iv = 0
    ic = 0
    OVER = 0xffffffff

    def __init__(self, key, iv, ic):
        self.key = key
        self.iv = iv
        self.ic = ic

    def split(self, key, length, endians="little"):
        bytes = key.to_bytes(length//8, 'little')
        chunks = []
        for i in range(length//32):
            num = int.from_bytes(bytes[i*4:(i+1)*4])
            chunks.append(num)

        return chunks[::-1]

    def rotate(self, v, c):
        return ((v << c) & self.OVER) | v >> (32 - c)

    def qr(self, x, ai, bi, ci, di):
        a, b, c, d = x[ai], x[bi], x[ci], x[di]

        a = (a + b) & self.OVER
        d = self.rotate(d ^ a, 16)
        c = (c + d) & self.OVER
        b = self.rotate(b ^ c, 12)
        a = (a + b) & self.OVER
        d = self.rotate(d ^ a, 8)
        c = (c + d) & self.OVER
        b = self.rotate(b ^ c, 7)

        x[ai], x[bi], x[ci], x[di] = a, b, c, d

    def double_r(self, x):
        self.qr(x, 0, 4,  8, 12)
        self.qr(x, 1, 5,  9, 13)
        self.qr(x, 2, 6, 10, 14)
        self.qr(x, 3, 7, 11, 15)
        self.qr(x, 0, 5, 10, 15)
        self.qr(x, 1, 6, 11, 12)
        self.qr(x, 2, 7,  8, 13)
        self.qr(x, 3, 4,  9, 14)

    def gen_key(self, counter=1):
        old_key = [0] * 16
        old_key[:4] = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
        old_key[4:12] = self.split(self.key, 256)
        old_key[12] = counter
        old_key[13:16] = self.split(self.iv, 96)

        new_key = list(old_key)
        key_stream = []

        for i in range(10):
            self.double_r(new_key)

        for i in range(len(new_key)):
            new_key[i] = (new_key[i] + old_key[i]) & self.OVER
            byte_array = new_key[i].to_bytes(4, "little")
            for byte in byte_array:
                key_stream.append(byte)
        return key_stream

    def xor(self, text):
        length = len(text)
        block = length//64
        res = bytearray([])

        for i in range(block):
            key = self.gen_key(self.ic + i)
            for j in range(len(key)):
                res.append(key[j] ^ text[j])

        if length % 64 != 0:
            key = self.gen_key(self.ic + block)
            rest = text[64*block:]
            for j in range(len(rest)):
                res.append(key[j] ^ rest[j])

        return res


cha = CHACHA20(0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F,
               0x000000000000004A00000000, 1)
x = cha.xor(b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
print(x.hex())
y = cha.xor(x)
print(y)
