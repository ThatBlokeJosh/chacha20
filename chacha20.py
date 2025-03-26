import struct


class CHACHA20():
    key = 0
    iv = 0
    OVER = 0xffffffff

    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def split(self, key, length):
        num = key

        num = num & ((1 << length) - 1)
        chunks = []
        for i in range(length//32):
            chunk = (num >> (length - (32 * (i+1)))) & self.OVER
            chunks.append(chunk)

        return chunks

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

    def gen_key(self, counter=0):
        old_key = [0] * 16
        old_key[:4] = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
        old_key[4:12] = struc
        old_key[12] = counter
        old_key[13:16] = self.split(self.iv, 96)
        print([hex(old_key[i]) for i in range(len(old_key))])

        new_key = list(old_key)

        for i in range(10):
            self.double_r(new_key)

        for i in range(len(new_key)):
            new_key[i] += old_key[i]
        return new_key

    def encrypt(self, open_text, ic=0):
        for i in range(2):
            key = self.gen_key(ic + i)
            print([hex(key[i]) for i in range(len(key))])

    def dencrypt(self, cipher_text):
        key = self.gen_key()
        return [key[i % len(key)] ^ cipher_text[i] for i in range(len(cipher_text))]


cha = CHACHA20(
    0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F,
    0x000000000000004A00000000)
x = cha.encrypt(b'Ladies and Gentlm', 1)
print(x)
