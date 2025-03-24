import struct

class CHACHA20():
    key = 0
    iv = 0
    OVER = 0xffffffff
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv
        
    def split_key(self):
        num = self.key

        num = num & ((1 << 256) - 1)        
        chunks = []
        for i in range(8):
            chunk = (num >> (256 - (32 * (i+1)))) & self.OVER
            chunks.append(chunk)
        
        return chunks
        
    def rotate(self, v, c):
        return ((v << c) & self.OVER) | v >> (32 - c)

    def qr(self, x, ai, bi, ci, di):
        a,b,c,d = x[ai],x[bi],x[ci],x[di]
        
        a = (a + b) & self.OVER
        d = self.rotate(d ^ a, 16)
        c = (c + d) & self.OVER
        b = self.rotate(b ^ c, 12)
        a = (a + b) & self.OVER
        d = self.rotate(d ^ a, 8)
        c = (c + d) & self.OVER
        b = self.rotate(b ^ c, 7)
        
        x[ai],x[bi],x[ci],x[di] = a,b,c,d
    def double_r(self, x):
        self.qr(x, 0, 4,  8, 12)
        self.qr(x, 1, 5,  9, 13)
        self.qr(x, 2, 6, 10, 14)
        self.qr(x, 3, 7, 11, 15)
        self.qr(x, 0, 5, 10, 15)
        self.qr(x, 1, 6, 11, 12)
        self.qr(x, 2, 7,  8, 13)
        self.qr(x, 3, 4,  9, 14)
        
    def gen_key(self):
        old_key = [0] * 16
        old_key[:4] = (3398389629, 3398389629, 3398389629, 3398389629)
        old_key[4:12] = self.split_key()
        
        new_key = list(old_key)
        
        for i in range(10):
            self.double_r(new_key)
        
        for i in range(len(new_key)):
            new_key[i] += old_key[i]
        return new_key
    
    def encrypt(self, open_text):
        key = self.gen_key()
        return [key[i] ^ ord(open_text[i]) for i in range(len(open_text))]
    
    def dencrypt(self, cipher_text):
        key = self.gen_key()
        return [key[i] ^ cipher_text[i] for i in range(len(cipher_text))]
        
cha = CHACHA20(0x8C72F7402C885828FE74FF8842EDD64480C23AE0ED776A4F9943253EC17DF8CC, 0)
x = cha.encrypt('hello world')
print(x)
y = cha.dencrypt(x)
print(y)
