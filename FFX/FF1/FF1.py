from ..utils import *
import math
from itertools import cycle
from cryptography.hazmat.primitives.ciphers import Cipher, modes

class FF1(FFXBase):
    def __init__(self, cipher, radix, maxTlen, messageLenghth):
        self.cipher = cipher
        self.radix = radix

        if self.radix < 2 or self.radix > 2**16:
            raise FFXError(f'The alphabeth length (radix) has to be within [2, {2**16}]')
        
        self.minlen = messageLenghth[0]
        self.maxlen = messageLenghth[1]

        # 1000000 is defined in the spec as security margin
        if self.radix**self.minlen < 1000000:
            raise FFXError(f'For the given radix, the minimal message length must be at least {math.ceil(math.log2(1000000) / math.log2(self.radix))}')

        if not (2 <= self.minlen <= self.maxlen <= 2**32):
            raise FFXError(f'Requirements for message length not met: 2 <= minlen ({self.minlen}) <= maxlen ({self.maxlen}) <= {2**32}')

        self.maxTlen = maxTlen


    def encrypt(self, data, key: bytes, tweak: bytes):
        n = len(data)
        t = len(tweak)
        encryptor = Cipher(self.cipher(key), modes.ECB()).encryptor()
        if not (self.minlen <= n <= self.maxlen):
            raise FFXError(f'Plaintext length invalid. The plaintext length must be between {self.minlen} and {self.maxlen}. Given: {n}')
        
        if len(tweak) > self.maxTlen:
            raise FFXError(f'Tweak to long. Maximum allowed length: {self.maxTlen}')

        u = n // 2
        v = n - u
        A, B = data[:u], data[u:]
        b = math.ceil(math.ceil(v * math.log2(self.radix)) / 8)
        d = 4 * math.ceil(b / 4) + 4

        P = bytes([1,2,1]) + self.radix.to_bytes(3, 'big') + bytes([10, u % 256]) + n.to_bytes(4, 'big') + t.to_bytes(4, 'big')
        
        # 10 rounds
        for i in range(10):
            Q = tweak + (0).to_bytes((-t - b - 1) % 16, 'big') + i.to_bytes(1, 'big') + num_radix(B, self.radix).to_bytes(b, 'big')
            R = prf(self.cipher(key), P + Q)
            R_cycle = cycle(R)
            S = (R + b''.join(
                    encryptor.update(xor(R_cycle, bytes(tmp.to_bytes(16, 'big')))) for tmp in range(1, (d // 16) + 1)
                    )
                )[:d]

            y = num(S)

            if i % 2 == 0:
                m = u
            else:
                m = v
            
            c = (num_radix(A, self.radix) + y) % self.radix**m
            C = str_radix_m(c, m, self.radix)
            
            A = B
            B = C
        
        return A + B
    


    def decrypt(self,data, key, tweak):
        n = len(data)
        t = len(tweak)
        encryptor = Cipher(self.cipher(key), modes.ECB()).encryptor()

        if not (self.minlen <= n <= self.maxlen):
            raise FFXError(f'Ciphertext length invalid. The ciphertext length must be between {self.minlen} and {self.maxlen}. Given: {n}')
        
        if len(tweak) > self.maxTlen:
            raise FFXError(f'Tweak to long. Maximum allowed length: {self.maxTlen}')

        u = n // 2
        v = n - u
        A, B = data[:u], data[u:]
        b = math.ceil(math.ceil(v * math.log2(self.radix)) / 8)
        d = 4 * math.ceil(b / 4) + 4

        P = bytes([1,2,1]) + self.radix.to_bytes(3, 'big') + bytes([10, u % 256]) + n.to_bytes(4, 'big') + t.to_bytes(4, 'big')

        # 10 rounds
        for i in range(9, -1, -1):
            Q = tweak + (0).to_bytes((-t - b - 1) % 16, 'big') + i.to_bytes(1, 'big') + num_radix(A, self.radix).to_bytes(b, 'big')
            R = prf(self.cipher(key), P + Q)
            R_cycle = cycle(R)
            S = (R + b''.join(
                    encryptor.update(xor(R_cycle, bytes(tmp.to_bytes(16, 'big')))) for tmp in range(1, (d // 16) + 1)
                    )
                )[:d]
            
            y = num(S)
            if i % 2 == 0:
                m = u
            else:
                m = v
            
            c = (num_radix(B, self.radix) - y) % self.radix**m
            C = str_radix_m(c, m, self.radix)
            B = A
            A = C

        return A + B
    
