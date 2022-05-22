from ..utils import *
import math
from cryptography.hazmat.primitives.ciphers import Cipher, modes

class FF3_1(FFXBase):
    def __init__(self, cipher, radix, messageLenghth):
        self.cipher = cipher
        self.radix = radix

        if self.radix < 2 or self.radix > 2**16:
            raise FFXError(f'The alphabeth length (radix) has to be within [2, {2**16}]')
        
        self.minlen = messageLenghth[0]
        self.maxlen = messageLenghth[1]

        # 1000000 is defined in the spec as security margin
        if self.radix**self.minlen < 1000000:
            raise FFXError(f'For the given radix, the minimal message length must be at least {math.ceil(math.log2(self.radix) / self.log2(self.minlen))}')


        upper_limit = 2 * math.floor(math.log(2**96, self.radix))
        if not (2 <= self.minlen <= self.maxlen <= upper_limit):
            raise FFXError(f'Requirements for message length not met: 2 <= minlen ({self.minlen}) <= maxlen ({self.maxlen}) <= {upper_limit}')



    def encrypt(self, data, key: bytes, tweak: bytes):
        n = len(data)
        t = len(tweak)
        encryptor = Cipher(self.cipher(key[::-1]), modes.ECB()).encryptor()
        if not (self.minlen <= n <= self.maxlen):
            raise FFXError(f'Plaintext length invalid. The plaintext length must be between {self.minlen} and {self.maxlen}. Given: {n}')
        
        if len(tweak) != 7:
            raise FFXError(f'Tweak length invalid. Tweak must have length 7. Privided: {len(tweak)}')

        u = n // 2
        v = n - u
        A, B = data[:u], data[u:]
        
        #prepare tweak
        Tl = bytearray(tweak[:4])
        Tl[3] = Tl[3] & 0xf0
        Tr = bytearray(tweak[4:])
        Tr.append((tweak[4] & 0x0f) << 4)

        for i in range(8):
            if i % 2 == 0:
                m = u
                W = Tr
            else:
                m = v
                W = Tl
            
            P = xor(W, i.to_bytes(4, 'big')) + num_radix(B[::-1], self.radix).to_bytes(12, 'big')
            S = encryptor.update(P[::-1])[::-1]
            y = num(S)
            c = (num_radix(A[::-1], self.radix) + y) %  self.radix**m
            C = str_radix_m(c, m, self.radix)[::-1]

            A = B
            B = C
        
        return A + B
        


    


    def decrypt(self,data, key, tweak):
        n = len(data)
        t = len(tweak)
        encryptor = Cipher(self.cipher(key[::-1]), modes.ECB()).encryptor()
        if not (self.minlen <= n <= self.maxlen):
            raise FFXError(f'Plaintext length invalid. The plaintext length must be between {self.minlen} and {self.maxlen}. Given: {n}')
        
        if len(tweak) != 7:
            raise FFXError(f'Tweak length invalid. Tweak must have length 7. Privided: {len(tweak)}')

        u = n // 2
        v = n - u
        A, B = data[:u], data[u:]

        #prepare tweak
        Tl = bytearray(tweak[:4])
        Tl[3] = Tl[3] & 0xf0
        Tr = bytearray(tweak[4:])
        Tr.append((tweak[4] & 0x0f) << 4)

        for i in range(7, -1, -1):
            if i % 2 == 0:
                m = u
                W = Tr
            else:
                m = v
                W = Tl
            
            P = xor(W, i.to_bytes(4, 'big')) + num_radix(A[::-1], self.radix).to_bytes(12, 'big')
            S = encryptor.update(P[::-1])[::-1]
            y = num(S)
            c = (num_radix(B[::-1], self.radix) - y) %  self.radix**m
            C = str_radix_m(c, m, self.radix)[::-1]
            
            B = A
            A = C
        
        return A + B
