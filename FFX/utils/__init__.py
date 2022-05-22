from .FFXBase import FFXBase
from functools import reduce
from cryptography.hazmat.primitives.ciphers import Cipher, modes
import math

class FFXError(Exception):
    pass


def num_radix(val, radix):
    return reduce(lambda x, c: x * radix + c, val, 0)

def prf(cipher, data):
    # The spec implements cbc mode manually. I'll use the defaule implementation to make use of faster implementations under the hood (in this case OpenSSL)
    # IV = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    encryptor = Cipher(cipher, modes.CBC(bytes([0] * 16))).encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    return ct[-16:]

def xor_generator(a, b):
    return (x ^ y for x, y in zip(a, b))

def xor(a, b):
    return bytes(xor_generator(a, b))

def num(x):
    return int.from_bytes(x, 'big')

def str_radix_m(x, m, radix):
    if not (0 <= x <= radix**m):
        raise FFXError(f'Invalid range for x. x must be within [0, {radix**m}]')

    X = [0] * m
    for i in range(m - 1, -1, -1):
        X[i] = x % radix
        x = x // radix
    return X

def string_to_numeral_string(string, inverse_alphabet):
    return [inverse_alphabet[x] for x in string]

def numeral_string_to_string(numeral_string, alphabet):
    return ''.join(alphabet[x] for x in numeral_string)