import unittest
from FFX import *
import string
from cryptography.hazmat.primitives.ciphers import algorithms

# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF1samples.pdf
class TestFF1(unittest.TestCase):
    # AES 128 Bit
    def test_FF1_saple1(self):
        key = bytes([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C])
        radix = 10
        maxTlen = 10
        minLen = 6
        maxLen = 10
        tweak = b''
        pt = '0123456789'
        expected = '2433477484'
        alphabet = string.digits
        cipher = FF1(algorithms.AES, radix, maxTlen, (minLen, maxLen))

        ct = encrypt(cipher, pt, alphabet, tweak=tweak, key=key)
        self.assertEqual(len(ct), len(pt))
        self.assertEqual(ct, expected)

        _pt = decrypt(cipher, ct, alphabet, tweak=tweak, key=key)
        self.assertEqual(len(_pt), len(pt))
        self.assertEqual(pt, _pt)
        

    def test_FF1_saple2(self):
        key = bytes([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C])
        radix = 10
        maxTlen = 10
        minLen = 6
        maxLen = 10
        tweak = bytes([0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30])
        pt = '0123456789'
        expected = '6124200773'
        alphabet = string.digits
        cipher = FF1(algorithms.AES, radix, maxTlen, (minLen, maxLen))

        ct = encrypt(cipher, pt, alphabet, tweak=tweak, key=key)
        self.assertEqual(len(ct), len(pt))
        self.assertEqual(ct, expected)

        _pt = decrypt(cipher, ct, alphabet, tweak=tweak, key=key)
        self.assertEqual(len(_pt), len(pt))
        self.assertEqual(pt, _pt)

    def test_FF1_saple3(self):
        key = bytes([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C])
        radix = 36
        maxTlen = 11
        minLen = 6
        maxLen = 20
        tweak = bytes([0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37])
        pt = '0123456789abcdefghi'
        expected = 'a9tv40mll9kdu509eum'
        alphabet = '0123456789abcdefghijklmnopqrstuvwxyz'
        cipher = FF1(algorithms.AES, radix, maxTlen, (minLen, maxLen))

        ct = encrypt(cipher, pt, alphabet, tweak=tweak, key=key)
        self.assertEqual(len(ct), len(pt))
        self.assertEqual(ct, expected)

        _pt = decrypt(cipher, ct, alphabet, tweak=tweak, key=key)
        self.assertEqual(len(_pt), len(pt))
        self.assertEqual(pt, _pt)
    

    def test_FF1_saple4(self):
        key = bytes([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C])
        radix = 36
        maxTlen = 11
        minLen = 6
        maxLen = 20
        tweak = bytes([0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37])
        pt = '0123456789abcdefghi'
        expected = 'a9tv40mll9kdu509eum'
        alphabet = '0123456789abcdefghijklmnopqrstuvwxyz'
        cipher = FF1(algorithms.AES, radix, maxTlen, (minLen, maxLen))

        ct = encrypt(cipher, pt, alphabet, tweak=tweak, key=key)
        self.assertEqual(len(ct), len(pt))
        self.assertEqual(ct, expected)

        _pt = decrypt(cipher, ct, alphabet, tweak=tweak, key=key)
        self.assertEqual(len(_pt), len(pt))
        self.assertEqual(pt, _pt)






    # AES 192Bit
    def test_FF1_saple5(self):
        key = bytes([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F])
        radix = 10
        maxTlen = 10
        minLen = 6
        maxLen = 10
        tweak = b''
        pt = '0123456789'
        expected = '2830668132'
        alphabet = string.digits
        cipher = FF1(algorithms.AES, radix, maxTlen, (minLen, maxLen))

        ct = encrypt(cipher, pt, alphabet, tweak=tweak, key=key)
        self.assertEqual(len(ct), len(pt))
        self.assertEqual(ct, expected)

        _pt = decrypt(cipher, ct, alphabet, tweak=tweak, key=key)
        self.assertEqual(len(_pt), len(pt))
        self.assertEqual(pt, _pt)
        

    def test_FF1_saple6(self):
        key = bytes([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F])
        radix = 36
        maxTlen = 16
        minLen = 6
        maxLen = 20
        tweak = bytes([0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37])
        pt = '0123456789abcdefghi'
        expected = 'xbj3kv35jrawxv32ysr'
        alphabet = '0123456789abcdefghijklmnopqrstuvwxyz'
        cipher = FF1(algorithms.AES, radix, maxTlen, (minLen, maxLen))

        ct = encrypt(cipher, pt, alphabet, tweak=tweak, key=key)
        self.assertEqual(len(ct), len(pt))
        self.assertEqual(ct, expected)

        _pt = decrypt(cipher, ct, alphabet, tweak=tweak, key=key)
        self.assertEqual(len(_pt), len(pt))
        self.assertEqual(pt, _pt)
    






    # AES 256Bit
    def test_FF1_saple7(self):
        key = bytes([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F, 0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94])
        radix = 10
        maxTlen = 10
        minLen = 6
        maxLen = 10
        tweak = b''
        pt = '0123456789'
        expected = '6657667009'
        alphabet = string.digits
        cipher = FF1(algorithms.AES, radix, maxTlen, (minLen, maxLen))

        ct = encrypt(cipher, pt, alphabet, tweak=tweak, key=key)
        self.assertEqual(len(ct), len(pt))
        self.assertEqual(ct, expected)

        _pt = decrypt(cipher, ct, alphabet, tweak=tweak, key=key)
        self.assertEqual(len(_pt), len(pt))
        self.assertEqual(pt, _pt)
        

    def test_FF1_saple8(self):
        key = bytes([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F, 0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94])
        radix = 10
        maxTlen = 16
        minLen = 6
        maxLen = 20
        tweak = bytes([0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30])
        pt = '0123456789'
        expected = '1001623463'
        alphabet = '0123456789'
        cipher = FF1(algorithms.AES, radix, maxTlen, (minLen, maxLen))

        ct = encrypt(cipher, pt, alphabet, tweak=tweak, key=key)
        self.assertEqual(len(ct), len(pt))
        self.assertEqual(ct, expected)

        _pt = decrypt(cipher, ct, alphabet, tweak=tweak, key=key)
        self.assertEqual(len(_pt), len(pt))
        self.assertEqual(pt, _pt)
    


    def test_FF1_saple6(self):
        key = bytes([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C, 0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F, 0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94])
        radix = 36
        maxTlen = 16
        minLen = 6
        maxLen = 20
        tweak = bytes([0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37])
        pt = '0123456789abcdefghi'
        expected = 'xs8a0azh2avyalyzuwd'
        alphabet = '0123456789abcdefghijklmnopqrstuvwxyz'
        cipher = FF1(algorithms.AES, radix, maxTlen, (minLen, maxLen))

        ct = encrypt(cipher, pt, alphabet, tweak=tweak, key=key)
        self.assertEqual(len(ct), len(pt))
        self.assertEqual(ct, expected)

        _pt = decrypt(cipher, ct, alphabet, tweak=tweak, key=key)
        self.assertEqual(len(_pt), len(pt))
        self.assertEqual(pt, _pt)
    
