import unittest
from FFX import *
import string
from cryptography.hazmat.primitives.ciphers import algorithms

class TestUtils(unittest.TestCase):
    def test_string_to_numeral_string(self):
        inverse_alphabet = {'0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9}
        res = string_to_numeral_string("1234567890", inverse_alphabet)
        self.assertEqual(res, [1, 2, 3, 4, 5, 6, 7, 8, 9, 0])

    def test_string_to_numeral_string_key_error(self):
        inverse_alphabet = {'0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9}
        self.assertRaises(KeyError, string_to_numeral_string, "1234567890A", inverse_alphabet)

    def test_numeral_string_to_string(self):
        res = numeral_string_to_string([1, 2, 3, 4, 5, 6, 7, 8, 9, 0], string.digits)
        self.assertEqual(res, "1234567890")
    
    def test_numeral_string_to_string_key_error(self):
        self.assertRaises(IndexError, numeral_string_to_string, [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 10], string.digits)
    

    def test_numeral_string_string_numeral(self):
        inverse_alphabet = {'0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9}
        alphabet = string.digits
        indata = "1234567890123"
        res = numeral_string_to_string(string_to_numeral_string(indata, inverse_alphabet), alphabet)
        self.assertEqual(res, indata)


    def test_xor(self):
        res = xor([1, 2, 3], [0, 0, 0])
        self.assertEqual(res, bytes([1, 2, 3]))

    def test_xor(self):
        res = xor([1, 2, 3], [1, 2, 3])
        self.assertEqual(res, bytes([0, 0, 0]))
    
    def test_num(self):
        res = num(bytes([1, 1]))
        self.assertEqual(res, 257)
    
    def test_num(self):
        res = num(bytes([255, 255]))
        self.assertEqual(res, 0xffff)
    
    def test_str_radix_m(self):
        self.assertEqual(str_radix_m(559, 4, 12), [0, 3, 10, 7])
    
    def test_str_radix_m_invalid_range(self):
        self.assertRaises(FFXError, str_radix_m, 559, 2, 2)

    def test_prf(self):
        res = prf(algorithms.AES(b'das ist ein test'), b'Das ist eine sehr geheime Nachricht. Nicht weite')
        self.assertEqual(len(res), 16)
        self.assertEqual(res, bytes([0x66, 0xce, 0x95, 0xe2, 0xaf, 0x0c, 0xc8, 0xfb, 0x82, 0x89, 0x0a, 0x88, 0xd9, 0x6e, 0x18, 0x68]))
    
    def test_prf_invalid_length(self):
        self.assertRaises(ValueError, prf, algorithms.AES(b'das ist ein test'), b'Das ist eine sehr geheime Nachricht. Nicht weitersagen!')
    
    def test_num_radix(self):
        res = num_radix([0, 0, 0, 1, 1, 0, 1, 0], 5)
        self.assertEqual(res, 755)