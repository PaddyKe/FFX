from .FF1 import *
from .FF3_1 import *
from .utils.FFXBase import FFXBase
from .utils import string_to_numeral_string, numeral_string_to_string

def encrypt(crypter: FFXBase, plaintext, alphabet, **kwargs):
    return numeral_string_to_string(  # Convert numerals back to original format
        crypter.encrypt( # encrypt using format preserving encryption
            string_to_numeral_string( # convert string to numeral string
                plaintext,
                {value: key for key, value in enumerate(alphabet)}
                ),
            **kwargs
            ),
            alphabet
    )


def decrypt(crypter: FFXBase, ciphertext, alphabet, **kwargs):
    return numeral_string_to_string(  # Convert numerals back to original format
        crypter.decrypt( # encrypt using format preserving encryption
            string_to_numeral_string( # convert string to numeral string
                ciphertext,
                {value: key for key, value in enumerate(alphabet)}
                ),
            **kwargs
            ),
            alphabet
    )