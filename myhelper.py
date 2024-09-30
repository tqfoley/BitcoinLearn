
from io import BytesIO
import base58
import urllib.request

# Chapter 13 from Programming Bitcoin book https://github.com/jimmysong/programmingbitcoin/blob/master/ch13.asciidoc
from ch13.helper import hash256
from ch13.tx import Tx
from ch13.ecc import S256Point, PrivateKey, Signature

G = S256Point(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)


def count_hex_bytes(input_string):
    count = int(len(input_string)/2)
    return hex(count)[2:]

def reverse_hex_string_and_every_two_chars_to_swap_endianness(s): # big endian to little endian and vice versa on hexidecimal strings https://en.wikipedia.org/wiki/Endianness
    result = ''
    for i in range(0, len(s), 2):
        pair = s[i:i+2]
        result += pair[::-1]
    return result[::-1]

def count_chars_and_checksum(input_string):
    # Count the number of digits in the input string
    digit_count = sum(char.isdigit() or char.isalpha() for char in input_string)
    # Sum the ASCII values of all characters in the string
    total = sum(ord(char) for char in input_string)
    # Calculate the checksum by taking the total modulo
    checksum = total % 10000    
    # Return the checksum as a two-digit string
    #print(str(digit_count) + "_C" + f"{checksum:04}")
    return str(digit_count) + "_C" + f"{checksum:04}"

def sats_in_hex(input_string):
    try:
        # Convert the string to an integer
        number = int(input_string)
        # Convert the integer to hexadecimal and format with leading zeros
        hex_value = f"{number:016x}"  # 16 characters wide, uppercase, padded with zeros
        return hex_value
    except ValueError:
        return "Invalid input"
