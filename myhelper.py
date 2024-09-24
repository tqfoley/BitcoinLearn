
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
    digit_count = sum(char.isdigit() for char in input_string)
    # Sum the ASCII values of all characters in the string
    total = sum(ord(char) for char in input_string)
    # Calculate the checksum by taking the total modulo
    checksum = total % 10000    
    # Return the checksum as a two-digit string
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