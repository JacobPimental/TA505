import r2pipe
import struct

# Global variables used in the check function
var_1 = 0
var_2 = 0

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

def tohex(x):
  return (x + (1 << 32)) % (1 << 32)

def check(data, i):
    """Peforms check based on current index of data

    Arguments:
        data -- The data that we are performing the check on
        i -- The current index of the data that we are looping through

    Returns:
        tuple of value a and modified i
    """
    global var_1
    global var_2
    a = var_1
    var_1 -= 1
    if a == 0:
        var_2 = data[i]
        i += 1
        var_1 = 7
    b = var_2 >> 7
    b = b & 1
    var_2 = var_2 << 1
    return (b, i)

def check2(dat, i):
    """Performs check based on current index using the previous check function

    Arguments:
        dat -- The data we are performing the check on
        i -- The current index of the data we are looping through

    Returns:
        tuple of value a and modified i
    """
    var_4h = 1
    while True:
        (a, i) = check(dat, i)
        var_4h = a + (var_4h*2)
        (a, i) = check(dat, i)
        if a == 0:
            break
    return (var_4h, i)

def compress_data(data):
    """Compresses data

    Arguments:
        data -- The data to be compressed

    Returns:
        byte array of compressed data
    """
    compressed_data = b''

    x = 0
    while x < len(data):
        if x % 2 == 0:
            x += 2
        compressed_data += bytes([data[x]])
        x += 1
    return compressed_data


def dword_decrypt(data, key):
    """Performs an xor decryption on each dword in the data provided

    Arguments:
        data -- The data to decrypt
        key -- The key used to decrypt the data

    Returns:
        byte array of the decrypted data
    """
    unencrypted = b''

    for i in range(0,len(data)-4,4):
        d = int(data[i:i+4][::-1].hex(), 16)
        c = d ^ key
        c = rol(c, 4, 32)
        c += 0x77777778
        c = c & 0xffffffff
        unencrypted += struct.pack('<I',c)
    return unencrypted


def deobfuscation(data):
    """Deobfuscates data using the method used in the Get2 downloader

    Arguments:
        data -- a list of integers to be deobfuscated

    Returns:
        a byte array of the deobfuscated data
    """
    decrypted = [0 for x in range(len(data))]
    decrypted[0] = data[0]
    dec_i = 1
    enc_i = 1
    var_ch = -1
    var_4h = 0
    end = False
    while not end:
        (a, enc_i) = check(data, enc_i)
        if a != 0:
            (a, enc_i) = check(data, enc_i)
            if a != 0:
                (a, enc_i) = check(data, enc_i)
                if a != 0:
                    var_14h = 0
                    var_8h = 4
                    while var_8h != 0:
                        (a, enc_i) = check(data, enc_i)
                        var_14h = a + (var_14h*2)
                        var_8h -= 1
                    if var_14h == 0:
                        decrypted[dec_i] = 0
                        dec_i += 1
                    else:
                        decrypted[dec_i] = decrypted[dec_i-var_14h]
                        dec_i += 1
                    var_4h = 0
                else:
                    var_14h = data[enc_i]
                    enc_i += 1
                    var_10h = (var_14h & 1) + 2
                    var_14h = var_14h >> 1
                    if var_14h == 0:
                        end = True
                        var_ch = var_14h
                        var_4h = 1
                    else:
                        while var_10h != 0:
                            decrypted[dec_i] = decrypted[dec_i-var_14h]
                            dec_i += 1
                            var_10h -= 1
                        var_ch = var_14h
                        var_4h = 1

            else:
                (a, enc_i) = check2(data, enc_i)
                var_14h = a
                if var_4h == 0 and var_14h == 2:
                    var_14h = var_ch
                    (a, enc_i) = check2(data, enc_i)
                    var_10h = a
                    while var_10h != 0:
                        decrypted[dec_i] = decrypted[dec_i-var_14h]
                        dec_i += 1
                        var_10h -= 1
                    var_4h = 1
                else:
                    if var_4h == 0:
                        var_14h -= 3
                    else:
                        var_14h -= 2
                    var_14h = var_14h << 8
                    var_14h = data[enc_i] + var_14h
                    enc_i += 1
                    (a, enc_i) = check2(data, enc_i)
                    var_10h = a
                    if var_14h >= 0x7d00:
                        var_10h += 1
                    if var_14h >= 0x500:
                        var_10h += 1
                    if var_14h < 0x80:
                        var_10h += 2
                    while var_10h != 0:
                        decrypted[dec_i] = decrypted[dec_i-var_14h]
                        dec_i += 1
                        var_10h -= 1
                    var_ch = var_14h
                    var_4h = 1
        else:
            decrypted[dec_i] = data[enc_i]
            dec_i += 1
            enc_i += 1
            var_4h = 0
    decrypted = bytes(decrypted)
    return decrypted


if __name__ == '__main__':
    r2 = r2pipe.open("mal1.dll")

    encrypted_data = bytes(r2.cmdj('pxj 0x3c870 @ 0x10005238'))

    compressed_data = compress_data(encrypted_data)
    unencrypted = dword_decrypt(encrypted_data, 0x4178)

    f = open("out2.bin", 'wb')
    f.write(unencrypted)
    f.close()

    encrypted = list(unencrypted)
    decrypted = deobfuscation(encrypted)
    f = open("payload.bin", "wb")
    f.write(decrypted)
    f.close()
