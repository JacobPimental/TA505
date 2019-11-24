import r2pipe
import struct

var_1 = 0
var_2 = 0

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

def tohex(x):
  return (x + (1 << 32)) % (1 << 32)

def check(data, i):
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
    var_4h = 1
    while True:
        (a, i) = check(dat, i)
        var_4h = a + (var_4h*2)
        (a, i) = check(dat, i)
        if a == 0:
            break
    return (var_4h, i)
 
r2 = r2pipe.open("mal1.dll")

encrypted_data = bytes(r2.cmdj('pxj 0x3c870 @ 0x10005238'))

print(encrypted_data[:4])
compressed_data = b''

x = 0
while x < len(encrypted_data):
    if x % 2 == 0:
        x += 2
    compressed_data += bytes([encrypted_data[x]])
    x += 1
    
encrypted_data = compressed_data
print(encrypted_data[:4])

unencrypted = b''
key = 0x4178

for i in range(0,len(encrypted_data)-4,4):
    #print(encrypted_data[i:i+4].hex())
    d = int(encrypted_data[i:i+4][::-1].hex(), 16)
    c = d ^ key
    c = rol(c, 4, 32)
    c += 0x77777778
    c = c & 0xffffffff
    unencrypted += struct.pack('<I',c)

f = open("out2.bin", 'wb')
f.write(unencrypted)
f.close()

encrypted = list(unencrypted)
decrypted = [0 for x in range(len(encrypted))]
decrypted[0] = encrypted[0]
dec_i = 1
enc_i = 1
var_ch = -1
var_4h = 0
end = False
while not end:
    (a, enc_i) = check(encrypted, enc_i)
    if a != 0:
        (a, enc_i) = check(encrypted, enc_i)
        if a != 0:
            (a, enc_i) = check(encrypted, enc_i)
            if a != 0:
                var_14h = 0
                var_8h = 4
                while var_8h != 0:
                    (a, enc_i) = check(encrypted, enc_i)
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
                var_14h = encrypted[enc_i]
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
            (a, enc_i) = check2(encrypted, enc_i)
            var_14h = a
            if var_4h == 0 and var_14h == 2:
                var_14h = var_ch
                (a, enc_i) = check2(encrypted, enc_i)
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
                var_14h = encrypted[enc_i] + var_14h
                enc_i += 1
                (a, enc_i) = check2(encrypted, enc_i)
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
        decrypted[dec_i] = encrypted[enc_i]
        dec_i += 1
        enc_i += 1
        var_4h = 0

decrypted = bytes(decrypted)
f = open("payload.bin", "wb")
f.write(decrypted)
f.close()
