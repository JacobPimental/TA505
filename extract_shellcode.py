import r2pipe
import struct

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

def tohex(x):
  return (x + (1 << 32)) % (1 << 32)

r2 = r2pipe.open("mal1.dll")

encrypted_data = bytes(r2.cmdj('pxj 0xbf4 @ 0x10004640'))

print(encrypted_data[:4][::-1].hex())
unencrypted = b''
key = 0x6949


for i in range(0,len(encrypted_data)-4,4):
    #print(encrypted_data[i:i+4].hex())
    d = int(encrypted_data[i:i+4][::-1].hex(), 16)
    c = d ^ key
    c = rol(c, 4, 32)
    c += 0x77777778
    c = c & 0xffffffff
    unencrypted += struct.pack('<I',c)

f = open("out.bin", 'wb')
f.write(unencrypted)

f.close()
