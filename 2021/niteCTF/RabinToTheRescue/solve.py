from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long
import binascii
import math
import gmpy2

IP = 'rabin.challenge.cryptonite.team'
PORT = 1337

DEBUG = True

if DEBUG:
	IP = "127.0.0.1"
	PORT = 9001

io = remote(IP,PORT)

io.recvline_endswith("_")

def encrypt(text):
	io.sendlineafter(b">>","E")
	io.sendlineafter(b"hex:",text.hex())
	io.recvuntil(b"is: ")
	io.recvline()
	inhex = io.recvline().decode().replace("\n","")
	e = int(inhex, base=16)
	return e

e = encrypt(long_to_bytes(2))/2


# GCD Between PT1**e - CT1 and PT2**e - CT2 == k*n, if we are lucky, k == 1

def getn():
	val1 = b"Some random text, you shouldn't be reading this"
	val2 = b"Just a more badass long string so it goes over the modulus limit. LOLz... Nah just kidding xd"
	c1 = encrypt(val1)
	c2 = encrypt(val2)
	c3 = bytes_to_long(val1)**2
	c4 = bytes_to_long(val2)**2
	n = math.gcd(c3-c1,c4-c2)
	return n
	
value = 4
i = 1
getn()
print(f"E: {e}")

def gcdExtended(a, b): 
    # Base Case 
    if a == 0 :  
        return b,0,1
             
    gcd,x1,y1 = gcdExtended(b%a, a) 
     
    # Update x and y using results of recursive 
    # call 
    x = y1 - (b//a) * x1 
    y = x1 
     
    return gcd,x,y

n = getn()
sq,b = gmpy2.iroot(n,2)

while n%sq != 0:
    sq += 1
p = int(sq)
q = int(n // sq)

print(f"P: {p}")
print(f"Q: {q}")

io.sendline(b"G")
print(io.recvuntil(b"is:"))
io.recvline()
ct = io.recvline().decode().replace("\n","")
print(ct)
ct = int(ct,base=16)

q = int(q)
p = int(p)
assert(p * q == n)

mp = pow(ct, (p+1)//4, p)
mq = pow(ct, (q+1)//4, q)

gcd,yp,yq = gcdExtended(p,q)

r = []

r.append((yp*p*mq+yq*q*mp) % n)
r.append(n - r[0])
r.append((yp*p*mq-yq*q*mp) % n)
r.append(n - r[2])

for item in r:
	if b'nite{' in long_to_bytes(item):
		print(long_to_bytes(item))

# FLAG = nite{r3p34t3d_r461n_3ncrypt10n_l1tr4lly_k1ll5_3d6f4adc5e}'
