# Copyright 2010 fail0verflow <master@fail0verflow.com>
# Licensed under the terms of the GNU GPL, version 2
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

import anergistic, array, struct, random, subprocess

class MFC:
	def __init__(self):
		self.MFC_TagMask = 0
		self.mbox = []

	class UnknownChannel(Exception):
		pass

	def wrch(self, ch, data):
		if ch == 7:
			return
		if ch == 16:
			self.MFC_LSA = data
		elif ch == 17:
			self.MFC_EAH = data
		elif ch == 18:
			self.MFC_EAL = data
		elif ch == 19:
			self.MFC_Size = data
		elif ch == 20:
			self.MFC_TagID = data
		elif ch == 21:
			self.handle_command(data)
		elif ch == 22:
			self.MFC_TagMask = data
		elif ch == 23:
			self.handle_mfc_tag_update(data)
		elif ch == 26:
			pass
		elif ch == 27:
			pass
		elif ch == 28:
			self.write_mbox(data)
		elif ch == 30:
			self.write_mbox(data, True)
		else:
			raise self.UnknownChannel("pc=%08x channel=%d" % (self.pc, ch))

	def rdch(self, ch):
		if ch == 24:
			return self.MFC_TagStat
		elif ch == 27:
			return self.MFC_AtomicStat
		elif ch == 74:
			return self.random()
		elif ch == 29:
			return self.mbox.pop(0)
		else:
			raise self.UnknownChannel("pc=%08x channel=%d" % (self.pc, ch))
	
	def rchcnt(self, ch):
		if ch == 23:
			return 1
		elif ch == 24:
			return 1
		elif ch == 27:
			return 1
		elif ch == 74:
			return 1
		elif ch == 28:
			return 1
		elif ch == 29:
			return len(self.mbox)
		elif ch == 30:
			return 1
		else:
			raise self.UnknownChannel("pc=%08x channel=%d" % (self.pc, ch))

	def random(self):
		return random.randrange(0, 256)

	class MBoxWrite(Exception):
		pass

	def write_mbox(self, data, interrupt = False):
		raise self.MBoxWrite("pc=%08x data=%08x, int %s" % (self.pc, data, interrupt))

	MFC_GET_CMD = 0x40
	MFC_SNDSIG_CMD = 0xA0
	MFC_PUT_CMD = 0x20
	
	class UnknownCommand(Exception):
		pass

	def handle_command(self, command):
		if command == self.MFC_GET_CMD:
#			print "DMA GET Local=%08x, EA = %08x:%08x, Size=%08x, TagID=%08x" % (self.MFC_LSA, self.MFC_EAH, self.MFC_EAL, self.MFC_Size, self.MFC_TagID)
			self.set_ls(self.MFC_LSA, self.dma_get((self.MFC_EAH << 32) | self.MFC_EAL, self.MFC_Size))
		elif command == self.MFC_PUT_CMD:
#			print "DMA PUT Local=%08x, EA = %08x:%08x, Size=%08x, TagID=%08x" % (self.MFC_LSA, self.MFC_EAH, self.MFC_EAL, self.MFC_Size, self.MFC_TagID)
			self.dma_set((self.MFC_EAH << 32) | self.MFC_EAL, self.ls[self.MFC_LSA:self.MFC_LSA + self.MFC_Size])
		else:
			raise self.UnknownCommand("pc=%08x command=%02x" % (self.pc, command))

	class UnknownTagUpdate(Exception):
		pass

	def handle_mfc_tag_update(self, tag):
		self.MFC_TagStat = self.MFC_TagMask

class Calltree:
	"basic calltree. call calltree_init after loading symbols(!), then call calltree_dump at the end."
	INSN_BI = (0x35000000 >> 21,)
	INSN_BRSL_BISL = range(0x33000000 >> 21, 0x33800000 >> 21) + [0x35200000 >> 21]
	def calltree_init(self, instant = False):
		# break on bi
		self.breakpoints_insns.update(self.INSN_BI)
		# break on brsl
		self.breakpoints_insns.update(self.INSN_BRSL_BISL)
		self.prerun.append(self.calltree_update)
		self.breakpoints.update(self.symbols.keys())
		self.tree = []
		self.expect_call = None
		self.level = 0
		self.instant_calltree = instant

	def calltree_update(self, opcode):
		if self.expect_call and self.pc in self.symbols:
			self.level += 1
			self.tree.append([self.expect_call, self.level, self.pc, [self.get_regW(x + 3) for x in range(8)] ])
			self.expect_call = None
		if opcode == 0x35000000: # bi r0
			self.tree.append([self.pc, self.level, None, [self.get_regW(3)]])
			self.level -= 1
		if opcode >> 21 in self.INSN_BRSL_BISL:
			self.expect_call = self.pc
		if self.instant_calltree:
			self.calltree_dump()

	def calltree_dump(self):		
		for (pc, level, target, res) in self.tree:
			print "%08x" % pc, 
			print level * " |",
			if target is None:
				print " \\= 0x%08x" % res[0]
			else:
				print "-> %s(%s)" % (self.symbols.get(target), ','.join(["0x%08x" % r for r in res]))
		self.tree = []

class SPU(MFC, Calltree):
	class UnknownStop(Exception):
		pass

	def __init__(self):
		self.ls = array.array("c", "\0" * 256 * 1024)
		self.registers = array.array("c", "\0" * 128 * 16)
		self.breakpoints = set()
		self.breakpoints_insns = set()
		self.prerun = []
		self.hooks = {}
		MFC.__init__(self)

	def demangle_symbols(self):
		try:
			symbols = ""
			for d in self.symbols:
				symbols = symbols + "\n" + self.symbols[d]
			p = subprocess.Popen(['c++filt', '-n'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
			out = p.communicate(symbols)[0].split("\n")
			i = 1
			for d in self.symbols:
				self.symbols[d] = out[i]
				i = i + 1
		except OSError:
			print "Unable to demangle ELF symbols."

	def run(self):
		while True:
			opcode = struct.unpack(">I", self.ls[self.pc:self.pc+4])[0]
			rt = opcode & 0x7F
			ch = (opcode >> 7) & 0x7F
			
			for f in self.prerun:
				f(opcode)
			
			if self.pc in self.hooks:
				if self.hooks[self.pc]():
					continue
			
			if   opcode & 0xFFE00000 == 0x21a00000:
				self.wrch(ch, self.get_regW(rt))
				self.pc += 4
			elif opcode & 0xFFE00000 == 0x01a00000:
				self.set_regW(rt, self.rdch(ch))
				self.pc += 4
			elif opcode & 0xFFE00000 == 0x01e00000:
				self.set_regW(rt, self.rchcnt(ch))
				self.pc += 4
			elif opcode & 0xFFE00000 == 0:
				if self.stop(opcode & 0x3FFF):
					break
			else:
				oldpc = self.pc
				self.pc = anergistic.execute(self.ls, self.registers, self.pc, self.breakpoints, self.breakpoints_insns)
				if opcode >> 21 in self.breakpoints_insns:
					return
				if self.pc in self.breakpoints:
					return
				if self.pc == oldpc:
					raise self.UnknownStop("stopped at pc=%08x (opcode %08x)" % (self.pc, opcode))

	def load(self, filename, no_calltree = True):
		"""Load an elf into the local store (and set PC to entry point)"""
		
		SHT_SYMTAB = 2
		SHT_STRTAB = 3
		
		elf = open(filename, "rb")
		(e_ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = \
			struct.unpack(">16sHHIIIIIHHHHHH", elf.read(0x34))
		assert e_ident[:4] == "\x7FELF"
		
		for i in range(e_phnum):
			elf.seek(e_phoff + e_phentsize * i)
			p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
				struct.unpack(">IIIIIIII", elf.read(0x20))
			
			elf.seek(p_offset)
			self.set_ls(p_paddr, elf.read(p_filesz))
						
			print "elf: phdr #%u: %08x bytes; %08x -> %08x" % (i, p_filesz, p_offset, p_paddr)
			
		symbols = {}
		
		strtab = None

		# fake two-pass algorithm to first find the symbtab, then load the strings
		for i in range(e_shnum):
			elf.seek(e_shoff + e_shentsize * i)
			sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = \
			struct.unpack(">IIIIIIIIII", elf.read(0x28))
			
			if sh_type == SHT_SYMTAB:
				elf.seek(sh_offset)
				
				for i in range(sh_size / sh_entsize):
					st_name, st_value, st_size, st_info, st_other, st_shndx = \
						struct.unpack(">IIIBBH", elf.read(sh_entsize))
					symbols[st_value] = st_name
				strtab = sh_link
			elif i == strtab: # yes, they need to be in order.
				print "symbol string tab at %08x size %08x" % (sh_offset, sh_size)
				for st_value in symbols:
					st_name = symbols[st_value]
					assert st_name < sh_size
					elf.seek(sh_offset + st_name)
					str = ""
					while True:
	 					str += elf.read(16)
	 					zero = str.find("\0")
	 					if zero != -1:
	 						str = str[:zero]
	 						break
					symbols[st_value] = str
		
		self.symbols = symbols
		self.symbols_mangled = {}
		for s in self.symbols:
			self.symbols_mangled[self.symbols[s]] = s
		self.demangle_symbols()
		self.pc = e_entry
		
#		self.calltree_init(True)
		if self.symbols and not no_calltree:
			self.calltree_init(True)
	
	def set_regW(self, reg, value):
		"""Set preferred word of register."""
		self.set_regW4(reg, (value, 0, 0, 0))

	def set_regW4(self, reg, value):
		"""Set register as 4 words."""
		self.registers[reg * 16:(reg + 1) * 16] = array.array("c", struct.pack(">IIII", *value))

	def set_regD(self, reg, value):
		"""Set preferred doubleword of register"""
		self.set_regW4(reg, ((value >> 32) & 0xFFFFFFFF, value & 0xFFFFFFFF, 0, 0))

	def get_regW4(self, reg):
		return struct.unpack(">IIII", self.registers[reg * 16:(reg + 1) * 16])
	
	def get_regW(self, reg):
		return self.get_regW4(reg)[0]

	def set_ls(self, offset, data):
		"""Store data in LS at offset"""
		assert offset + len(data) <= len(self.ls)
		self.ls[offset:offset+len(data)] = array.array("c", data)

	def get_ls(self, offset, len):
		return self.ls[offset:offset + len]

	def stop(self, code):
		raise self.UnknownStop("Stopped with code %08x" % code)

	def hook(self, addr, fnc):
		addr = self.symbols_mangled[addr]
		self.breakpoints.add(addr)
		self.hooks[addr] = fnc
