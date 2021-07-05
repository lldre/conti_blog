import idaapi
import idc
import idautils
import flare_emu

MAX_LOOKBACK_CNT = 180

def harvest(start, end):
	# We need to have 1 0x00 at the start for this algo
	b = bytearray([0x00])
	insn = ida_ua.insn_t()

	while start != end:
		ida_ua.decode_insn(insn, start)

		if (insn.itype == idaapi.NN_mov) and (insn.Op2.type == o_imm):
			b.append(insn.Op2.value)


		start = idc.next_head(start)

	return b

def emulate_inline(start, end, b, stack_offset_of_null_load, reg):

	string = ""

	# The inlined deobfuscator expects the bytes
	# 	at a certain offset in the stack, so
	#	we can't just load the bytes we harvested in verbatim.
	# We need to pad the stack with 0s to complete the stack
	# 	up to the point where the deobfuscator is going
	#	to read from it.
	for x in range(stack_offset_of_null_load - len(b)):
		b.append(0)


	eh = flare_emu.EmuHelper()
	ret = eh.loadBytes(b)
	eh.emulateRange(start, registers = {"ebp":ret+len(b), reg:0x7f}, endAddr = end,  hookApis=False)
	

	emu_bytes = eh.getEmuBytes(ret+1, len(b))

	# Check if unicode string or not
	if emu_bytes[1] == 0x00:
		bb = bytearray()
		for i, x in enumerate(eh.getEmuBytes(ret, len(b))):
			if (i & 1):
				bb.append(x)
		print(bb.decode())
		string = bb.decode()
	else:
		print(eh.getEmuString(ret+1).decode())
		string = eh.getEmuString(ret+1).decode()


	# Insert the deobfuscated string back into IDA	
	idc.set_cmt(start, idc.get_func_cmt(ea, 1) + "\n" + string, 1)


def byte_search(byte_search_string):

	addrs = []
	start = idaapi.get_imagebase()

	while True:
		ea = idc.find_binary(start, SEARCH_NEXT|SEARCH_DOWN, byte_search_string)
		if ea != BADADDR:
			start = ea+1
		else:
			break

		addrs.append(ea)

	return addrs


def find_end_of_loop(start):
	insn = ida_ua.insn_t()
	ea = start
	end = 0

	for i in range(0x40):
		ea = idc.next_head(ea)

		ida_ua.decode_insn(insn, ea)

		if (insn.itype == idaapi.NN_jb):
			end = idc.next_head(ea)
			break

		if i == 0x40-1:
			print("Couldn't find the end of the deobfuscation loop for ea: %X"%ea)
			continue

	return end

def find_idiv_reg(start):
	insn = ida_ua.insn_t()
	ea = start
	idiv_reg = ""

	for i in range(0x40):
		ea = idc.next_head(ea)

		ida_ua.decode_insn(insn, ea)

		if (insn.itype == idaapi.NN_idiv):
			idiv_reg = idc.generate_disasm_line(0x004010A2, 0)[-3:]
			break

		if i == 0x40-1:
			print("Couldn't find the end of the deobfuscation loop for ea: %X"%ea)
			continue

	return idiv_reg


# Binary patterns to locate the start of
#	inlined string deobfuscation routines
search_strings = ["0x8A 0x44 ? ? 0x0F 0xB6 ?", "0x8A ? ? ? ? ? ? 0x0F 0xB6 ?", "0x8A ? ? ? ? ? ? 0xB9 ?", "0x8A ? ? ? ? ? ? 0xB9 ?"]

for s in search_strings:
	for ea in byte_search(s):


		# Get the value representing the stack offset
		# 	which is conveniently located right where our 
		#	byte pattern drops us off
		# 
		# The format for this is `lea ecx, [ebp+XX]`, the 1
		# 	indicating that we want the value of `[ebp+XX]`
		b_stack_off = idc.get_operand_value(ea, 1)

		if b_stack_off < 0xFFFF:
			print("b_stack_off for ea: %X needs to be handled manually"%ea)
			continue #quick hack to skip buggy ones


		ea_n = ea
		i = 0

		for i in range(MAX_LOOKBACK_CNT):
			ea_n = idc.prev_head(ea_n)

			# We keep looking back until we find the same
			# 	stack position by value, that we identified above
			#
			# This time we're looking for `mov [ebp+XX], 0`, so
			#	we pass a 0 indicating the first operand 
			if (idc.get_operand_value(ea_n, 0) == b_stack_off):

				# Extract all the bytes
				obfuscated_string = harvest(ea_n, ea)

				# Locate end of inline deobfuscation loop
				end = find_end_of_loop(ea)
				if not end:
					print("Couldn't find the end of the deobfuscation loop for %x"%ea)
					break

				# identify register used in idev operation
				reg = find_idiv_reg(ea)
				if not reg:
					print("Couldn't find the idiv reg used in the deobfuscation loop for %x"%ea)
					break


				# Pass all info to the emulator to emulate the inline deobfuscator
				emulate_inline(ea, end, obfuscated_string, ((~b_stack_off & 0xFFFFFFFF) + 1), reg)
				break

		# Limit the max amount it can look back, just in case
		if i == MAX_LOOKBACK_CNT-1:
			print("Couldn't find the start of byte loads for ea: %X"%ea)
			continue