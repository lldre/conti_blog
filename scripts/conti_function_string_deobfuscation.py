import idaapi
import idc
import idautils
import flare_emu

MAX_LOOKBACK_CNT = 180

def harvest(start, end):
	b = bytearray()
	insn = ida_ua.insn_t()

	while start != end:
		ida_ua.decode_insn(insn, start)

		if (insn.itype == idaapi.NN_mov) and (insn.Op2.type == o_imm):
			b.append(insn.Op2.value)


		start = idc.next_head(start)

	return b

def emulate_func(ea, b):
	eh = flare_emu.EmuHelper()
	ret = eh.loadBytes(b)

	eh.emulateRange(ea, registers = {"ecx":ret}, hookApis=False)

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

	# Set repeatable function comment with deobfuscated string
	ida_funcs.set_func_cmt(idaapi.get_func(ea), idc.get_func_cmt(ea, 1) + "\n" + string, 1)


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

def get_offset_load(start):
	ea = start
	insn = ida_ua.insn_t()

	for i in range(MAX_LOOKBACK_CNT):
		ea = idc.prev_head(ea)
		ida_ua.decode_insn(insn, ea)


		# Look for `lea ecx, [ebp+XX]` before function call
		if (insn.itype == idaapi.NN_lea) and (idc.get_operand_value(ea, 0) == 1):
			return idc.get_operand_value(ea, 1)

	return 0




# Binary patterns to locate the start of
#	inlined string deobfuscation routines
search_strings = ["0x8A 0x06 0x8D 0x76 0x01 0x0F 0xB6 0xC0"]

for s in search_strings:
	for f in byte_search(s):
		func_ea = idaapi.get_func(f).start_ea

		print("Identified func at: %x"%func_ea)

		for ea in idautils.CodeRefsTo(func_ea, 0):


			# Get the value representing the stack offset
			# 	which is conveniently located right where our 
			#	byte pattern drops us off
			# 
			# The format for this is `lea ecx, [ebp+XX]`, the 1
			# 	indicating that we want the value of `[ebp+XX]`
			b_stack_off = get_offset_load(ea)

			if b_stack_off < 0xFFFF:
				print("b_stack_off for ea: %X needs to be handled manually with %X"%(ea, b_stack_off))
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


					# Pass all info to the emulator to emulate the inline deobfuscator
					emulate_func(func_ea, obfuscated_string)
					break

			# Limit the max amount it can look back, just in case
			if i == MAX_LOOKBACK_CNT-1:
				print("Couldn't find the start of byte loads for ea: %X"%ea)
				continue