from xdis.load import load_module
from xdis.bytecode import get_instructions_bytes, instruction_size
from xasm.assemble import Assembler, Instruction, create_code
import xdis, xdis.main, xdis.marsh, xdis.code
import uncompyle6
import sys
import keyword
import zlib
import base64
import io
import re
import argparse

def nop_jump_junk(co, opc):
    # Get the first jump target.
    first_jump_inst = next(get_instructions_bytes(co.co_code, opc))
    first_jump_target = first_jump_inst.argval

    # Abuse the text header to find the second jump.
    header_start_target = co.co_code.find(b'\r\n\r\n========')
    has_pyprotect_header = header_start_target != -1

    # Get the start of the JUMP_FORWARD, right before the header.
    jump_forward_inst_size = instruction_size(opc.opmap['JUMP_FORWARD'], opc)
    second_jump_start = header_start_target-jump_forward_inst_size

    # Go over the existing code and decide whether to copy each byte.
    fixed_code = bytearray()
    for i in range(len(co.co_code)):
        if (i < first_jump_target):
            # Replace the first anti-disassembly jump with NOPs
            fixed_code.append(opc.opmap['NOP'])
        elif has_pyprotect_header and (i >= second_jump_start):
            # Don't copy the second AD jump or anything after it.
            pass
        else:
            # Copy everything else.
            fixed_code.append(co.co_code[i])

    # Set fixed code back on co.
    co.co_code = fixed_code
    co.freeze()

def remove_nops(co, opc, version):
    asm = Assembler(str(version))
    asm.code = co
    asm.code.instructions = []

    # Disassemble the original instructions,
    # ignore if NOP, recalculate if absolute jump
    # then append them to our assembler.
    removed_nop_count = 0
    cur_offset = 0
    for inst in get_instructions_bytes(asm.code, opc):
        if inst.opname is 'NOP':
            removed_nop_count += 1
            continue

        # Recalculate absolute jump arg.
        arg = inst.arg
        if inst.optype is 'jabs':
            joff = inst.arg - inst.offset
            arg = cur_offset + joff

        # Create a new `xasm` Instruction.
        new_inst = Instruction()
        new_inst.opcode = inst.opcode
        new_inst.arg = arg
        new_inst.offset = cur_offset
        new_inst.line_no = 0
        
        # Add the instruction to the assembler.
        asm.code.instructions.append(new_inst)
        cur_offset += inst.inst_size

    code = create_code(asm, [], [])

    # HACK/FIX: xasm's `create_code` makes co_code a str on opcode version < 3,
    # when it should _probably_ be checking the interpreter version instead.
    # uncompyle6 requires this to be bytes-like, so we convert it.
    if sys.version_info > (3, 0, 0):
        code.co_code = bytes([ord(c) for c in code.co_code])

    return code


def undo_stage1(co2, opc, version):
    co_code = co2.co_code

    # TODO: Not sure it the const index is always the same,
    # may need to grab this by finding the largest const.
    stage2_enc_code = co2.co_consts[2] 
    stage2_out_code = bytearray()

    for i in range(len(stage2_enc_code)):
        stage2_out_code.append(stage2_enc_code[i] ^ co_code[i % len(co_code)])

    return (xdis.marsh.loads(zlib.decompress(base64.b64decode(stage2_out_code)), version), opc)

def undo_stage2(co2, opc, version, original_co_code):
    # Get the consts from the `pyopencoder_opDecoder` function code object.
    decode_func_consts = co2.co_consts[2].co_consts

    # Copy the code from the decompiled version,
    # using the keys right out of the `co_consts`.
    code_key = base64.b64decode(decode_func_consts[1])
    obj_key = base64.b64decode(decode_func_consts[2])
    split_by = decode_func_consts[3]

    # Decrypt the code object.
    # This contains the co_const, co_name, etc.
    # This object's `co_code` is encrypted.
    encrypted_obj = original_co_code.split(split_by, 1)[1][:-1]
    decrypted_obj = bytearray()
    for i in range(len(encrypted_obj)):
        decrypted_obj.append(encrypted_obj[i] ^ obj_key[i%len(obj_key)])

    stage3_out_code = xdis.marsh.loads(zlib.decompress(decrypted_obj), version)

    # Decrypt the `co_code`.
    encrypted_code = stage3_out_code.co_code
    decrypted_code = bytearray()
    for i in range(len(encrypted_code)):
        decrypted_code.append(encrypted_code[i] ^ code_key[i%len(code_key)])

    # Because we are using `xdis`, 
    # we can just set the co_code back onto the object.
    stage3_out_code.co_code = decrypted_code
    stage3_out_code.freeze()

    return (stage3_out_code, opc)


def recursive_fix_stage3(co2):
    co2.co_name = str(co2.co_name)

    # Replace the jump+junk anti-disassembler instructions with NOP.
    nop_jump_junk(co2, opc)

    # Remove the NOP's and recalculate the offsets.
    co2 = remove_nops(co2, opc, version)

    insts = list(get_instructions_bytes(co2, opc))
    for (k, v) in enumerate(insts):
        if (insts[k+0].opname == 'LOAD_CONST' and
            insts[k+1].opname == 'MAKE_FUNCTION' and
            insts[k+2].opname == 'STORE_NAME' ):
            co2.co_consts[insts[k+0].arg].co_name = str(co2.co_names[insts[k+2].arg]) 

    # Recursively fix up the code objects in `co_consts`
    consts = list(co2.co_consts)
    for (k, v) in enumerate(consts):
        if xdis.code.iscode(v) and 'pyprotect' in v.co_filename:
            consts[k] = recursive_fix_stage3(v)
            pass

    co2.co_consts = tuple(consts)
    co2.freeze()

    return co2


def undo_stage3(co2, opc, version):
    co2 = recursive_fix_stage3(co2)
    return co2


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unpack and decompile a PyProtected .pyc file")
    parser.add_argument("filepath", help="Path to the .pyc file")
    parser.add_argument("--decode-utf8", action='store_true', help="Try to decode the decompiled utf8 string literals")
    args = parser.parse_args()


    filename = args.filepath
    filebase = filename.split('.')[0]

    # Load the .pyc file.
    (version, timestamp, magic_int, stage1_co, pypy, source_size) = load_module(filename)
    opc = xdis.main.get_opcode(version, pypy)


    # Unpack the various stages.
    stage2_co, opc = undo_stage1(stage1_co, opc, version)
    stage3_co, opc = undo_stage2(stage2_co, opc, version, stage1_co.co_code)
    unpacked_co = undo_stage3(stage3_co, opc, version)

    #xdis.main.disco(version, unpacked_co, timestamp)

    # Decompile the final, cleaned and fixed, code object.
    f = io.StringIO('')
    uncompyle6.main.decompile(version, unpacked_co, f)
    code = f.getvalue()

    with open('{}.py'.format(filebase), 'w', encoding='utf8') as outf:
        # Optionally decode the utf8 string literals.
        if args.decode_utf8:
            byte_str_regex = r"\bb\'.+?\'"
            for match in re.findall(byte_str_regex, code):
                if '\\x' in match:
                    s = eval("{}".format(match))
                    code = code.replace(match, "u'{}'".format(s.decode('utf8')))
            
            outf.write("# -*- coding: utf-8 -*-\n\n")
        
        # Write the code.
        outf.write(code)