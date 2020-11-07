import idc
import sys
import idaapi
import idautils
import ida_auto
import ida_funcs
import re
import time

class StatefulSegmentManager(object):
    """ A stateful segment manager for IDBs, saves/recovers state across IDAPython script executions.
    
        Based on segment API usage from https://github.com/fireeye/flare-ida/tree/master/python/flare/IDB_MSDN_Annotator
    """
    def __init__(self, segment_name, segment_size=0x100000, delete_existing=False):
        self.segment_name = segment_name
        self.start_ea = -1
        self.end_ea = -1
        self._cur_ea = -1
        self.reserved_state_space = 16

        if delete_existing:
            for segment in idautils.Segments():
                if idc.SegName(segment) == segment_name:
                    idaapi.del_segm(idc.SegStart(segment), idaapi.SEGMOD_KILL)


        last_segment_ea = 0
        for segment in idautils.Segments():
            # Load the segment if it already exists.
            if idc.SegName(segment) == segment_name:
                self._load_existing_segment(segment)
                return

            if idc.SegEnd(segment) > last_segment_ea:
                last_segment_ea = idc.SegEnd(segment)
        
        # Create a new segment for it after the last segment
        self.start_ea = last_segment_ea
        self.end_ea = self.start_ea + segment_size

        idc.AddSeg(self.start_ea, self.end_ea, 0, 1, 0, idaapi.scPub)
        idc.RenameSeg(self.start_ea, segment_name)
        idc.SetSegClass(self.start_ea, 'CODE')
        idc.SetSegAddressing(self.start_ea, 1)

        self.cur_ea = self.start_ea+self.reserved_state_space

    def _load_existing_segment(self, segment):
        self.start_ea = idc.SegStart(segment)+self.reserved_state_space
        self.end_ea = idc.SegEnd(segment)
        self._cur_ea = idc.Dword(self.start_ea)

    @property
    def cur_ea(self):
        return self._cur_ea

    @cur_ea.setter
    def cur_ea(self, value):
        self._cur_ea = value
        idc.patch_dword(self.start_ea, self.cur_ea)

# Writes `nop_length` nops starting at ea, then writes the code starting at ea
def write_patch_with_nops(ea, code, nop_count):
    for i in range(nop_count):
        patch_ea = ea + i
        #print('patch_byte({:X}, {:X})'.format(patch_ea, 0x90))
        idc.patch_byte(patch_ea, 0x90)
    
    for i, v in enumerate(code):
        patch_ea = ea + i
        #print('patch_byte({:X}, {:X})'.format(patch_ea, ord(v)))
        idc.patch_byte(patch_ea, ord(v))


def get_instruction_length(ea):
    ida_auto.auto_wait()
    #return idc.NextHead(ea)-ea

    try:
        size = idautils.DecodeInstruction(ea).size
        if size >= 16:
            print("Got instruction size > 16 @ {:X}".format(ea))
            sys.exit(1)
        return size
    except Exception as e:
        print("Got Exception on get_instruction_length(0x{:X}) - {}".format(ea, e))
        sys.exit(1)

def write_patch_nop_instruction(ea):
    instruction_length = get_instruction_length(ea)
    for i in range(instruction_length):
        patch_ea = ea + i
        #print('patch_byte({:X}, {:X})'.format(patch_ea, 0x90))
        idc.patch_byte(patch_ea, 0x90)

def write_patch_override_instruction(ea, code):
    instruction_length = get_instruction_length(ea)
    if len(code) > instruction_length:
        #print("Can't override instruction, code is too long.")
        sys.exit(1)

    write_patch_nop_instruction(ea)

        
    for i, v in enumerate(code):
        patch_ea = ea + i
        #print('patch_byte({:X}, {:X})'.format(patch_ea, ord(v)))
        idc.patch_byte(patch_ea, ord(v))


def next_head_after_nops(ea):
    cur_ea = ea
    while True:
        cur_ea = idc.NextHead(cur_ea)
        if idc.GetMnem(cur_ea) != 'nop':
            break
    return cur_ea


def write_patch_linear_instructions(eas, instructions):
    breakpoint()
    # Get a list of linear address space, not seperated by jmps.
    chunks = []
    chunk_start_ea = eas[0]
    for i, ea in enumerate(eas):
        next_ea = next_head_after_nops(ea)
        if i+1 < len(eas):
            if next_ea == eas[i+1]:
                pass
            else:
                chunk_size = next_ea-chunk_start_ea
                if chunk_size > 0x1000:
                    print("Invalid chunk size")
                    sys.exit(1)
                chunks.append((chunk_start_ea, chunk_size))
                chunk_start_ea = eas[i+1]

    chunks.append((chunk_start_ea, next_ea-chunk_start_ea))

    # Sanity checks.
    for _, c in enumerate(chunks):
        if c[1] > 100:
            print("Invalid chunk size")
            sys.exit(1)


    # Nop all the chunks:
    for _, c in enumerate(chunks):
        chunk_start_ea = c[0]
        nop_count = c[1]
        for i in range(nop_count):
            patch_ea = ea + i
            print('patch_byte({:X}, {:X})'.format(patch_ea, 0x90))
            idc.patch_byte(patch_ea, 0x90)

    

    # Find the first place (if any) that we can write the new instructions.
    space_needed = sum([len(x) for x in instructions])
    usable_ea = None
    for _, c in enumerate(chunks):
        if c[1] >= space_needed:
            usable_ea = c[0]
            break

    if usable_ea == None:
        print("Can't find linear space for instructions in eas!")
        sys.exit(1)

    patch_ea = 0
    code = [inner for outer in instructions for inner in outer]
    for i, v in enumerate(code):
        patch_ea = usable_ea + i
        print('patch_byte({:X}, {:X})'.format(patch_ea, ord(v)))
        idc.patch_byte(patch_ea, ord(v))

    




conditional_jump_mnems = [
    'jo',
    'jno',
    'js',
    'jns',
    'je', 'jz',
    'jne', 'jnz',
    'jb', 'jnae', 'jc', 
    'jnb', 'jae', 'jnc',
    'jbe', 'jna',
    'ja', 'jnbe',
    'jl', 'jnge',
    'jge', 'jnl',
    'jle', 'jng'
    'jg', 'jnle',
    'jp', 'jpe',
    'jnp', 'jpo',
    'jcxz', 'jecxz',
    ]
def is_conditional_jump_mnem(mnem):
    return mnem in conditional_jump_mnems


class DeobfuNode(object):
    walked_node_eas = []

    def __init__(self, ea, parent=None):
        self.ea = ea
        self.parent = parent
        self.instructions = None
        self.children = []

    def Walk(self):
        ea = self.ea
        self.instructions = DeobfuNode.linear_follow(ea)

        while self.clean_passes(ea):
            print("Performing iterative clean/walk for starting ea: {:X}".format(ea))
            pass

        DeobfuNode.walked_node_eas.append(ea)

        for branch_ea in self.get_branch_eas():
            if branch_ea not in DeobfuNode.walked_node_eas:
                node = DeobfuNode(branch_ea, parent=self)
                node.Walk()
                self.children.append(node)

        """
        for ea in self.instructions:
            print(hex(ea).split('L')[0] + ' ' + idc.GetDisasm(ea))
        """

    def FixRegions(self):
        if self.parent != None:
            print("This node isn't the root, exiting FixRegions.")
            return

        all_chunks = self.get_chunks_recursive()

        print(all_chunks)

        # Re-define all function codes to remove previous sub_xxxxxxx and tail chunk detection.
        for chunk in all_chunks:
            idc.MakeUnknown(chunk[0], chunk[1]-chunk[0], idc.DOUNK_DELNAMES)
            idc.MakeCode(chunk[0])

        ida_auto.auto_wait()
        
        # Make the root node a function
        idc.MakeFunction(self.ea)
        f = idaapi.get_func(self.ea)
        ida_auto.auto_wait()

        # Add all other nodes as tail chunks.
        for chunk in all_chunks[1:]:
            idaapi.append_func_tail(f, chunk[0], chunk[1])
            ida_funcs.set_tail_owner(f, chunk[0])
            ida_auto.auto_wait()

        # Undefine the code (except root chunk) after the address ranges have been marked as function chunks.
        for chunk in all_chunks[1:]:
            idc.MakeUnknown(chunk[0], chunk[1]-chunk[0], idc.DOUNK_DELNAMES)

        # Ask IDA to reanalyze
        ida_funcs.reanalyze_function(f, all_chunks[0][0], all_chunks[0][1])
        ida_auto.auto_wait()

        
        

        """



        # Undefine any functions these addresses are listed as being part of, as function tail chunks cannot be removed easily.
        for ea in self.instructions:
            f = idaapi.get_func(ea)
            if f is not None:
                idc.MakeUnknown(f.startEA, 1, idc.DOUNK_DELNAMES)
                idc.MakeCode(f.startEA)

        for _, child in enumerate(self.children):
            child.FixRegions(root_node=root_node)

        if root_node == None:
            idc.MakeFunction(self.ea)
        """

    def get_chunks_recursive(self):
        chunks = DeobfuNode.get_chunks(self.ea)
        for child in self.children:
            chunks.extend(child.get_chunks_recursive())

        return chunks

    def clean_passes(self, ea):
        patched = False
        self.instructions = DeobfuNode.linear_follow(ea)
        ida_auto.auto_wait()
        patched |= self.clean_push_pass()
        self.instructions = DeobfuNode.linear_follow(ea)
        ida_auto.auto_wait()
        patched |= self.clean_push_pass2()
        self.instructions = DeobfuNode.linear_follow(ea)
        ida_auto.auto_wait()
        patched |= self.clean_pop_pass()
        self.instructions = DeobfuNode.linear_follow(ea)
        ida_auto.auto_wait()
        patched |= self.clean_pop_pass2()
        self.instructions = DeobfuNode.linear_follow(ea)
        ida_auto.auto_wait()
        patched |= self.clean_lea_jmp()
        self.instructions = DeobfuNode.linear_follow(ea)
        ida_auto.auto_wait()
        patched |= self.clean_push_ret()
        self.instructions = DeobfuNode.linear_follow(ea)
        ida_auto.auto_wait()
        patched |= self.clean_conditional_jump_pass()
        self.instructions = DeobfuNode.linear_follow(ea)
        ida_auto.auto_wait()
        return patched


    @staticmethod
    def linear_follow(ea, max_instructions=500, skip_nops=True):
        output_eas = []
        all_walked_eas = []

        done = False
        for _ in range(max_instructions):
            all_walked_eas.append(ea)
            if done:
                break

            idc.OpHex(ea, -1)

            mnem = idc.GetMnem(ea)
            if skip_nops and mnem == 'nop':
                ea = idc.NextHead(ea)
                continue
            elif mnem == 'jmp' and (idc.GetOpType(ea, 0) == idc.o_near or idc.GetOpType(ea, 0) == idc.o_far):
                # Jump to a constant literal, non-conditional.
                target = idc.GetOperandValue(ea, 0)

                # Handle recursion / loops.
                if target in all_walked_eas:
                    output_eas.append(ea)
                    done = True

                ea = target
                continue
            
            elif mnem == 'ret' or mnem == 'retn' or mnem == 'jmp':
                done = True
                
            output_eas.append(ea)
            
            #print(hex(ea).split('L')[0] + ' ' + idc.GetDisasm(ea))
            ea = idc.NextHead(ea)

        return output_eas

    @staticmethod
    def get_chunks(ea, max_instructions=500):
        output_chunks = []
        all_walked_eas = []

        done = False
        chunk_start = ea
        for _ in range(max_instructions):
            all_walked_eas.append(ea)
            if done:
                break

            mnem = idc.GetMnem(ea)
            if mnem == 'jmp' and (idc.GetOpType(ea, 0) == idc.o_near or idc.GetOpType(ea, 0) == idc.o_far):
                # Jump to a constant literal, non-conditional.
                target = idc.GetOperandValue(ea, 0)

                # Handle recursion / loops.
                if target in all_walked_eas:
                    done = True

                output_chunks.append((chunk_start, ea+get_instruction_length(ea)))
                chunk_start = target
                ea = target
                continue
            
            elif mnem == 'ret' or mnem == 'retn' or mnem == 'jmp':
                output_chunks.append((chunk_start, ea+get_instruction_length(ea)))
                done = True
            
            ea = idc.NextHead(ea)

        return output_chunks
        

    def get_branch_eas(self):
        targets = []

        for _, ea in enumerate(self.instructions):
            if is_conditional_jump_mnem(idc.GetMnem(ea)):
                target = idc.GetOperandValue(ea, 0)
                targets.append(target)

        return targets


    # Cleans up obfuscated/manual pushes
    #   mov [esp-4], ###
    #   lea esp, [esp-4]
    def clean_push_pass(self):
        patched = False
        i = 0
        while i < len(self.instructions):
            ea = self.instructions[i]
            if idc.GetMnem(ea) == 'mov' and idc.GetOpnd(ea, 0) == '[esp-4]' and idc.GetOpType(ea, 1) == idc.o_reg:
                next_ea = self.instructions[i+1]
                if idc.GetMnem(next_ea) == 'lea' and idc.GetOpnd(next_ea, 0) == 'esp' and idc.GetOpnd(next_ea, 1) == '[esp-4]':
                    pushed_reg = idc.GetOpnd(ea, 1)
                    print('obfu push {} at: {:X}'.format(pushed_reg, ea))
                    
                    ok, code = idautils.Assemble(ea, 'push {}'.format(pushed_reg))
                    if ok:
                        write_patch_override_instruction(ea, code)
                        write_patch_nop_instruction(next_ea)
                        patched = True

            i += 1
        return patched

    # Cleans up obfuscated/manual pushes
    #   lea esp, [esp-4]
    #   mov [esp], ###
    def clean_push_pass2(self):
        patched = False
        i = 0
        
        while i < len(self.instructions):
            ea = self.instructions[i]
            if idc.GetMnem(ea) == 'lea' and idc.GetOpnd(ea, 0) == 'esp' and idc.GetOpnd(ea, 1) == '[esp-4]':
                next_ea = self.instructions[i+1]
                if idc.GetMnem(next_ea) == 'mov' and idc.GetOpnd(next_ea, 0) == '[esp]' and idc.GetOpType(next_ea, 1) == idc.o_reg:
                    pushed_reg = idc.GetOpnd(next_ea, 1)
                    print('obfu push {} at: {:X}'.format(pushed_reg, ea))

                    ok, code = idautils.Assemble(ea, 'push {}'.format(pushed_reg))
                    if ok:
                        write_patch_override_instruction(ea, code)
                        write_patch_nop_instruction(next_ea)
                        patched = True
                    

            i += 1
        return patched



    # lea esp, [esp+4]
    # mov xxx, [esp-4]
    #
    # to pop xxx
    def clean_pop_pass(self):
        patched = False
        i = 0
        while i < len(self.instructions):
            ea = self.instructions[i]
            if idc.GetMnem(ea) == 'lea' and idc.GetOpnd(ea, 0) == 'esp' and idc.GetOpnd(ea, 1) == '[esp+4]':
                next_ea = self.instructions[i+1]
                if idc.GetMnem(next_ea) == 'mov' and idc.GetOpType(next_ea, 0) == idc.o_reg and idc.GetOpnd(next_ea, 1) == '[esp-4]':
                    popped_reg = idc.GetOpnd(next_ea, 0)
                    print('obfu pop {} at: {:X}'.format(popped_reg, ea))

                    ok, code = idautils.Assemble(ea, 'pop {}'.format(popped_reg))
                    if ok:
                        write_patch_override_instruction(ea, code)
                        write_patch_nop_instruction(next_ea)
                        patched = True

            i += 1
        return patched


    # mov xxx, [esp]
    # lea esp, [esp+4]
    #
    # to pop xxx
    def clean_pop_pass2(self):
        patched = False
        i = 0
        while i < len(self.instructions):
            ea = self.instructions[i]
            if idc.GetMnem(ea) == 'mov' and idc.GetOpType(ea, 0) == idc.o_reg and idc.GetOpnd(ea, 1) == '[esp]':
                next_ea = self.instructions[i+1]
                if idc.GetMnem(next_ea) == 'lea' and idc.GetOpnd(next_ea, 0) == 'esp' and idc.GetOpnd(next_ea, 1) == '[esp+4]':
                    popped_reg = idc.GetOpnd(ea, 0)
                    print('obfu pop {} at: {:X}'.format(popped_reg, ea))

                    ok, code = idautils.Assemble(ea, 'pop {}'.format(popped_reg))
                    if ok:
                        write_patch_override_instruction(ea, code)
                        write_patch_nop_instruction(next_ea)
                        patched = True

            i += 1
        return patched

    #lea     esp, [esp+4]
    #jmp     dword ptr [esp-4]
    #into a "ret"
    def clean_lea_jmp(self):
        patched = False
        i = 0
        while i < len(self.instructions):
            ea = self.instructions[i]
            if idc.GetMnem(ea) == 'lea' and idc.GetOpnd(ea, 0) == 'esp' and idc.GetOpnd(ea, 1) == '[esp+4]':
                next_ea = self.instructions[i+1]
                if idc.GetMnem(next_ea) == 'jmp' and idc.GetOpnd(next_ea, 0) == 'dword ptr [esp-4]':
                    ok, code = idautils.Assemble(ea, 'ret')
                    if ok:
                        write_patch_override_instruction(ea, code)
                        write_patch_nop_instruction(next_ea)
                        patched = True
                    
            i += 1
        return patched
    
    def clean_push_ret(self):
        patched = False
        i = 0
        while i < len(self.instructions):
            ea = self.instructions[i]
            if idc.GetMnem(ea) == 'push' and idc.GetOpType(ea, 0) == idc.o_imm:
                next_ea = self.instructions[i+1]
                if idc.GetMnem(next_ea) == 'retn' and idc.GetOperandValue(next_ea, 0) == -1:
                    jump_target = idc.GetOperandValue(ea, 0)

                    ok, code = idautils.Assemble(ea, 'jmp 0{:X}h'.format(jump_target))
                    if ok:
                        write_patch_override_instruction(ea, code)
                        write_patch_nop_instruction(next_ea)
                        patched = True
                    else:
                        print("assemble error:", code)

            i += 1

        return patched

    """
    def clean_push_jmp_ret_pass(self):
        i = 0
        while i < len(self.instructions):
            ea = self.instructions[i]
            if idc.GetMnem(ea) == 'push' and idc.GetOpType(ea, 0) == idc.o_imm:
                next_ea = self.instructions[i+1]
                if idc.GetMnem(next_ea) == 'lea' and idc.GetOpnd(next_ea, 0) == 'esp' and idc.GetOpnd(next_ea, 1) == '[esp+4]':
                    next_ea = self.instructions[i+2]
                    if idc.GetMnem(next_ea) == 'jmp' and idc.GetOpnd(next_ea, 0) == 'dword ptr [esp-4]':
                        nop_count = idc.NextHead(next_ea) - ea
                        jump_target = idc.GetOperandValue(ea, 0)
                        print('obfu push-ret-jmp {} at: {:X}, size: {}'.format(jump_target, ea, nop_count))

                        
                        ok, code = idautils.Assemble(ea, 'jmp {:X}h'.format(jump_target))
                        if ok and len(code) <= nop_count:
                            write_patch_with_nops(ea, code, nop_count)

            i += 1
    """

    def clean_conditional_jump_pass(self):
        """
        cmp     edx, ds:dword_60C7F6
        push    offset sub_3D7996B
        push    eax
        push    ecx
        mov     eax, [esp+8]
        mov     ecx, offset sub_430A4F7
        cmovnb  eax, ecx
        mov     [esp+8], eax
        pop     ecx
        pop     eax
        lea     esp, [esp+4]
        jmp     dword ptr [esp-4]

        to

        cmp     edx, ds:dword_60C7F6
        jnb     sub_430A4F7
        jmp     sub_3D7996B
        """

        patched = False

        i = 0
        while i < len(self.instructions):
            ea = self.instructions[i]

            if (
                idc.GetMnem(self.instructions[i+0]) == 'cmp' and
                idc.GetMnem(self.instructions[i+1]) == 'push' and
                idc.GetMnem(self.instructions[i+2]) == 'push' and
                idc.GetMnem(self.instructions[i+3]) == 'push' and
                idc.GetMnem(self.instructions[i+4]) == 'mov' and
                idc.GetMnem(self.instructions[i+5]) == 'mov' and
                idc.GetMnem(self.instructions[i+6]).startswith('cmov') and
                idc.GetMnem(self.instructions[i+7]) == 'mov' and
                idc.GetMnem(self.instructions[i+8]) == 'pop' and
                idc.GetMnem(self.instructions[i+9]) == 'pop'):


                print("Identified CMOVxx conditional branch at {:X}".format(ea))

                if idc.GetOpType(self.instructions[i+1], 0) != idc.o_imm:
                    print("Failed to get default jump target!")
                    sys.exit(1)
                else: 
                    default_jump_target = idc.GetOperandValue(self.instructions[i+1], 0)

                print("Identified CMOVxx default_jump_target {:X}".format(default_jump_target))

                if idc.GetOpType(self.instructions[i+5], 1) != idc.o_imm:
                    print("Failed to get conditional jump target!")
                    sys.exit(1)
                else: 
                    conditional_jump_target = idc.GetOperandValue(self.instructions[i+5], 1)

                print("Identified CMOVxx conditional_jump_target {:X}".format(conditional_jump_target))


                overwrite_start_ea = self.instructions[i+1]

                conditional_type = idc.GetMnem(self.instructions[i+6]).split('cmov')[1]
                ok1, conditional_jump_code = idautils.Assemble(overwrite_start_ea, 'j{} {:X}h'.format(conditional_type, conditional_jump_target))
                if ok1:
                    ok2, default_jump_code = idautils.Assemble(overwrite_start_ea+len(conditional_jump_code), 'jmp {:X}h'.format(default_jump_target))
                    if ok2:
                        print('j{} {:X}h'.format(conditional_type, conditional_jump_target))
                        print('jmp {:X}h'.format(default_jump_target))

                        print('linear space needed: {}, starting at: {:X}'.format(len(conditional_jump_code) + len(default_jump_code), overwrite_start_ea))

                        write_patch_linear_instructions(self.instructions[i+1:], [conditional_jump_code, default_jump_code])
                        patched = True
                        #write_patch_with_nops(overwrite_start_ea, conditional_jump_code, len(conditional_jump_code))
                        #write_patch_with_nops(overwrite_start_ea+len(conditional_jump_code), default_jump_code, len(default_jump_code))


            i += 1

        return patched


class ObfuCodeRelocator(object):
    def __init__(self, seg):
        self.seg = seg

    def RelocateNodes(self, root_node):
        original_ea = root_node.ea
        relocated_ea = self.seg.cur_ea
        instruction_map = self._recursive_copy(root_node)
        print(instruction_map)
        self._branch_fixups(instruction_map)

        return (original_ea, relocated_ea)

    def _recursive_copy(self, node):
        instruction_map = {}

        # Copy to new segment
        for ea in node.instructions:
            idc.OpHex(ea, -1)
            disasm = idc.GetDisasm(ea).replace('     ', ' ')
            #if 'ds:' in disasm:
            #    disasm = re.sub(r'ds:([a-zA-Z0-9_]+)', r'dword ptr ds:[\1]', disasm)
            if disasm == 'retn':
                disasm = 'ret'

            
            ok, code = idautils.Assemble(self.seg.cur_ea, disasm)
            print("Moving: {:X} {} -> {:X} {:X} ".format(ea, disasm, self.seg.cur_ea, ord(code[0])))
            if not ok:
                print('ERROR, NOT OK!', code)
                print('Manually copying instruction bytes')
                code = idaapi.get_bytes(ea, get_instruction_length(ea))

            # Save ea mapping for future jmp fixups
            instruction_map[ea] = self.seg.cur_ea

            idaapi.patch_bytes(self.seg.cur_ea, code)
            self.seg.cur_ea += len(code)

        for child in node.children:
            child_instruction_map = self._recursive_copy(child)
            instruction_map.update(child_instruction_map)

        """
        ida_auto.auto_make_code(node.instructions[0])
        ida_auto.auto_wait()
        idc.MakeCode(node.instructions[0])
        """

        return instruction_map

    def _branch_fixups(self, instruction_map):
        ida_auto.auto_wait()
        print("Start branch fixups")
        for old_ea, new_ea in instruction_map.iteritems():
            mnem = idc.GetMnem(old_ea)
            print(mnem)
            if is_conditional_jump_mnem(mnem) or mnem == 'jmp':
                print("branch at: {:X}".format(new_ea))
                jump_target = idc.GetOperandValue(new_ea, 0)
                if jump_target in instruction_map:
                    ida_auto.auto_wait()
                    original_length = get_instruction_length(old_ea)
                    if original_length >= 16:
                        print("get_instruction_length died for ea: {:X}".format(new_ea))
                        sys.exit(1)

                    ok, code = idautils.Assemble(new_ea, '{} 0{:X}h'.format(mnem, instruction_map[jump_target]))
                    if ok:
                        if len(code) <= original_length:
                            idaapi.patch_bytes(new_ea, '\x90'*original_length)
                            idaapi.patch_bytes(new_ea, code)
                        else:
                            print("fixup too large for insn at {:X}".format(new_ea))
                            sys.exit(1) 
                else:
                    print("Can't find fixup for jmp at {:X}".format(new_ea))
                    sys.exit(1) 


def get_fixed_node(ea):
    root_node = DeobfuNode(ea)#0x2389F93)
    
    root_node.Walk()
    root_node.FixRegions()

    root_node.Walk()
    root_node.FixRegions()

    root_node.Walk()
    root_node.FixRegions()

    return root_node


if __name__ == '__main__':
    breakpoint()
    obfuscated_eas = [0x3750E89]#0x13EF180]#[0xD36411]#0x293B6B0, 0x2389F93]

    deobfu_nodes = []
    for ea in obfuscated_eas:
        deobfu_nodes.append(get_fixed_node(ea))
        print(ea)

    """    
    chunks = root_node.get_chunks_recursive()#DeobfuNode.get_chunks(0x2389F93)
    #chunks = DeobfuNode.get_chunks(0x3D72C55)
    for chunk in chunks:
        print("chunk start {:X}, end {:X}".format(chunk[0], chunk[1]))
    """

    """
    print('stateful segment')
    
    seg = StatefulSegmentManager(".deobf", delete_existing=True)
    #idc.patch_dword(seg.cur_ea, 0xC3)
    #eas = DeobfuNode.linear_follow(0x293B6B0)

    breakpoint()
    print('RELOCATOR')

    relocator = ObfuCodeRelocator(seg)
    relocations = []

    for node in deobfu_nodes:
        print('relocate node: {:X}'.format(node.ea))
        time.sleep(5)
        relocations.append(relocator.RelocateNodes(node))
        time.sleep(60)
        ida_auto.auto_wait()


    
    print("Waiting a few seconds...")

    ida_auto.auto_wait()
    for relocation in relocations:
        ida_auto.auto_make_code(relocation[1])
        idc.MakeCode(relocation[1])

        print("Deobfuscated & relocated {:X} to {:X}".format(relocation[0], relocation[1]))

    """






    """
    root_node.clean_push_pass()
    root_node.clean_pop_pass()
    root_node.clean_push_jmp_ret_pass()
    root_node.clean_lea_jmp()
    root_node.clean_conditional_jump_pass()
    root_node.Walk(0x293B6B0)
    for ea in root_node.instructions:
        print(hex(ea).split('L')[0] + ' ' + idc.GetDisasm(ea))
    """

    #write_patch_with_nops(0x3D799D1, idautils.Assemble(0x3D799D1, 'jmp 0EED1B1h')[1], 5)