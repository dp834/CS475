#! /usr/bin/python3
import argparse
import os.path
import sys
from collections import defaultdict

def is_valid_file(parser, file):
    if(file=="-" or os.path.exists(file)):
        return file
    else:
        parser.error("File {} does not exist".format(file))

parser = argparse.ArgumentParser(description="Disassembler for a made up architecture the s20")
parser.add_argument('file_type', choices=["b","binary", "t", "text"], help="Is the input file is binary or text")
parser.add_argument('-f', dest="filename", metavar="file", help="File to read from, default is stdin", default="-",
                    type=lambda x: is_valid_file(parser,x))



opcode_table     = {-1:"UNKOWN-op", 0x1:"ld", 0x2:"st", 0x3:"br", 0x4:"bsr", 0x5:"brz", 0x6:"bnz", 0x7:"brn", 0x8:"bnn"}
sub_opcode_table = {-1:"UNKOWN-subop", 0x0:"nop", 0x01:"ldi", 0x02:"sti", 0x03:"add", 0x04:"sub", 0x05:"and", 0x06:"or",
                    0x07:"xor", 0x08:"shl", 0x09:"sal",0x0A:"shr", 0x0B:"sar", 0x0C:"rts", 0x1F:"halt"}

class Instruction:
    # static counts so
    # labels and variables are unique
    variable_count = 0
    label_count = 0

    def __init__(self, address, instr, type, code, dict):
        self.addr        = address
        self.instr       = instr
        # types are op, subop, data
        self.type        = type
        # opcode or subopcode
        self.code        = code
        self.code_dict   = dict
        self.label       = ""
        self.args        = ""

        # Used when seeing what code is reachable
        self.visited     = False


    def parse_args(self, program):
        if(self.type == "data"):
            self.args = "0"
        elif(self.type == "op"):
            # if ld
            # print src, dest
            if(self.code in [0x01]):
                self.args = "{}, r{}".format(self.get_label_from_address(program, self.instr & 0x7FFF),
                                            (self.instr >> 15) & 0x1F)
            # if st
            # print src, dest
            elif(self.code in [0x02]):
                self.args = "r{}, {}".format((self.instr >> 15) & 0x1F,
                                              self.get_label_from_address(program, self.instr & 0x7FFF))
            # if br or bsr
            # print label (register is ignored)
            elif(self.code in [0x03, 0x04]):
                self.args = "{}".format(self.get_label_from_address(program, self.instr & 0x7FFF))

            # if bzr, bnz, brn, bnn
            # print register, label
            elif(self.code in [0x05,0x06,0x07, 0x08]):
                self.args = "r{}, {}".format((self.instr >> 15) & 0x1F,
                                              self.get_label_from_address(program, self.instr & 0x7FFF))
            # Unkown print format
            else:
                self.args = "Unkown format"

        elif(self.type == "subop"):

            # if ldi
            # rA = base
            # rB = offset
            # rC = dest
            # print base, offset, dest
            if(self.code in [0x01]):
                self.args = "r{}, r{}, r{}".format((self.instr >>  5) & 0x1F,
                                                   (self.instr >> 15) & 0x1F,
                                                   (self.instr >> 10) & 0x1F)
            # if sti
            # rA = base
            # rB = offset
            # rC = src
            # print src, base, offset
            elif(self.code in [0x02]):
                self.args = "r{}, r{}, r{}".format((self.instr >>  5) & 0x1F,
                                                   (self.instr >> 15) & 0x1F,
                                                   (self.instr >> 10) & 0x1F)
            # if add, sub, and, or, xor
            # print src, src, dest
            elif(self.code in [0x03, 0x04, 0x05, 0x06, 0x07]):
                self.args = "r{}, r{}, r{}".format((self.instr >> 15) & 0x1F,
                                                   (self.instr >> 10) & 0x1F,
                                                   (self.instr >>  5) & 0x1F)
            # if shl, sal, shr, sar
            # print src, shift count, dest
            elif(self.code in [0x08, 0x09, 0x0A, 0x0B]):
                self.args = "r{}, {:2}, r{}".format((self.instr >> 15) & 0x1F,
                                                    (self.instr >> 10) & 0x1F,
                                                    (self.instr >>  5) & 0x1F)
            # if nop, rts, halt
            # no args
            elif(self.code in [0x00, 0x10, 0x1f]):
                self.args = ""

            else:
                self.args = "Unkown format"

    def get_label_from_address(self, program, address):
        if(len(program) < address):
            return "Address {:04x} not found".format(address)
        else:
            l = program[address].label
            if(l == ""):
                l = "{:04x}".format(address)
            return l

    def get_code_str(self):
        if(self.type == "data"):
            return "data"
        else:
            return self.code_dict[self.code]

    def give_label(self, type):
        if(self.label != ""):
            # if i have a label don't replace
            return
        if(type == "var"):
            self.label = "x{}".format(Instruction.variable_count)
            Instruction.variable_count += 1
        elif(type == "label"):
            self.label = "l{}".format(Instruction.label_count)
            Instruction.label_count +=1

    def explore(self, program):
        if(self.visited):
            # some loop has happened
            # don't fall into infinite loop
            return
        self.visited = True
        # implement logic for each group of commands
        if(self.type == "op"):
            addr = self.instr & 0x7FFF
            if(self.code in [0x01, 0x02]):
                # reading or writing variable
                program[addr].give_label("var")
                program[addr].type = "data"

            else:
                program[addr].give_label("label")
                program[addr].explore(program)

            program[self.addr + 1].explore(program)

        elif(self.type == "subop"):
            # can't trigger explore or find new data
            # since this only runs modifies registers
            # program will continue to next instruction
            if(self.code == 0x1f):
                # if we are halt then don't run next
                return
            program[self.addr + 1].explore(program)

        elif(self.type == "data"):
            # Here we seem to be executing some modified data
            # Mark it but ignore?
            self.label = "Exec data"
            self.args = "Executing field that has been written to"
            program[self.addr + 1].explore(program)

    def __str__(self):
        return "{address:04x} {instr:06x} {label:8} {code:5} {args}".format(
                        address = self.addr,
                        instr   = self.instr,
                        label   = self.label,
                        code    = self.get_code_str(),
                        args    = self.args
                        )

# given an instruction and address will return
# a (address, instr, opcode, sub-opcode, [args])
# if anything is invalid it will be marked as -1
def breakdown_instruction(address, instr):
    code = (instr >> 4*5) & 0xF
    type = ""
    if(code == 0):
        code = (instr & 0x1F)
        if(code not in sub_opcode_table.keys()):
            # invalid sub_opcode probably data
            code = -1
        else:
            type = "subop"
            dict = sub_opcode_table

    else:
        if(code not in opcode_table.keys()):
            # invalid opcode probably data
            code = -1
        else:
            type = "op"
            dict = opcode_table

    return Instruction(address, instr, type, code, dict)

def read_by_instruction(data,type):
    readsize = 0
    if(type == "b"):
        # An instruction is 3 bytes
        readsize = 3
    else:
        # A byte is two characters in hex
        readsize = 3 * 2

    instruction = data.read(readsize)
    # TODO: What is end condition if reading binary
    while(instruction != "\n"):
        if(type == "t"):
            # convert text to integer, stored in hex
            instruction = int(instruction,16)
        yield instruction
        instruction = data.read(readsize)



def disassemble(data, type):
    addr    = 0x00
    program = []
    for instr in read_by_instruction(data,type):
        program.append(breakdown_instruction(addr, instr))
        addr += 1

    program[0].explore(program)

    for instr in program:
        if(not instr.visited):
            instr.type = "data"
        instr.parse_args(program)
        print(instr)



if(__name__ == "__main__"):
    args = parser.parse_args()

    if(args.file_type == 'b'):
        read_type = "rb"
    else:
        read_type = "r"

    file = None

    if(args.filename == "-"):
        if(args.file_type in ["b", "binary"]):
            args.file_type = "b"
            file = sys.stdin.buffer
        else:
            args.file_type = "t"
            file = sys.stdin
    else:
        if(args.file_type in ["b", "binary"]):
            args.file_type = "b"
            file = open(args.filename, "rb")
        else:
            args.file_type = "t"
            file = open(args.filename, "r")

    disassemble(file, args.file_type)

    if(args.filename != "-"):
        file.close()



