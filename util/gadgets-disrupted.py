#!/usr/bin/python3

import sys

if len(sys.argv) < 3:
    print("Usage: {} <gadgets> <randomization log> <start> <end>" \
        .format(sys.argv[0]))
    sys.exit(1)

if len(sys.argv) >= 5:
    startRange = int(sys.argv[3], base=16)
    endRange = int(sys.argv[4], base=16)
else:
    startRange = 0
    endRange = 0xffffffffffffffff

verbose = True

class Gadget:
    def __init__(self, addr, size, ninstr):
        self.start = addr
        self.end = addr + size
        self.size = size
        self.ninstr = ninstr
        self.disrupted = False

    def overlaps(self, start, end):
        if self.end > start and self.start < end : return True
        else: return False

    def __str__(self):
        return "{:x} - {:x} ({} instructions)" \
                .format(self.start, self.end, self.ninstr)

def instrSize(instr):
    def operandSize(operands):
        # TODO finish implementing
        return 2
        #if operands[0] == "qword":
        #    return 2 # Not correct if the register doesn't have an offset
        #else: return 1

    if instr[0] == "ret":
        if len(instr) > 1: return 3 # ret imm16
        else: return 1              # ret
    elif instr[0] == "syscall" or instr[0] == "sysenter": return 2
    elif instr[0] == "jmp" or instr[0] == "call":
        return 1 + operandSize(instr[1:])
    else:
        print("WARNING: unknown instruction size for {}".format(instr))
        return 0

gadgets = []
ninstr = 0
ntrivial = 0
with open(sys.argv[1], 'r') as gadgetFile:
    for line in gadgetFile:
        fields = line.strip().split()
        if "Gadget:" in line:
            addr = int(fields[1], base=16)
        elif "gadgets found" in line:
            continue
        elif len(fields) > 1:
            lastAddr = int(fields[0][:-1], base=16)
            lastInstr = fields[1:]
            ninstr += 1
        elif ninstr:
            if startRange <= addr and addr < endRange:
                size = lastAddr + instrSize(lastInstr) - addr
                if ninstr == 1:
                    ntrivial += 1
                    if verbose:
                        print("1-instruction gadget at 0x{:x}".format(addr))
                if addr in gadgets:
                    print("WARNING: duplicate gadget at 0x{:x}".format(addr))
                gadgets.append(Gadget(addr, size, ninstr))
            elif verbose:
                print("Skipping {:x}".format(addr))
            ninstr = 0

gadgets.sort(key=lambda x: x.start)
ngadgets = len(gadgets)
print("Parsed {} gadgets ({} 1-instruction gadgets)".format(ngadgets, ntrivial))

nrewrote = 0
with open(sys.argv[2], 'r') as randomizeLog:
    for line in randomizeLog:
        if "transform.cpp" not in line: continue
        if "rewrote" in line:
            nrewrote += 1
            # TODO use binary search
            for g in gadgets:
                if g.overlaps(addr, addr + size):
                    if verbose:
                        print("Instruction @ {:x} - {:x} disrupted gadget {}" \
                            .format(addr, addr + size, g))
                    g.disrupted = True
        else:
            fields = line.strip().split()
            try:
                addr = int(fields[4], base=16)
                size = int(fields[7])
            except ValueError: continue

ndisrupted = sum(x.disrupted for x in gadgets)
print("Rewrote {} instructions".format(nrewrote))
print("Total gadgets: {}, disrupted: {}, {:.2f} % ({:.2f} % non-trivial)" \
    .format(ngadgets, ndisrupted,
            100 * float(ndisrupted) / float(ngadgets),
            100 * float(ndisrupted) / float(ngadgets - ntrivial)))
