#!/usr/bin/python3

import sys, statistics

if len(sys.argv) < 2:
    print("Please supply a Chameleon-generated log file")
    sys.exit(1)

class Function:
    def __init__(self, addr):
        self.addr = addr
        self.regions = []

    def addRegion(self, name, bits, nslots):
        if name != 'alignment': self.regions.append((name, bits, nslots))

    def avg(self):
        totalBits = sum(r[1] * r[2] for r in self.regions \
                        if r[0] != 'callee-save without SP/FBP')
        totalSlots = sum(r[2] for r in self.regions \
                         if r[0] != 'callee-save without SP/FBP')
        return float(totalBits) / float(totalSlots)

    def setsUpFrame(self):
        frame = False
        for r in self.regions:
            if r[0] == "callee-save" or r[0] == "callee-save without SP/FBP":
                if r[1] > 0.0: frame = True
            else: frame = True
        return frame

    def __str__(self):
        if self.setsUpFrame(): frame = ""
        else: frame = " (does not set up frame)"

        ret = "Function @ 0x{:x}{}:\n".format(self.addr, frame)
        for r in self.regions:
            ret += "  {}: {} bit(s) for {} slot(s)\n".format(r[0], r[1], r[2])
        ret += "  average: {}\n".format(self.avg())
        return ret

functions = []
curFunc = None
with open(sys.argv[1]) as log:
    for line in log:
        if 'analyzing function @' in line:
            if curFunc: functions.append(curFunc)
            fields = line.strip().split()
            curFunc = Function(int(fields[7][:-1], base=16))
        elif 'bits of entropy' in line:
            startParen = line.find('(')
            endParen = line.find(')')
            fields = line[endParen+3:].strip().split()
            name = line[startParen+1: endParen]
            bits = float(fields[0])
            nslots = int(fields[2])
            curFunc.addRegion(name, bits, nslots)

average = []
averageFrameOnly = []
for f in functions:
    curAvg = f.avg()
    average.append(curAvg)
    if f.setsUpFrame(): averageFrameOnly.append(curAvg)
    print(f)
print("Average bits of entropy: {}".format(statistics.mean(average)))
print("Average bits of entropy (only functions that set up frame): {}" \
      .format(statistics.mean(averageFrameOnly)))
