# Work with raw fltrace output to find callsites 

import argparse
from enum import Enum
import os
import sys
import subprocess
import pandas as pd
import re
from dataclasses import dataclass,field

from bisect import bisect_left

def binary_search(a, x, key,lo=0, hi=None):
    if hi is None: hi = len(a)
    pos = bisect_left(a, x, lo, hi, key=key)         # find insertion position
    return pos if pos != hi and key(a[pos]) == x else -1  # don't walk off the end

TIMECOL = "tstamp"

# parse /proc/<pid>/maps
MAPS_LINE_RE = re.compile(r"""
    (?P<addr_start>[0-9a-f]+)-(?P<addr_end>[0-9a-f]+)\s+  # Address
    (?P<perms>\S+)\s+                                     # Permissions
    (?P<offset>[0-9a-f]+)\s+                              # Map offset
    (?P<dev>\S+)\s+                                       # Device node
    (?P<inode>\d+)\s+                                     # Inode
    (?P<path>.*)\s+                                   # path
""", re.VERBOSE)


class Record:
    """A line in /proc/<pid>/maps"""
    addr_start: int
    addr_end: int
    perms: str
    offset: int
    dev: str
    inode: int
    path: str

    @staticmethod
    def parse(filename):
        records = []
        with open(filename) as fd:
            for line in fd:
                m = MAPS_LINE_RE.match(line)
                if not m:
                    print("Skipping: %s" % line)
                    continue
                addr_start, addr_end, perms, offset, _, _, path = m.groups()
                r = Record()
                r.addr_start = int(addr_start, 16)
                r.addr_end = int(addr_end, 16)
                r.offset = int(offset, 16)
                r.perms = perms
                r.path = path
                records.append(r)
        return records

    @staticmethod
    def find_record(records, addr):
        for r in records:
            if r.addr_start <= addr < r.addr_end:
                return r
        return None


class LibOrExe:
    """A library or executable mapped into process memory"""
    records: list
    ips: list
    path: str
    base_addr: int
    codemap: dict

    def __init__(self, records):
        """For libs collected from /proc/<pid>/maps"""
        self.records = records
        self.path = records[0].path
        self.base_addr = min([r.addr_start for r in records])
        self.ips = []
        self.codemap = {}
        self.objdump = None

    def code_location(self, ipx):
        """Lookup the library to find code location for an ip"""
        assert ipx in self.ips, "ip does not fall in lib: " + ipx
        if not self.codemap and self.ips:
            ips = self.ips
            # offset the ips if the lib is loaded at a high address
            if self.base_addr >= 2**32:
                ips_int = [int(ip, 16) for ip in self.ips]
                ips = [hex(ip - self.base_addr) for ip in ips_int]
            locations = lookup_code_locations(self.path, ips)
            self.codemap = dict(zip(self.ips, locations))
        return self.codemap[ipx]


def lookup_code_locations(libpath, ips):
    """Lookup a library using addr2line to find code location for each ip"""
    assert os.path.exists(libpath), "can't locate lib: " + libpath
    sys.stderr.write("looking up {} for {} ips\n".format(libpath, len(ips)))
    locations = subprocess.check_output(     \
        ['addr2line', '-p', '-i', '-e', libpath] + list(ips)) \
        .decode('utf-8')    \
        .replace("\n (inlined by) ", "<<<")   \
        .split("\n")
    locations.remove("")
    assert(len(locations) == len(ips))
    return locations


class FaultOp(Enum):
    """Enumerates the memory access operations that result in a fault"""
    READ = "read"
    WRITE = "write"
    WRPROTECT = "wrprotect"

    def parse(flags):
        """Get the access op from the flags column"""
        op = flags & 0x1F
        if op == 0:   return FaultOp.READ
        if op == 1:   return FaultOp.WRITE
        if op == 3:   return FaultOp.WRPROTECT
        raise Exception("unknown op: {}".format(op))
    
    def __str__(self):
        return self.value


class FaultType(Enum):
    """Enumerates the fault types (defined in fltrace)"""
    REGULAR = "regular"
    ZEROPAGE = "zero"

    def parse(flags):
        """Get the fault type from the flags column"""
        type = flags >> 5
        if type == 0:   return FaultType.REGULAR
        if type == 1:   return FaultType.ZEROPAGE
        raise Exception("unknown type: {}".format(type))

    def __str__(self):
        return self.value

@dataclass
class ObjDump_ASM_Instr:
    addr: int
    hex_repr:str # space separate
    instr:str
    params:str

    def get_full_text_repr(self):
        return self.instr+' '+self.params

    def __str__(self):
        return self.get_full_text_repr()

@dataclass
class ObjDump_Section:
    name:str
    start_addr:int  #included
    end_addr:int = -1 # excluded
    asm_instructions : list[ObjDump_ASM_Instr] = field(default_factory=list)

@dataclass
class ObjDump:
    sections : list[ObjDump_Section] = field(default_factory=list) #sorted by section start address

def get_objdump_object(binary_file):
    objdump_out = subprocess.run(['objdump', '-d', binary_file], stdout=subprocess.PIPE).stdout.decode("utf-8")
    objdump = ObjDump()
    current_section = None
    change_of_data_section = False
    for line in objdump_out.split("\n")[3:]:
        if line is None:
            continue
        elif line.startswith("Disassembly of section"):
            change_of_data_section = True
        elif line.strip() != '':
            if line[0].isnumeric():
                #We're starting a new section
                assert ':' in line
                splitted = line.split()
                assert len(splitted) == 2
                raw_start, raw_name = splitted[0],splitted[1]
                assert raw_start.isalnum() and '<' in raw_name and '>' in raw_name
                curr_add = int(raw_start,16)
                if current_section is not None and not change_of_data_section:
                    # End previous section
                    assert current_section.end_addr == curr_add
                    objdump.sections.append(current_section)
                change_of_data_section = False
                # Start the new one
                current_section = ObjDump_Section(start_addr=curr_add,name=raw_name)  # .replace('<','').replace('>','')) ?
            else:
                elements = line.strip().split('\t')
                assert ':' == elements[0][-1]
                curr_add = elements[0][:-1]
                assert curr_add.isalnum()
                curr_add = int(curr_add,16)
                hex_repr = elements[1].strip()
                if len(elements) == 2 :
                    #nop, quick path
                    instr = "nop"
                    params = ""
                else:
                    assert len(elements) == 3
                    textual_repr = elements[2] if len(elements) == 3 else "nop"
                    tr_splitted = textual_repr.split()
                    # for everything but `bnd <instr>`, instruction is one word, rest is params
                    # `bnd` simply specifies CPU to check bounds, can ignore it, as it doesn't give semantical info abt input
                    if "bnd" in textual_repr:
                        assert tr_splitted[0] == "bnd"
                        tr_splitted = tr_splitted[1:]
                    instr = tr_splitted[0]
                    # restore params with spaces (e.g.: for `call`)
                    params = ' '.join(tr_splitted[1:])
                curr_line_asm = ObjDump_ASM_Instr(curr_add,hex_repr,instr,params)
                current_section.asm_instructions.append(curr_line_asm)
        elif current_section is not None:
            # End Section
            last_asm_instr = current_section.asm_instructions[-1]
            current_section.end_addr = last_asm_instr.addr + len(last_asm_instr.hex_repr.split())
    objdump.sections.sort(key=lambda section: section.start_addr) # Should essentially not change the order, but juuuust in case
    return objdump


def get_surrounding_assembly(loe:LibOrExe,ip:int,window:int=3, only_future=False) -> (list[ObjDump_ASM_Instr],str):
    correct_rec = Record.find_record(loe.records,ip)
    assert correct_rec
    ip = correct_rec.offset + (ip-correct_rec.addr_start)
    # returns element after which we can insert such that we remain sorted
    objdump = loe.objdump
    address_section_idx = bisect_left(objdump.sections,ip,lo=0,hi=len(objdump.sections),key=lambda section: section.start_addr)
    if objdump.sections[address_section_idx].start_addr != ip:
        assert address_section_idx != 0 and objdump.sections[address_section_idx].start_addr > ip
        address_section_idx -= 1
    ip_sect = objdump.sections[address_section_idx]
    assert ip_sect.start_addr <= ip < ip_sect.end_addr
    asms_in_sect = ip_sect.asm_instructions
    ip_idx_in_list = binary_search(asms_in_sect,ip,lambda asm_inst: asm_inst.addr)
    assert ip_idx_in_list != -1
    min_past,max_future = max(0,ip_idx_in_list-window),min(len(asms_in_sect),ip_idx_in_list+window)
    if only_future:
        min_past = ip_idx_in_list
    return asms_in_sect[min_past:max_future],ip_sect.name


def main():
    parser = argparse.ArgumentParser("Process input and write csv-formatted data to stdout/output file")
    parser.add_argument('-i', '--input', action='store', nargs='+', help="path to the input/data file(s)", required=True)
    parser.add_argument('-st', '--start', action='store', type=int,  help='start tstamp to filter data')
    parser.add_argument('-et', '--end', action='store', type=int, help='end tstamp to filter data')
    parser.add_argument('-fo', '--faultop', action='store', type=FaultOp, choices=list(FaultOp), help='filter for a specific fault op')
    parser.add_argument('-fr', '--frcutoff', action='store', type=int,  help='cut off the seconds where fault rate per second is less than this')
    parser.add_argument('-b', '--binary', action='store', help='path to the binary file to locate code location')
    parser.add_argument('-pm', '--procmap', action='store', help='path to the proc maps file to locate unresolved libraries')
    parser.add_argument('-ma', '--maxaddrs', action='store_true', help='just return max uniq addrs')
    parser.add_argument('-o', '--out', action='store', help="path to the output file")
    args = parser.parse_args()

    # read in
    dfs = []
    for file in args.input:
        if not os.path.exists(file):
            print("can't locate input file: {}".format(file))
            exit(1)

        tempdf = pd.read_csv(file, skipinitialspace=True)
        sys.stderr.write("rows read from {}: {}\n".format(file, len(tempdf)))
        dfs.append(tempdf)
    df = pd.concat(dfs, ignore_index=True)

    # time filter
    if args.start:  df = df[df[TIMECOL] >= args.start]
    if args.end:    df = df[df[TIMECOL] <= args.end]

    # op col renamd to flags
    FLAGSCOL="flags"

    # group by ip or trace
    TRACECOL="trace"

    # return max uniq addrs if specified
    if args.maxaddrs:
        df = df[df[FLAGSCOL] < 32]  # filter out zero-page faults : this removes all page faults which occur on the first access of page
        df = df.groupby("addr").size().reset_index(name='count')
        print(len(df.index))
        return

    df = df.rename(columns={TRACECOL: "ips"})

    # evaluate op & type
    if df.empty:
        df["op"] = []
        df["type"] = []
    else:
        df["op"] = df.apply(lambda r: FaultOp.parse(r[FLAGSCOL]).value, axis=1)
        df["type"] = df.apply(lambda r: FaultType.parse(r[FLAGSCOL]).value, axis=1)
    
    # filter by op
    if args.faultop:    df = df[df["op"] == args.faultop.value]

    # get all unique ips
    iplists = df['ips'].str.split("|")
    ips = set().union(*[set(i) for i in iplists])
    ips.discard("")

    # if procmap is available, look up library locations
    libmap = {}
    libs = {}
    if args.procmap:
        assert os.path.exists(args.procmap)
        records = Record.parse(args.procmap)
        for ip in ips:
            lib = Record.find_record(records, int(ip, 16))
            assert lib, "can't find lib for ip: {}".format(ip)
            assert lib.path, "no lib file path for ip: {}".format(ip)
            if lib.path not in libs:
                librecs = [r for r in records if r.path == lib.path]
                libs[lib.path] = LibOrExe(librecs)
            libs[lib.path].ips.append(ip)
            libmap[ip] = lib.path
        # print(libmap)
        # print(libs)

    # make a new lib column
    def liblookup(ips):
        iplist = ips.split("|")
        lib = "<//>".join([libmap[ip] if ip in libmap else "??" for ip in iplist])
        return lib
    df['lib'] = df['ips'].apply(liblookup)

    # if binary is provided, use it to look up code locations
    codemap = {}
    if args.binary:
        assert args.procmap
        for path,lib in libs.items():
            # If there is an executable record (= memory region) for that lib/exec
            if sum([int('x' in record.perms) for record in lib.records])>0:
                lib.objdump = get_objdump_object(lib.path)
        ip_to_windows_cache = {}
        def instructions_lookup(ips):
            iplist = ips.split("|")
            if iplist[-1] == '':
                del iplist[-1]
            instrs = ';'.join(
                [' '.join(
                    [asm_instr.get_full_text_repr() for asm_instr in
                     ip_to_windows_cache.setdefault(ip,
                                                    get_surrounding_assembly(libs[libmap[ip]],
                                                                             int(ip,16),
                                                                             only_future=True))[0]]
                    ) for ip in iplist])
            return instrs
        df['surr_insts'] = df['ips'].apply(instructions_lookup)

    # make a new code column
    def codelookup(ips):
        iplist = ips.split("|")
        locations = []
        for ip in iplist:
            if ip in libmap:
                lib = libs[libmap[ip]]
                locations.append(lib.code_location(ip))
            elif ip in codemap:
                locations.append(codemap[ip])
            else:
                locations.append("??:?")
        code = "<//>".join(locations)
        return code
    df['code'] = df['ips'].apply(codelookup)

    # write out
    out = args.out if args.out else sys.stdout
    df.to_csv(out, index=False, header=True)

if __name__ == '__main__':
    main()
