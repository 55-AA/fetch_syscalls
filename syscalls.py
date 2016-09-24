'''
This IdaPython script fetchs syscall's ID and function name from 
those Windows dlls with IDA Pro, such as ntdll.dll, user32.dll.

It requires IDA 6.8 and later. For getting function prototypes,
A pdb file is required when the dll is first opened to analyze.

Then you can use 'Alt+F7' to open this script to run.

The last, you can obtain a output file at the script path.

A example of function fetched from IDA is following:

.text:77D74BF9      _NtUserGetPriorityClipboardFormat@8 proc near
.text:77D74BF9             mov     eax, 11BDh
.text:77D74BFE             mov     edx, 7FFE0300h
.text:77D74C03             call    dword ptr [edx]
.text:77D74C05             retn    8
.text:77D74C05      _NtUserGetPriorityClipboardFormat@8 endp

The example of output is following:
......
0x1178, NtUserDragDetect, BOOL, 3, (HWND, POINT)
0x1179, NtUserDragObject, DWORD, 5, (HWND, HWND, UINT, ULONG_PTR, HCURSOR)
0x117a, NtUserDrawAnimatedRects, BOOL, 4, (HWND, int, const, const)
0x117b, NtUserDrawCaption, PVOID, 4, (PVOID, PVOID, PVOID, PVOID)
......

The columns meanning above: 
allID, Func, return Type, arguments count, argument list

author: 55-AA

ref: https://www.hex-rays.com/products/ida/support/idapython_docs/
     idaapi.py
'''

import os
from idaapi import *

def parse_function_type(T):
    # BOOL __stdcall(HWND hwnd, LONG idObject, PSCROLLBARINFO psbi)
    (Ret, Other) = T.strip().split('(')
    Ret = Ret.strip().split(' ')[0].strip()
    Other = Other.strip().split(')')[0].strip()
    Args = ''
    for i in Other.split(','):
        i = i.strip()
        if 'const ' == i[:6]:
            i = i[6:]
        arg = i.split(' ')[0].strip()
        if i.find('*') >= 0:
            arg += " *"
        Args += arg + ', '
    if ', ' == Args[-2:] :
        Args = Args[:-2]

    if 'void' == Args:
        Args = ''

    return(Ret, Args)


def fetch_x86(seg, fout):
    total_func = 0
    func = get_next_func(seg.startEA)
    while func is not None and func.startEA < seg.endEA:
        funcEA = func.startEA
        INSTS = list(FuncItems(funcEA))
        if len(INSTS) == 4               \
        and "mov" == GetMnem(INSTS[0])   \
        and "mov" == GetMnem(INSTS[1])   \
        and "call" == GetMnem(INSTS[2])  \
        and "retn" == GetMnem(INSTS[3]) :
            ID = GetOperandValue(INSTS[0], 1)
            ArgN = get_frame_size(func) / 4 - 1
            Types = idc_get_type(funcEA)
            if Types:
                (Ret, Args) = parse_function_type(Types)
            else:
                Ret = 'PVOID'
                Args = 'PVOID, ' * ArgN
                if ', ' == Args[-2:] :
                    Args = Args[:-2]

            Name = get_func_name(funcEA).split('@')[0]
            if '_' == Name[0]:
                Name = Name[1:]
            
            print "0x%04x, %s(0x%x), %s, %d, (%s)" % (ID, Name, funcEA, Ret, ArgN, Args)
            fout.write("0x%04x, %s, %s, %d, (%s)\n" % (ID, Name, Ret, ArgN, Args))

            total_func += 1

        func = get_next_func(funcEA)

    return total_func

def fetch_x64(seg, fout):
    total_func = 0
    func = get_next_func(seg.startEA)
    while func is not None and func.startEA < seg.endEA:
        funcEA = func.startEA

        INSTS = list(FuncItems(funcEA))
        if len(INSTS) == 4               \
        and "mov" == GetMnem(INSTS[0])   \
        and "mov" == GetMnem(INSTS[1])   \
        and "syscall" == GetMnem(INSTS[2])  \
        and "retn" == GetMnem(INSTS[3]) :

            ID = GetOperandValue(INSTS[1], 1)
            Name = get_func_name(funcEA).split('@')[0]
            if '_' == Name[0]:
                Name = Name[1:]

            print "0x%04x, %s(0x%x)" % (ID, Name, funcEA)
            fout.write("0x%04x, %s\n" % (ID, Name))

            total_func += 1

        func = get_next_func(funcEA)

    return total_func

def main():
    seg = get_segm_by_name(".text")
    if not seg:
        print "canot find CODE section."
        return

    if get_inf_structure().is_64bit():
        arch = "_x64.txt"
    else:
        arch = "_x86.txt"

    file_out = get_root_filename().split('.')[0] + arch
    filename = os.path.join(os.path.dirname(os.path.realpath(__file__)) , file_out)
    f = open(filename, "w")

    if get_inf_structure().is_64bit():
        total_func = fetch_x64(seg, f)
    else:
        total_func = fetch_x86(seg, f)
 
    f.close()
    print "total:%d" % total_func

main()
 