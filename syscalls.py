'''
This IdaPython script fetchs syscall's ID and function name from 
those Windows dlls with IDA Pro, such as ntdll.dll, user32.dll.

It requires IDA 6.8 and later. For getting function prototypes,
A pdb file is required when the dll is first opened to analyze.

If not a H_APIs.h, You need generate it from ntgdi_reactos.h,
ntuser_reactos.h and ntuser_w2k.h, then use 'Alt+F7' to open 
this script to run. The H_APIs.h supply the prototype, when IDA 
cannot get it.

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
/*0x116e,03*/BOOL NtUserDeleteMenu(HMENU,UINT,UINT);
/*0x1211,03*/BOOL NtUserRemoveMenu(HMENU,UINT,UINT);
/*0x122d,03*/BOOL NtUserSetMenuDefaultItem(HMENU,UINT,UINT);
/*0x1172,01*/BOOL NtUserDestroyMenu(HMENU);
/*0x11ef,06*/BOOL NtUserMoveWindow(HWND,INT,INT,INT,INT,BOOL);
/*0x1158,01*/BOOL NtUserCheckDesktopByThreadId(DWORD);
......

The columns meanning above: 
ID, Paramster count, Function prototype

author: 55-AA

ref: https://www.hex-rays.com/products/ida/support/idapython_docs/
     idaapi.py
'''

import os
from idaapi import *

g_param_format = {
    "char"      : "CHAR",
    "int"       : "INT",
    "void"      : "VOID",
    "_DWORD"    : "DWORD",

    "LPSTR"     : "PSTR",
    "LPCSTR"    : "PCSTR",
    "LPWSTR"    : "PWSTR",
    "LPCWSTR"   : "PCWSTR",

    "LPVOID"    : "PVOID",
    "LPCHAR"    : "PCHAR",
    "LPUCHAR"   : "PUCHAR",
    "LPBYTE"    : "PBYTE",
    "LPWCHAR"   : "PWCHAR",
    "LPSHORT"   : "PSHORT",
    "LPUSHORT"  : "PUSHORT",
    "LPDWORD"   : "PDWORD",
    "LPWORD"    : "PWORD",
    "LPINT"     : "PINT",
    "LPUINT"    : "PUINT",
    "LPLONG"    : "PLONG",
    "LPULONG"   : "PULONG",
    "LPBOOL"    : "PBOOL",

    "PMSG"      : "LPMSG",
    "PSIZE"     : "LPSIZE",
    "PPOINT"    : "LPPOINT",
    "PRECT"     : "LPRECT",
    "PCURSORINFO"       : "LPCURSORINFO",
    "PTITLEBARINFO"     : "LPTITLEBARINFO",
    "PGUITHREADINFO"    : "LPGUITHREADINFO",
    "PSCROLLBARINFO"    : "LPSCROLLBARINFO",
    "PCOMBOBOXINFO"     : "LPCOMBOBOXINFO",
}

g_param_format2 = {
    "VOID*"     : "PVOID",
    "CHAR*"     : "PCHAR",
    "UCHAR*"    : "PUCHAR",
    "BYTE*"     : "PBYTE",
    "WCHAR*"    : "PWCHAR",
    "SHORT*"    : "PSHORT",
    "USHORT*"   : "PUSHORT",
    "DWORD*"    : "PDWORD",
    "WORD*"     : "PWORD",
    "INT*"      : "PINT",
    "UINT*"     : "PUINT",
    "LONG*"     : "PLONG",
    "ULONG*"    : "PULONG",
    "BOOL*"     : "PBOOL",
    #structure
    "SIZE*"             : "LPSIZE",
    "MSG*"              : "LPMSG",
    "POINT*"            : "LPPOINT",
    "POINTL*"           : "PPOINTL",
    "HKL*"              : "LPHKL",
    "RECT*"             : "LPRECT",
    "RECTL*"            : "LPRECTL",
    "COLORREF*"         : "LPCOLORREF",
    "WNDCLASSEXW*"      : "LPWNDCLASSEXW",
    "PAINTSTRUCT*"      : "LPPAINTSTRUCT",
    "WINDOWPLACEMENT*"  : "LPWINDOWPLACEMENT",
    "BLENDFUNCTION*"    : "PBLENDFUNCTION",     #
}

def format_type(T):
    A = T.split('*')
    param = A[0]
    if param in g_param_format.keys():
        param = g_param_format[param]

    if len(A) > 1:
        param += '*'
        if param in g_param_format2.keys():
            param = g_param_format2[param]

    return param

def from_IDA_function_type(T):
    # BOOL __stdcall(HWND hwnd, LONG idObject, PSCROLLBARINFO psbi)
    (Ret, Other) = T.strip().split('(')
    Ret = Ret.strip().split(' ')[0].strip()
    Ret = format_type(Ret)
    Other = Other.strip().split(')')[0].strip()
    Args = []
    Argn = 0
    IN_key_skip = ["IN", "OUT", "CONST", "const", "OPTIONAL"]
    for i in Other.split(','):
        words = i.split()
        for j in IN_key_skip:
            if j in words:
                words.remove(j)

        if len(words) > 0:
            arg = words[0]
            argument = ''
            if len(words) > 1:
                argument = words[1]

            if '*' in words:
                arg += '*'
            else:
                if len(words) > 1 and '*' == words[1][:1]:
                    arg += '*'

            Argn += 1
        else:
            arg = "VOID"

        Args.append(format_type(arg))

    return(Ret, ','.join(Args), Argn)

g_func_dict = {}

def load_h_file(h_file):
    f = open(h_file, "r")
    for line in f:
        (line, paramN) = line.split(');//')
        (func_ret, line) = line.split(' ', 1)
        (func_name, parameters) = line.split('(')
        dictV = [func_ret, int(paramN), parameters]
        g_func_dict[func_name] = dictV
        continue

    f.close()
    
def from_h_function_type(Name, argN):
    if Name in g_func_dict.keys():
        Value = g_func_dict[Name]
        if Value[1] == argN:
            return (Value[0], Value[2], Value[1])

    Ret = '_UNKNOWN'
    Args = ','.join([Ret] * argN)
    return (Ret, Args, argN)

def fetch_x86(seg, fout):
    g_TotalFunc = 0
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

            Name = get_func_name(funcEA).split('@')[0]
            if '_' == Name[0]:
                Name = Name[1:]

            ArgN = get_frame_size(func) / 4 - 1

            Types = idc_get_type(funcEA)
            if Types:
                (Ret, Args, ArgN) = from_IDA_function_type(Types)
            else :
                (Ret, Args, ArgN) = from_h_function_type(Name, ArgN)

            print '/*0x%04x,%02d*/%s %s(%s);' % (ID, ArgN, Ret, Name, Args)
            fout.write('/*0x%04x,%02d*/%s %s(%s);\n' % (ID, ArgN, Ret, Name, Args))

            g_TotalFunc += 1

        func = get_next_func(funcEA)

    return g_TotalFunc

def fetch_x64(seg, fout):
    g_TotalFunc = 0
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

            g_TotalFunc += 1

        func = get_next_func(funcEA)

    return g_TotalFunc

def main():
    seg = get_segm_by_name(".text")
    if not seg:
        print "canot find CODE section."
        return

    if get_inf_structure().is_64bit():
        arch = "_x64.txt"
    else:
        arch = "_x86.txt"

    current_path = os.path.join(os.path.dirname(os.path.realpath(__file__)))
    load_h_file(os.path.join(current_path, "H_APIs.h"))

    file_out = get_root_filename().split('.')[0] + arch
    f = open(os.path.join(current_path, file_out), "w")

    if get_inf_structure().is_64bit():
        g_TotalFunc = fetch_x64(seg, f)
    else:
        g_TotalFunc = fetch_x86(seg, f)
 
    f.close()
    print "total:%d" % g_TotalFunc

main()
 