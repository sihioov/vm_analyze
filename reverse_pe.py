import pefile

def list_rwx_sections(path: str):    
    pe = pefile.PE(path)
    for s in pe.sections:
        flags = s.Characteristics
        perm  = []
        if flags & 0x20000000: perm.append('X')
        if flags & 0x40000000: perm.append('R')
        if flags & 0x80000000: perm.append('W')
        print(f"{s.Name.decode().strip():<8}  {''.join(perm):<3}  "
            f"VA {hex(pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress)}")
        

if __name__ == "__main__":
    list_rwx_sections(r"D:\\black\\L2j0m.exe")


# pe = pefile.PE(r"C:\Users\sihio\Downloads\Easy_CrackMe.exe")
# for s in pe.sections:
#     flags = s.Characteristics
#     perm  = []
#     if flags & 0x20000000: perm.append('X')
#     if flags & 0x40000000: perm.append('R')
#     if flags & 0x80000000: perm.append('W')
#     print(f"{s.Name.decode().strip():<8}  {''.join(perm):<3}  "
#           f"VA {hex(pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress)}")