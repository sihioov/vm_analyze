# patch_iat.py
import pefile

# 1) 대상 파일 경로
src = r"D:\black\L2j0m.exe"
dst = r"D:\black\L2j0m.iatpatched.exe"

# 2) 패치할 함수 목록
TARGETS = {
    b"kernel32.dll": [b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent"],
    b"ntdll.dll":   [b"NtQueryInformationProcess"]
}

pe = pefile.PE(src)

# 3) Import Directory 순회
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.lower()
    if dll in TARGETS:
        for imp in entry.imports:
            if imp.name in TARGETS[dll]:
                rva = imp.address - pe.OPTIONAL_HEADER.ImageBase
                print(f"Patching {dll.decode()}!{imp.name.decode()} @ RVA 0x{rva:X}")
                # IAT thunk(4/8바이트 포인터)는 프로세스 로드 시 FAT()->jmp [IAT] 형태로 쓰임.
                # 여기서는 IAT에 바로 'ret' 하나만 써 넣어서 호출 즉시 복귀하게 만듦.
                pe.set_bytes_at_rva(rva, b"\xC3")

# 4) 새 파일로 저장
pe.write(dst)
print(f"Written patched file to {dst}")
