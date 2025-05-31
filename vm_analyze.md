vm_analyze

# 목표
## VM 바이트코드 주소부터 시작해 tail-call 흐름을 따라가며 어떤 연산이 수행되는지 자동 추적하는 도구

# 기본 구성
## 분석 도구 설계
구성 요소	설명
VMAnalyzer 클래스	전체 흐름 추적 및 컨트롤
HandlerTracer 클래스	tail-call 흐름을 따라가며 연산을 추적
BinaryReader 또는 capstone	바이너리 디스어셈블링 (capstone 이용 추천)
StateTracker	가상 레지스터 / 메모리 상태 추적 (선택)

## capstone 설치 (디스어셈블러)
bash
복사
편집
pip install capstone
## 기본 예제 코드 (간단한 분석기)
python
복사
편집
from capstone import *
from capstone.x86 import *
import struct

class VMAnalyzer:
    def __init__(self, code_bytes, base_addr):
        self.code = code_bytes
        self.base = base_addr
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True

    def disasm_at(self, addr, size=0x40):
        offset = addr - self.base
        return list(self.md.disasm(self.code[offset:offset + size], addr))

    def trace_tailcalls(self, entry_addr):
        visited = set()
        to_visit = [entry_addr]

        while to_visit:
            addr = to_visit.pop()
            if addr in visited:
                continue
            visited.add(addr)

            insns = self.disasm_at(addr)
            for ins in insns:
                print(f"0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}")
                # tail-call 인 경우
                if ins.mnemonic == "jmp":
                    if ins.operands[0].type == X86_OP_IMM:
                        target = ins.operands[0].imm
                        print(f"\n[+] Tail call to: 0x{target:x}\n")
                        to_visit.append(target)
                        break  # tail call 이후 더 없음
                elif ins.mnemonic == "ret":
                    break

## 사용법
python
복사
편집
with open("target.bin", "rb") as f:
    code = f.read()

BASE_ADDR = 0x7FF614D00000  # 바이너리 로드 주소
ENTRY_ADDR = 0x7FF614D04340 # tail-call 시작 주소

analyzer = VMAnalyzer(code, BASE_ADDR)
analyzer.trace_tailcalls(ENTRY_ADDR)

시작 주소가 jmp [rax]인 디스패처라면, rax의 값을 추적해 jmp 흐름을 따라갑니다.

각 jmp, call, mov, xor 등의 명령어들을 계속 따라가며,

"이 VM 명령어는 무엇을 하는가?"를 연산 흐름으로 복원합니다.

## 확장 아이디어
레지스터 추적기 추가 (StateTracker)

operand 추적: mov rax, [rbp+0x33] → rbp 값을 알아야 의미가 생김

흐름 시각화 (Graphviz)

자동 signature 생성 (hash of handler sequence)

당신이 분석 중인 바이너리의 전체 흐름 or 메모리 덤프 등을 기반으로 도구를 좀 더 구체화 필요
handler가 몇 바이트 단위인지, opcode 구조가 정형화돼 있는지 등 확인필요