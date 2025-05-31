from capstone import Cs, CS_ARCH_X86, CS_MODE_64, x86_const

# ============================================================================
# 메모리 및 레지스터 관리 클래스
# ============================================================================
class VMState:
    """VM의 레지스터와 메모리 상태를 관리합니다."""
    
    def __init__(self):
        self.registers = {
            'rax': 0, 'rbx': 0, 'rcx': 0, 'rdx': 0,
            'rsi': 0, 'rdi': 0, 'rbp': 0x7fff12340000,
            'rsp': 0x7fff12340000, 'r8': 0, 'r9': 0, 'r10': 0,
            'r11': 0, 'r12': 0, 'r13': 0, 'r14': 0, 'r15': 0
        }
        self.memory = {}
        self.use_real_values = False

    def set_real_memory_values(self, memory_values: dict):
        """실제 메모리 값들을 설정합니다."""
        self.memory.update(memory_values)
        self.use_real_values = True
        print(f"[*] 실제 메모리 값 {len(memory_values)}개 설정됨:")
        for addr, val in memory_values.items():
            print(f"    [0x{addr:x}] = 0x{val:x}")

    def set_real_registers(self, register_values: dict):
        """실제 레지스터 값들을 설정합니다."""
        self.registers.update(register_values)
        print(f"[*] 실제 레지스터 값 {len(register_values)}개 설정됨:")
        for reg, val in register_values.items():
            print(f"    {reg} = 0x{val:x}")

    def get_register(self, reg_name: str) -> int:
        """레지스터 값을 가져옵니다."""
        return self.registers.get(reg_name, 0)

    def set_register(self, reg_name: str, value: int):
        """레지스터 값을 설정합니다."""
        self.registers[reg_name] = value

    def get_memory(self, address: int) -> int:
        """메모리 값을 가져옵니다."""
        if address in self.memory:
            return self.memory[address]
        else:
            # 추정값 계산
            initial_value = self._estimate_memory_value(address)
            self.memory[address] = initial_value
            return initial_value

    def set_memory(self, address: int, value: int):
        """메모리 값을 설정합니다."""
        self.memory[address] = value

    def _estimate_memory_value(self, address: int) -> int:
        """VM 초기 메모리 상태 추정"""
        if self.use_real_values:
            return 0x0
        
        rbp = self.registers['rbp']
        offset = address - rbp
        
        # VM 구조에 따른 추정값
        if offset == 0xf8: return 0x2
        elif offset == 0x33: return 0x1000
        elif offset == 0x61: return 0x5
        elif offset == 0x170: return 0x8
        elif offset == 0x7d: return 0xa
        else: return 0x0

    def print_registers(self):
        """레지스터 상태를 출력합니다."""
        important_regs = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 
                         'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
        changed = {reg: val for reg in important_regs 
                  if (val := self.registers.get(reg, 0)) != 0}
        
        if changed:
            reg_str = ', '.join([f'{k}=0x{v:x}' for k, v in changed.items()])
            print(f"        레지스터: {reg_str}")


# ============================================================================
# 디스어셈블리 및 기본 분석 클래스  
# ============================================================================
class DisassemblyEngine:
    """코드 디스어셈블리를 담당합니다."""
    
    def __init__(self, code_bytes: bytes, base_address: int):
        self.code_bytes = code_bytes
        self.base_address = base_address
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True

    def get_code_slice(self, address: int, size: int) -> bytes:
        """코드 바이트 슬라이스를 반환합니다."""
        offset = address - self.base_address
        if offset < 0 or offset >= len(self.code_bytes):
            print(f"[!] 오류: 주소 0x{address:x}가 범위를 벗어났습니다.")
            return b''
        
        actual_size = min(size, len(self.code_bytes) - offset)
        return self.code_bytes[offset : offset + actual_size]

    def disassemble_at(self, address: int, size: int = 0x40) -> list:
        """해당 주소에서 디스어셈블합니다."""
        code_slice = self.get_code_slice(address, size)
        if not code_slice:
            return []
        return list(self.md.disasm(code_slice, address))

    def is_address_valid(self, address: int) -> bool:
        """주소가 유효한지 확인합니다."""
        offset = address - self.base_address
        return 0 <= offset < len(self.code_bytes)


# ============================================================================
# Tail-Call 추적기
# ============================================================================
class TailCallTracker:
    """Tail-call 체인을 추적합니다."""
    
    def __init__(self, disasm_engine: DisassemblyEngine):
        self.disasm = disasm_engine

    def trace(self, entry_address: int, max_instructions_per_block: int = 50, max_revisits: int = 3):
        """Tail-call 추적을 실행합니다."""
        visited_addresses = {}
        addresses_to_visit = [entry_address]
        tail_call_count = 0

        print(f"[*] 0x{entry_address:x}에서 tail-call 추적을 시작합니다\n")

        while addresses_to_visit:
            current_address = addresses_to_visit.pop(0)
            
            # 방문 횟수 체크
            visit_count = visited_addresses.get(current_address, 0)
            if visit_count >= max_revisits:
                print(f"[!] 0x{current_address:x} 최대 재방문 횟수 도달. 건너뜁니다.")
                continue
            
            visited_addresses[current_address] = visit_count + 1
            
            if visit_count > 0:
                print(f"[-] 재방문: 0x{current_address:x} (방문 횟수: {visit_count + 1})")
            
            print(f"--- 0x{current_address:x}에서 블록 추적 중 ---")
            
            # 블록 내 명령어 처리
            instructions = self.disasm.disassemble_at(current_address, 
                                                    size=max_instructions_per_block * 8)
            if not instructions:
                print(f"[!] 0x{current_address:x}에서 명령어를 찾을 수 없습니다.")
                continue

            instruction_count = 0
            for insn in instructions:
                print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
                instruction_count += 1

                if insn.mnemonic == "jmp":
                    if insn.operands and insn.operands[0].type == x86_const.X86_OP_IMM:
                        # 직접 점프
                        target_address = insn.operands[0].imm
                        tail_call_count += 1
                        print(f"\n[+] Tail call #{tail_call_count} → 0x{target_address:x}\n")
                        
                        target_visit_count = visited_addresses.get(target_address, 0)
                        if target_visit_count < max_revisits:
                            addresses_to_visit.append(target_address)
                        break
                    else:
                        # 간접 점프
                        print(f"[!] 0x{insn.address:x}에서 간접 점프: {insn.mnemonic} {insn.op_str}. 추적 중단.")
                        break
                elif insn.mnemonic == "ret":
                    print(f"\n[-] 0x{insn.address:x}에서 반환. 추적 중단.\n")
                    break
                
                if instruction_count >= max_instructions_per_block:
                    print(f"[!] 최대 명령어 수({max_instructions_per_block})에 도달. 추적 중단.")
                    break


# ============================================================================
# 패턴 분석기
# ============================================================================
class PatternAnalyzer:
    """VM 패턴을 분석합니다."""
    
    def __init__(self, disasm_engine: DisassemblyEngine):
        self.disasm = disasm_engine

    def analyze(self, entry_address: int, max_chains: int = 10):
        """VM 패턴 분석을 실행합니다."""
        print(f"[*] VM 패턴 분석을 시작합니다 (시작 주소: 0x{entry_address:x})")
        print(f"[*] 파일 범위: 0x{self.disasm.base_address:x} ~ 0x{self.disasm.base_address + len(self.disasm.code_bytes):x}")
        print("=" * 60)
        
        # 디스패처 테이블 감지
        dispatcher_targets = self._detect_dispatcher_table(entry_address)
        
        if dispatcher_targets:
            self._analyze_dispatcher_handlers(dispatcher_targets, max_chains)
        else:
            self._analyze_single_chain(entry_address, max_chains)

    def _detect_dispatcher_table(self, address: int) -> list:
        """VM 디스패처 테이블을 감지합니다."""
        instructions = self.disasm.disassemble_at(address, size=0x100)
        jump_targets = []
        
        consecutive_jumps = 0
        for insn in instructions:
            if (insn.mnemonic == 'jmp' and insn.operands and 
                insn.operands[0].type == x86_const.X86_OP_IMM):
                target_addr = insn.operands[0].imm
                jump_targets.append(target_addr)
                consecutive_jumps += 1
                print(f"[디버그] 점프 #{consecutive_jumps}: 0x{insn.address:x} -> 0x{target_addr:x}")
            else:
                break
                
        if consecutive_jumps >= 3:
            print(f"[감지] {consecutive_jumps}개의 연속된 점프 발견 → VM 디스패처 테이블")
            return jump_targets
        else:
            return []

    def _analyze_dispatcher_handlers(self, dispatcher_targets: list, max_chains: int):
        """디스패처 핸들러들을 분석합니다."""
        valid_handlers = []
        invalid_handlers = []
        
        for target_addr in dispatcher_targets:
            if self.disasm.is_address_valid(target_addr):
                valid_handlers.append(target_addr)
            else:
                invalid_handlers.append(target_addr)
        
        print(f"[*] VM 디스패처 테이블 감지! 총 {len(dispatcher_targets)}개 핸들러 발견")
        print(f"[*] 유효한 핸들러: {len(valid_handlers)}개, 무효한 핸들러: {len(invalid_handlers)}개")
        
        if invalid_handlers:
            print(f"[주의] 범위를 벗어나는 핸들러 주소들:")
            for addr in invalid_handlers:
                offset = addr - self.disasm.base_address
                print(f"  - 0x{addr:x} (오프셋: 0x{offset:x})")
        
        print("-" * 60)
        
        # 유효한 핸들러 분석
        for i, target_addr in enumerate(valid_handlers[:max_chains]):
            print(f"\n[핸들러 #{i}] 주소: 0x{target_addr:x}")
            print("-" * 40)
            vm_operation = self._analyze_single_handler(target_addr)
            print(f"[결과] VM_OPCODE_{i}: {vm_operation}")
            
        print(f"\n[완료] 총 {len(valid_handlers)}개의 유효한 VM 핸들러를 분석했습니다.")

    def _analyze_single_handler(self, start_address: int) -> str:
        """단일 핸들러를 분석합니다."""
        operations = []
        memory_accesses = []
        arithmetic_ops = []
        
        instructions = self.disasm.disassemble_at(start_address, size=0x200)
        print(f"[디버그] 0x{start_address:x}에서 {len(instructions)}개 명령어 발견")
        
        for i, insn in enumerate(instructions[:50]):
            print(f"  {i+1:2d}. 0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
            
            # 패턴 감지
            if any(keyword in insn.op_str for keyword in ['qword ptr', 'dword ptr', 'word ptr', 'byte ptr']):
                memory_accesses.append(f"{insn.mnemonic} {insn.op_str}")
                print(f"      → 메모리 접근 감지")
            
            if insn.mnemonic in ['mov', 'movzx', 'movsx', 'push', 'pop']:
                operations.append(f"데이터이동: {insn.mnemonic} {insn.op_str}")
                print(f"      → 데이터 이동 감지")
            
            if insn.mnemonic in ['add', 'sub', 'mul', 'div', 'xor', 'and', 'or', 'shl', 'shr']:
                arithmetic_ops.append(f"{insn.mnemonic} {insn.op_str}")
                print(f"      → 산술 연산 감지")
            
            if insn.mnemonic in ['cmp', 'test']:
                operations.append(f"조건비교: {insn.op_str}")
                print(f"      → 조건 비교 감지")
            
            if insn.mnemonic in ['call', 'ret', 'jmp', 'je', 'jne', 'jz', 'jnz']:
                operations.append(f"제어흐름: {insn.mnemonic} {insn.op_str}")
                print(f"      → 제어 흐름 감지")
            
            if insn.mnemonic == 'jmp' and 'r' in insn.op_str and '[' not in insn.op_str:
                print(f"      → 간접 점프 감지: {insn.op_str}")
                break
                
            if i >= 9:
                print(f"  ... (총 {len(instructions)}개 중 처음 10개만 표시)")
                break
        
        # 결과 생성
        result_parts = []
        if memory_accesses:
            result_parts.append(f"메모리접근({len(memory_accesses)}개)")
        if arithmetic_ops:
            result_parts.append(f"산술연산({len(arithmetic_ops)}개)")
        if any("조건비교" in op for op in operations):
            result_parts.append("조건분기")
        if any("데이터이동" in op for op in operations):
            result_parts.append(f"데이터이동({len([op for op in operations if '데이터이동' in op])}개)")
        if any("제어흐름" in op for op in operations):
            result_parts.append(f"제어흐름({len([op for op in operations if '제어흐름' in op])}개)")
        
        return " + ".join(result_parts) if result_parts else "미분류_연산"

    def _analyze_single_chain(self, entry_address: int, max_chains: int):
        """단일 체인 분석 (디스패처가 없는 경우)"""
        print("단일 체인 분석은 아직 구현되지 않았습니다.")


# ... 다음 부분에서 계속
