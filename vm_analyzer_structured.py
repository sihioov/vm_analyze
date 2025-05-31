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
        self.memory = {}  # {address: (value, is_estimated)}
        self.use_real_values = False

    def set_real_memory_values(self, memory_values: dict):
        """실제 메모리 값들을 설정합니다."""
        for addr, val in memory_values.items():
            self.memory[addr] = (val, False)  # 실제값으로 저장
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
        return self.registers.get(reg_name, 0)

    def set_register(self, reg_name: str, value: int):
        self.registers[reg_name] = value

    def get_memory(self, address: int) -> tuple[int, bool]:
        """메모리 값을 가져옵니다. (값, 추정값여부) 반환"""
        if address in self.memory:
            value, is_estimated = self.memory[address]
            return value, is_estimated
        else:
            initial_value = self._estimate_memory_value(address)
            self.memory[address] = (initial_value, True)  # 추정값으로 저장
            return initial_value, True

    def set_memory(self, address: int, value: int):
        """메모리 값을 설정합니다. (항상 실제값으로 처리)"""
        self.memory[address] = (value, False)  # 새로 설정된 값은 실제값

    def _estimate_memory_value(self, address: int) -> int:
        """VM 초기 메모리 상태 추정"""
        if self.use_real_values:
            return 0x0
        
        rbp = self.registers['rbp']
        offset = address - rbp
        
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
# 디스어셈블리 엔진
# ============================================================================
class DisassemblyEngine:
    """코드 디스어셈블리를 담당합니다."""
    
    def __init__(self, code_bytes: bytes, base_address: int):
        self.code_bytes = code_bytes
        self.base_address = base_address
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True

    def get_code_slice(self, address: int, size: int) -> bytes:
        offset = address - self.base_address
        if offset < 0 or offset >= len(self.code_bytes):
            print(f"[!] 오류: 주소 0x{address:x}가 범위를 벗어났습니다.")
            return b''
        
        actual_size = min(size, len(self.code_bytes) - offset)
        return self.code_bytes[offset : offset + actual_size]

    def disassemble_at(self, address: int, size: int = 0x40) -> list:
        code_slice = self.get_code_slice(address, size)
        if not code_slice:
            return []
        return list(self.md.disasm(code_slice, address))

    def is_address_valid(self, address: int) -> bool:
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
        visited_addresses = {}
        addresses_to_visit = [entry_address]
        tail_call_count = 0

        print(f"[*] 0x{entry_address:x}에서 tail-call 추적을 시작합니다\n")

        while addresses_to_visit:
            current_address = addresses_to_visit.pop(0)
            
            visit_count = visited_addresses.get(current_address, 0)
            if visit_count >= max_revisits:
                print(f"[!] 0x{current_address:x} 최대 재방문 횟수 도달. 건너뜁니다.")
                continue
            
            visited_addresses[current_address] = visit_count + 1
            
            if visit_count > 0:
                print(f"[-] 재방문: 0x{current_address:x} (방문 횟수: {visit_count + 1})")
            
            print(f"--- 0x{current_address:x}에서 블록 추적 중 ---")
            
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
                        target_address = insn.operands[0].imm
                        tail_call_count += 1
                        print(f"\n[+] Tail call #{tail_call_count} → 0x{target_address:x}\n")
                        
                        target_visit_count = visited_addresses.get(target_address, 0)
                        if target_visit_count < max_revisits:
                            addresses_to_visit.append(target_address)
                        break
                    else:
                        print(f"[*] 간접 점프: {insn.mnemonic} {insn.op_str}. 추적 계속 진행.")
                        # 간접 점프에서도 추적을 계속 진행
                elif insn.mnemonic == "ret":
                    print(f"\n[-] 반환. 추적 중단.\n")
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
        print(f"[*] VM 패턴 분석 시작 (주소: 0x{entry_address:x})")
        print("=" * 60)
        
        dispatcher_targets = self._detect_dispatcher_table(entry_address)
        
        if dispatcher_targets:
            self._analyze_dispatcher_handlers(dispatcher_targets, max_chains)
        else:
            print("디스패처 테이블을 찾을 수 없습니다.")

    def _detect_dispatcher_table(self, address: int) -> list:
        instructions = self.disasm.disassemble_at(address, size=0x100)
        jump_targets = []
        consecutive_jumps = 0
        
        for insn in instructions:
            if (insn.mnemonic == 'jmp' and insn.operands and 
                insn.operands[0].type == x86_const.X86_OP_IMM):
                target_addr = insn.operands[0].imm
                jump_targets.append(target_addr)
                consecutive_jumps += 1
            else:
                break
                
        if consecutive_jumps >= 3:
            print(f"[감지] {consecutive_jumps}개의 연속 점프 → VM 디스패처")
            return jump_targets
        return []

    def _analyze_dispatcher_handlers(self, dispatcher_targets: list, max_chains: int):
        valid_handlers = [addr for addr in dispatcher_targets 
                         if self.disasm.is_address_valid(addr)]
        
        print(f"[*] 총 {len(dispatcher_targets)}개 핸들러 중 {len(valid_handlers)}개 유효")
        print("-" * 40)
        
        for i, target_addr in enumerate(valid_handlers[:max_chains]):
            print(f"\n[핸들러 #{i}] 0x{target_addr:x}")
            result = self._analyze_single_handler(target_addr)
            print(f"[결과] {result}")
            
        print(f"\n[완료] {len(valid_handlers)}개 핸들러 분석 완료")

    def _analyze_single_handler(self, start_address: int) -> str:
        instructions = self.disasm.disassemble_at(start_address, size=0x200)
        
        memory_count = 0
        arithmetic_count = 0
        data_move_count = 0
        
        for i, insn in enumerate(instructions[:20]):
            if any(kw in insn.op_str for kw in ['ptr [']):
                memory_count += 1
            if insn.mnemonic in ['add', 'sub', 'mul', 'div', 'xor', 'and', 'or']:
                arithmetic_count += 1
            if insn.mnemonic in ['mov', 'movzx', 'movsx']:
                data_move_count += 1
        
        parts = []
        if memory_count > 0: parts.append(f"메모리({memory_count})")
        if arithmetic_count > 0: parts.append(f"산술({arithmetic_count})")
        if data_move_count > 0: parts.append(f"이동({data_move_count})")
        
        return " + ".join(parts) if parts else "미분류"


# ============================================================================
# 실행 시뮬레이터
# ============================================================================
class ExecutionSimulator:
    """명령어 실행을 시뮬레이션합니다."""
    
    def __init__(self, disasm_engine: DisassemblyEngine, vm_state: VMState):
        self.disasm = disasm_engine
        self.vm_state = vm_state

    def simulate(self, entry_address: int, max_instructions: int = 200):
        print(f"[*] 실행 시뮬레이션 시작: 0x{entry_address:x}")
        print("=" * 60)
        
        current_address = entry_address
        instruction_count = 0
        
        while instruction_count < max_instructions:
            instructions = self.disasm.disassemble_at(current_address, size=0x20)
            if not instructions:
                print(f"[!] 명령어를 찾을 수 없습니다: 0x{current_address:x}")
                break
                
            insn = instructions[0]
            instruction_count += 1
            
            print(f"{instruction_count:3d}. 0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
            
            next_address = self._simulate_instruction(insn)
            self.vm_state.print_registers()
            
            if next_address:
                if next_address != insn.address + insn.size:
                    print(f"        🔄 점프: 0x{insn.address:x} → 0x{next_address:x}")
                current_address = next_address
            else:
                current_address = insn.address + insn.size
                
            # 간접 점프 감지 개선
            if insn.mnemonic == 'jmp':
                # 직접 점프가 아닌 경우 (레지스터나 메모리 참조)
                if not insn.op_str.startswith('0x'):
                    print(f"🔴 [간접 점프 감지] {insn.op_str}")
                    # 시뮬레이션을 종료하지 않고 계속 진행
                    print(f"[*] 간접 점프 계속 진행: {insn.op_str}")
                
            print("-" * 40)
        
        print(f"\n[*] 시뮬레이션 완료 - 총 {instruction_count}개 명령어 실행")

    def _simulate_instruction(self, insn):
        """개별 명령어 시뮬레이션"""
        mnemonic = insn.mnemonic
        op_str = insn.op_str
        
        if mnemonic == 'mov':
            return self._simulate_mov(op_str)
        elif mnemonic == 'movzx':
            return self._simulate_movzx(op_str)
        elif mnemonic == 'add':
            return self._simulate_add(op_str)
        elif mnemonic == 'sub':
            return self._simulate_sub(op_str)
        elif mnemonic == 'xor':
            return self._simulate_xor(op_str)
        elif mnemonic == 'and':
            return self._simulate_and(op_str)
        elif mnemonic == 'or':
            return self._simulate_or(op_str)
        elif mnemonic == 'shl':
            return self._simulate_shl(op_str)
        elif mnemonic == 'shr':
            return self._simulate_shr(op_str)
        elif mnemonic == 'cmp':
            return self._simulate_cmp(op_str)
        elif mnemonic == 'jmp':
            return self._simulate_jmp(op_str)
        else:
            print(f"        → 지원하지 않는 명령어: {mnemonic}")
            return None

    def _simulate_mov(self, op_str: str):
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        src_val = self._get_operand_value(src)
        self._set_operand_value(dst, src_val)
        
        print(f"        → {dst} = 0x{src_val:x}")
        return None

    def _simulate_movzx(self, op_str: str):
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        src_val = self._get_operand_value(src)
        self._set_operand_value(dst, src_val)
        
        print(f"        → {dst} = 0x{src_val:x}")
        return None

    def _simulate_add(self, op_str: str):
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        dst_val = self._get_operand_value(dst)
        src_val = self._get_operand_value(src)
        result = (dst_val + src_val) & 0xFFFFFFFFFFFFFFFF
        
        self._set_operand_value(dst, result)
        print(f"        → {dst} = 0x{dst_val:x} + 0x{src_val:x} = 0x{result:x}")
        return None

    def _simulate_sub(self, op_str: str):
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        dst_val = self._get_operand_value(dst)
        src_val = self._get_operand_value(src)
        result = (dst_val - src_val) & 0xFFFFFFFFFFFFFFFF
        
        self._set_operand_value(dst, result)
        print(f"        → {dst} = 0x{dst_val:x} - 0x{src_val:x} = 0x{result:x}")
        return None

    def _simulate_xor(self, op_str: str):
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        dst_val = self._get_operand_value(dst)
        src_val = self._get_operand_value(src)
        result = (dst_val ^ src_val) & 0xFFFFFFFFFFFFFFFF
        
        self._set_operand_value(dst, result)
        print(f"        → {dst} = 0x{dst_val:x} ^ 0x{src_val:x} = 0x{result:x}")
        return None

    def _simulate_and(self, op_str: str):
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        dst_val = self._get_operand_value(dst)
        src_val = self._get_operand_value(src)
        result = (dst_val & src_val) & 0xFFFFFFFFFFFFFFFF
        
        self._set_operand_value(dst, result)
        print(f"        → {dst} = 0x{dst_val:x} & 0x{src_val:x} = 0x{result:x}")
        return None

    def _simulate_or(self, op_str: str):
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        dst_val = self._get_operand_value(dst)
        src_val = self._get_operand_value(src)
        result = (dst_val | src_val) & 0xFFFFFFFFFFFFFFFF
        
        self._set_operand_value(dst, result)
        print(f"        → {dst} = 0x{dst_val:x} | 0x{src_val:x} = 0x{result:x}")
        return None

    def _simulate_shl(self, op_str: str):
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        dst_val = self._get_operand_value(dst)
        src_val = self._get_operand_value(src)
        result = (dst_val << src_val) & 0xFFFFFFFFFFFFFFFF
        
        self._set_operand_value(dst, result)
        print(f"        → {dst} = 0x{dst_val:x} << 0x{src_val:x} = 0x{result:x}")
        return None

    def _simulate_shr(self, op_str: str):
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        dst_val = self._get_operand_value(dst)
        src_val = self._get_operand_value(src)
        result = (dst_val >> src_val) & 0xFFFFFFFFFFFFFFFF
        
        self._set_operand_value(dst, result)
        print(f"        → {dst} = 0x{dst_val:x} >> 0x{src_val:x} = 0x{result:x}")
        return None

    def _simulate_cmp(self, op_str: str):
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        dst_val = self._get_operand_value(dst)
        src_val = self._get_operand_value(src)
        result = (dst_val - src_val) & 0xFFFFFFFFFFFFFFFF
        
        print(f"        → {dst} - {src} = 0x{result:x}")
        return None

    def _simulate_jmp(self, op_str: str):
        if op_str.startswith('0x'):
            target = int(op_str, 16)
            print(f"        → 점프: 0x{target:x}")
            return target
        elif op_str in self.vm_state.registers:
            target = self.vm_state.get_register(op_str)
            print(f"        → 간접 점프: {op_str} (0x{target:x})")
            return target
        return None

    def _get_operand_value(self, operand: str) -> int:
        operand = operand.strip()
        
        if operand.startswith('0x'):
            return int(operand, 16)
        elif operand.isdigit():
            return int(operand)
        elif operand in self.vm_state.registers:
            return self.vm_state.get_register(operand)
        elif self._is_32bit_register(operand):
            # 32비트 레지스터를 64비트로 변환
            reg_64 = self._map_32bit_to_64bit(operand)
            return self.vm_state.get_register(reg_64) & 0xFFFFFFFF
        elif 'ptr [' in operand:
            # 메모리 참조 파싱 (예: "qword ptr [rax]", "dword ptr [rbp + 0xf8]")
            address = self._parse_memory_reference(operand)
            if address is not None:
                value, is_estimated = self.vm_state.get_memory(address)
                if is_estimated:
                    print(f"        🔮 [추정값] 0x{address:x} = 0x{value:x} ← 실제값 확인 필요!")
                    #print(f"           💡 하드코딩 예시: memory_values[0x{address:x}] = 0x실제값")
                else:
                    print(f"        [메모리] 0x{address:x} = 0x{value:x} (설정값)")
                return value
            return 0
        else:
            return 0

    def _set_operand_value(self, operand: str, value: int):
        operand = operand.strip()
        if operand in self.vm_state.registers:
            self.vm_state.set_register(operand, value)
        elif self._is_32bit_register(operand):
            # 32비트 레지스터의 경우 상위 32비트는 0으로 클리어
            reg_64 = self._map_32bit_to_64bit(operand)
            self.vm_state.set_register(reg_64, value & 0xFFFFFFFF)
        elif 'ptr [' in operand:
            # 메모리 참조 파싱
            address = self._parse_memory_reference(operand)
            if address is not None:
                self.vm_state.set_memory(address, value)
                print(f"        [메모리] 0x{address:x} ← 0x{value:x} (저장)")

    def _is_32bit_register(self, operand: str) -> bool:
        """32비트 레지스터인지 확인"""
        return operand in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp',
                          'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']

    def _map_32bit_to_64bit(self, reg_32: str) -> str:
        """32비트 레지스터를 64비트로 매핑"""
        mapping = {
            'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
            'esi': 'rsi', 'edi': 'rdi', 'esp': 'rsp', 'ebp': 'rbp',
            'r8d': 'r8', 'r9d': 'r9', 'r10d': 'r10', 'r11d': 'r11',
            'r12d': 'r12', 'r13d': 'r13', 'r14d': 'r14', 'r15d': 'r15'
        }
        return mapping.get(reg_32, reg_32)

    def _parse_memory_reference(self, operand: str) -> int:
        """메모리 참조를 파싱하여 주소를 계산합니다."""
        try:
            # "qword ptr [rax]" → "rax"
            # "dword ptr [rbp + 0xf8]" → "rbp + 0xf8"
            start = operand.find('[') + 1
            end = operand.find(']')
            expr = operand[start:end].strip()
            
            if '+' in expr:
                parts = expr.split('+')
                reg_name = parts[0].strip()
                offset_str = parts[1].strip()
                
                base_addr = self.vm_state.get_register(reg_name)
                if offset_str.startswith('0x'):
                    offset = int(offset_str, 16)
                else:
                    offset = int(offset_str)
                    
                return base_addr + offset
            else:
                # 단순 레지스터 참조
                reg_name = expr.strip()
                return self.vm_state.get_register(reg_name)
                
        except (ValueError, IndexError):
            print(f"        [!] 메모리 참조 파싱 실패: {operand}")
            return None


# ============================================================================
# 메인 VM 분석기
# ============================================================================
class VMAnalyzer:
    """통합 VM 분석기"""
    
    def __init__(self, code_bytes: bytes, base_address: int):
        self.disasm = DisassemblyEngine(code_bytes, base_address)
        self.vm_state = VMState()
        self.tail_tracker = TailCallTracker(self.disasm)
        self.pattern_analyzer = PatternAnalyzer(self.disasm)
        self.simulator = ExecutionSimulator(self.disasm, self.vm_state)

    def set_real_memory_values(self, memory_values: dict):
        self.vm_state.set_real_memory_values(memory_values)

    def set_real_registers(self, register_values: dict):
        self.vm_state.set_real_registers(register_values)

    def trace_tail_calls(self, entry_address: int, max_instructions_per_block: int = 50, max_revisits: int = 3):
        self.tail_tracker.trace(entry_address, max_instructions_per_block, max_revisits)

    def analyze_vm_patterns(self, entry_address: int, max_chains: int = 10):
        self.pattern_analyzer.analyze(entry_address, max_chains)

    def simulate_execution(self, entry_address: int, max_instructions: int = 200):
        self.simulator.simulate(entry_address, max_instructions)


# ============================================================================
# 메인 실행부
# ============================================================================
def get_user_choice():
    """사용자 입력을 받아 분석 모드를 선택합니다."""
    print("[*] 분석 모드를 선택하세요:")
    print("1. 상세 tail-call 추적")
    print("2. 고수준 VM 패턴 분석") 
    print("3. 실행 시뮬레이션")
    
    try:
        mode = input("모드 선택 (1/2/3): ").strip()
        if mode not in ['1', '2', '3']:
            print("잘못된 입력. 기본값 1번 사용.")
            return '1'
        return mode
    except:
        print("입력 오류. 기본값 1번 사용.")
        return '1'

def get_trace_settings():
    """Tail-call 추적 설정을 받습니다."""
    try:
        max_block = input("블록당 최대 명령어 수 (기본값 50): ").strip()
        max_block = int(max_block) if max_block else 50
        
        max_revisits = input("재방문 허용 횟수 (기본값 3): ").strip()
        max_revisits = int(max_revisits) if max_revisits else 3
        
        return max_block, max_revisits
    except:
        return 50, 3

def get_simulation_settings():
    """시뮬레이션 설정을 받습니다."""
    try:
        max_insns = input("최대 명령어 개수 (기본값 200): ").strip()
        return int(max_insns) if max_insns else 200
    except:
        return 200

if __name__ == "__main__":
    # 설정
    binary_file_path = "L2.bin"
    BASE_ADDRESS = 0x7ff64dbcf6f4
    ENTRY_ADDRESS = 0x7ff64dbfc67a
    
    # 바이너리 로드
    try:
        with open(binary_file_path, "rb") as f:
            code = f.read()
        print(f"[*] {binary_file_path}에서 {len(code)} 바이트 로드 성공\n")
    except FileNotFoundError:
        print(f"[!] 파일을 찾을 수 없습니다: {binary_file_path}")
        exit(1)

    # 분석기 초기화
    analyzer = VMAnalyzer(code, BASE_ADDRESS)
    
    # 실제 메모리 값 설정 (Binary Ninja나 디버거에서 확인한 값들)
    # 추정값이 나오면 아래에 실제값을 추가하세요
    memory_values = {
        # 예시: 0x7fff123400f8: 0x실제값,
        # 예시: 0x7fff12340170: 0x실제값,
    }
    if memory_values:
        analyzer.set_real_memory_values(memory_values)
    
    # 실제 레지스터 값 설정 (필요시)
    register_values = {
        # 예시: 'r13': 0x실제값,
    }
    if register_values:
        analyzer.set_real_registers(register_values)
    
    # 사용자 선택
    analysis_mode = get_user_choice()
    
    # 분석 실행
    if analysis_mode == "1":
        print("\n[*] 상세 tail-call 추적을 시작합니다...")
        max_block, max_revisits = get_trace_settings()
        print(f"[*] 설정: 블록당 {max_block}개, 재방문 {max_revisits}회")
        analyzer.trace_tail_calls(ENTRY_ADDRESS, max_block, max_revisits)
        
    elif analysis_mode == "2":
        print("\n[*] 고수준 VM 패턴 분석을 시작합니다...")
        analyzer.analyze_vm_patterns(ENTRY_ADDRESS, max_chains=5)
        
    elif analysis_mode == "3":
        print("\n[*] 실행 시뮬레이션을 시작합니다...")
        max_insns = get_simulation_settings()
        print(f"[*] 설정: 최대 {max_insns}개 명령어")
        analyzer.simulate_execution(ENTRY_ADDRESS, max_insns)
    
    print("\n[*] 분석이 완료되었습니다.") 