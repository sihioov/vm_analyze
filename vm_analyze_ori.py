from capstone import Cs, CS_ARCH_X86, CS_MODE_64, x86_const

class VMAnalyzer:
    """
    tail-call 기반 실행 흐름을 추적하여 VM 바이트코드를 분석합니다.
    """
    def __init__(self, code_bytes: bytes, base_address: int):
        """
        Initialize VMAnalyzer

        Args:
            code_bytes: 분석할 코드의 원시 바이트
            base_address: 코드가 메모리에 로드되는 기본 주소
        """
        self.code_bytes = code_bytes
        self.base_address = base_address
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True  # 상세한 명령어 정보 활성화
        
        # 가상 레지스터 상태 추가
        self.registers = {
            'rax': 0, 'rbx': 0, 'rcx': 0, 'rdx': 0,
            'rsi': 0, 'rdi': 0, 'rbp': 0x7fff12340000,  # 스택 기본값
            'rsp': 0x7fff12340000, 'r8': 0, 'r9': 0, 'r10': 0,
            'r11': 0, 'r12': 0, 'r13': 0, 'r14': 0, 'r15': 0
        }
        self.memory = {}  # 가상 메모리 (간단한 dict)

    def _get_code_slice(self, address: int, size: int) -> bytes | None:
        """
        코드 바이트 슬라이스
        Out of bound = return None;
        """
        offset = address - self.base_address
        if offset < 0 or offset >= len(self.code_bytes):
            print(f"[!] 오류: 주소 0x{address:x}가 범위를 벗어났습니다.")
            return None
        
        end_offset = offset + size
        # code_bytes의 끝을 넘지 않도록 보장
        actual_size = min(size, len(self.code_bytes) - offset)
        return self.code_bytes[offset : offset + actual_size]

    def disassemble_at(self, address: int, size: int = 0x40) -> list:
        """
        해당 메모리 디스어셈블

        Args:
            address: 디스어셈블 시작할 가상 주소
            size: 디스어셈블할 바이트 수

        Returns:
            capstone 명령어 객체의 리스트
        """
        code_slice = self._get_code_slice(address, size)
        if not code_slice:
            return []
            
        return list(self.md.disasm(code_slice, address))

    def trace_tail_calls(self, entry_address: int, max_instructions_per_block: int = 50, max_revisits: int = 3):
        """
        tail-call 추적

        Args:
            entry_address: 시작 가상 주소
            max_instructions_per_block: 점프 전까지 블록에서 처리할 최대 명령어 수
            max_revisits: 같은 주소를 재방문할 수 있는 최대 횟수
        """
        visited_addresses = {}  # 주소 -> 방문 횟수
        addresses_to_visit = [entry_address]
        instruction_count_in_block = 0
        tail_call_count = 0  # tail-call 카운터 초기화

        print(f"[*] 0x{entry_address:x}에서 tail-call 추적을 시작합니다\n")

        while addresses_to_visit:
            current_address = addresses_to_visit.pop(0) # 너비 우선 탐색과 유사한 FIFO

            # 방문 횟수 체크
            visit_count = visited_addresses.get(current_address, 0)
            if visit_count > 0:
                print(f"[-] 이미 방문한 주소를 재방문: 0x{current_address:x} (방문 횟수: {visit_count + 1})")
                if visit_count >= max_revisits:
                    print(f"[!] 0x{current_address:x} 최대 재방문 횟수({max_revisits})에 도달. 무한루프 방지를 위해 건너뜁니다.")
                    continue
            
            # 방문 횟수 증가
            visited_addresses[current_address] = visit_count + 1
            
            print(f"--- 0x{current_address:x}에서 블록 추적 중 ---")
            
            # 적절한 크기의 명령어 청크를 디스어셈블합니다.
            # 여기서 크기는 일반적인 핸들러 크기에 따라 조정이 필요할 수 있습니다.
            instructions = self.disassemble_at(current_address, size=max_instructions_per_block * 8) # 명령어당 약 8바이트로 추정
            
            if not instructions:
                print(f"[!] 0x{current_address:x}에서 명령어를 찾을 수 없거나 주소가 범위를 벗어났습니다.")
                continue

            instruction_count_in_block = 0
            followed_jump_in_block = False

            for insn in instructions:
                print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
                instruction_count_in_block += 1

                if insn.mnemonic == "jmp":
                    # 피연산자가 즉시값(직접 점프)인지 확인
                    if insn.operands and insn.operands[0].type == x86_const.X86_OP_IMM:
                        target_address = insn.operands[0].imm
                        tail_call_count += 1 # tail-call 카운터 증가
                        print(f"\n[+] Tail call #{tail_call_count} → 0x{target_address:x}\n") # 카운터 표시
                        # 방문 횟수가 최대치를 넘지 않은 주소만 큐에 추가
                        target_visit_count = visited_addresses.get(target_address, 0)
                        if target_visit_count < max_revisits:
                             addresses_to_visit.append(target_address)
                        else:
                             print(f"[!] 대상 주소 0x{target_address:x}가 이미 최대 방문 횟수에 도달했으므로 큐에 추가하지 않습니다.")
                        followed_jump_in_block = True
                        break  # 현재 블록 처리 중단, 점프를 따라감
                    else:
                        # 간접 점프 (예: jmp rax, jmp [mem]) - 상태 추적 필요
                        print(f"[!] 0x{insn.address:x}에서 간접 점프: {insn.mnemonic} {insn.op_str}. 이 경로의 추적을 중단합니다.")
                        followed_jump_in_block = True # 이 간단한 추적기에서는 현재 경로의 끝으로 처리
                        break
                elif insn.mnemonic == "ret":
                    print(f"\n[-] 0x{insn.address:x}에서 반환을 만났습니다. 이 경로의 추적을 중단합니다.\n")
                    followed_jump_in_block = True
                    break
                
                if instruction_count_in_block >= max_instructions_per_block:
                    print(f"[!] 0x{current_address:x}에서 jmp/ret 없이 최대 명령어 수({max_instructions_per_block})에 도달했습니다. 이 경로의 추적을 중단합니다.")
                    followed_jump_in_block = True
                    break
            
            if not followed_jump_in_block and instructions: # jmp/ret 없이 디스어셈블된 청크의 끝에 도달
                 print(f"[!] jmp/ret 없이 0x{instructions[-1].address + instructions[-1].size:x}에서 디스어셈블된 청크가 끝났습니다. 이 경로의 추적을 중단합니다.")

    def analyze_vm_patterns(self, entry_address: int, max_chains: int = 10):
        """
        VM 패턴을 분석하여 고수준 연산을 식별합니다.
        
        Args:
            entry_address: 시작 주소
            max_chains: 분석할 최대 체인 수
        """
        print(f"[*] VM 패턴 분석을 시작합니다 (시작 주소: 0x{entry_address:x})")
        print("=" * 60)
        
        # 먼저 현재 주소가 디스패처 테이블인지 확인
        dispatcher_targets = self._detect_dispatcher_table(entry_address)
        
        if dispatcher_targets:
            print(f"[*] VM 디스패처 테이블 감지! {len(dispatcher_targets)}개의 핸들러 발견")
            print("-" * 60)
            
            # 각 핸들러를 개별 분석
            for i, target_addr in enumerate(dispatcher_targets[:max_chains]):
                print(f"\n[핸들러 #{i}] 주소: 0x{target_addr:x}")
                print("-" * 40)
                
                vm_operation = self._analyze_single_chain(target_addr)
                print(f"[결과] VM_OPCODE_{i}: {vm_operation}")
                
            print(f"\n[완료] 총 {len(dispatcher_targets)}개의 VM 핸들러를 분석했습니다.")
        else:
            # 기존 단일 체인 분석
            current_entry = entry_address
            chain_count = 0
            
            while chain_count < max_chains and current_entry:
                print(f"\n[체인 #{chain_count + 1}] 시작 주소: 0x{current_entry:x}")
                print("-" * 40)
                
                vm_operation = self._analyze_single_chain(current_entry)
                
                if vm_operation:
                    print(f"[결과] {vm_operation}")
                    
                    next_entry = self._find_next_chain_entry(current_entry)
                    if next_entry and next_entry != current_entry:
                        current_entry = next_entry
                        chain_count += 1
                    else:
                        print(f"[종료] 다음 체인을 찾을 수 없습니다.")
                        break
                else:
                    print(f"[오류] 체인 분석 실패")
                    break
                    
            print(f"\n[완료] 총 {chain_count + 1}개의 VM 연산 체인을 분석했습니다.")

    def _detect_dispatcher_table(self, address: int) -> list:
        """
        주소가 VM 디스패처 테이블인지 감지하고, 점프 대상들을 반환합니다.
        """
        instructions = self.disassemble_at(address, size=0x100)
        jump_targets = []
        
        consecutive_jumps = 0
        for insn in instructions:
            if insn.mnemonic == 'jmp' and insn.operands and insn.operands[0].type == x86_const.X86_OP_IMM:
                jump_targets.append(insn.operands[0].imm)
                consecutive_jumps += 1
            else:
                break  # 연속된 점프가 끝남
                
        # 3개 이상의 연속된 직접 점프가 있으면 디스패처 테이블로 간주
        if consecutive_jumps >= 3:
            print(f"[감지] {consecutive_jumps}개의 연속된 점프 발견 → VM 디스패처 테이블")
            return jump_targets
        else:
            return []

    def _analyze_single_chain(self, start_address: int) -> str:
        """
        단일 tail-call 체인을 분석하여 VM 연산을 식별합니다.
        """
        operations = []
        memory_accesses = []
        arithmetic_ops = []
        
        # 제한된 수의 명령어만 추적
        instructions = self.disassemble_at(start_address, size=0x200)
        
        print(f"[디버그] 0x{start_address:x}에서 {len(instructions)}개 명령어 발견")
        
        instruction_count = 0
        for insn in instructions[:50]:  # 최대 50개 명령어만 분석
            instruction_count += 1
            print(f"  {instruction_count:2d}. 0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
            
            # 메모리 접근 패턴 감지 (확장)
            if any(keyword in insn.op_str for keyword in ['qword ptr', 'dword ptr', 'word ptr', 'byte ptr']):
                memory_accesses.append(f"{insn.mnemonic} {insn.op_str}")
                print(f"      → 메모리 접근")
            
            # 데이터 이동 연산 감지
            if insn.mnemonic in ['mov', 'movzx', 'movsx', 'push', 'pop']:
                operations.append(f"데이터이동: {insn.mnemonic} {insn.op_str}")
                print(f"      → 데이터 이동")
            
            # 산술 연산 감지
            if insn.mnemonic in ['add', 'sub', 'mul', 'div', 'xor', 'and', 'or', 'shl', 'shr', 'inc', 'dec']:
                arithmetic_ops.append(f"{insn.mnemonic} {insn.op_str}")
                print(f"      → 산술 연산")
            
            # 비교 연산 감지
            if insn.mnemonic in ['cmp', 'test']:
                operations.append(f"조건비교: {insn.op_str}")
                print(f"      → 조건 비교")
            
            # 제어 흐름 감지
            if insn.mnemonic in ['call', 'ret', 'jmp', 'je', 'jne', 'jz', 'jnz']:
                operations.append(f"제어흐름: {insn.mnemonic} {insn.op_str}")
                print(f"      → 제어 흐름")
            
            # 간접 점프로 체인 종료
            if insn.mnemonic == 'jmp' and 'r' in insn.op_str and '[' not in insn.op_str:
                operations.append(f"다음_핸들러로_분기: {insn.op_str}")
                print(f"      → 간접 점프: {insn.op_str}")
                break
                
            # 처음 10개 명령어만 자세히 보기
            if instruction_count >= 10:
                print(f"  ... (총 {len(instructions)}개 중 처음 10개만 표시)")
                break
        
        # 패턴 분석 결과 생성
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
        
        print(f"[디버그] 감지된 패턴 - 메모리:{len(memory_accesses)}, 산술:{len(arithmetic_ops)}, 전체연산:{len(operations)}")
        
        return " + ".join(result_parts) if result_parts else "미분류_연산"

    def _find_next_chain_entry(self, current_address: int) -> int:
        """
        현재 체인에서 다음 체인의 시작점을 찾습니다.
        """
        # 이 부분은 실제 레지스터 값을 알아야 하므로 
        # 지금은 간단히 고정 오프셋을 사용
        # 실제로는 동적 분석이나 에뮬레이션이 필요
        return None  # 일단 None 반환

    def simulate_execution(self, entry_address: int, max_instructions: int = 100):
        """
        코드를 실제로 시뮬레이션하여 연산 결과를 계산합니다.
        """
        print(f"[*] 실행 시뮬레이션 시작: 0x{entry_address:x}")
        print(f"[*] 초기 레지스터 상태:")
        for reg, val in self.registers.items():
            if val != 0:
                print(f"    {reg}: 0x{val:x}")
        print("=" * 60)
        
        current_address = entry_address
        instruction_count = 0
        
        while instruction_count < max_instructions:
            # 명령어 디스어셈블
            instructions = self.disassemble_at(current_address, size=0x20)
            if not instructions:
                print(f"[!] 0x{current_address:x}에서 명령어를 찾을 수 없습니다.")
                break
                
            insn = instructions[0]
            instruction_count += 1
            
            print(f"{instruction_count:3d}. 0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
            
            # 명령어 실행 시뮬레이션
            next_address = self._simulate_instruction(insn)
            
            # 레지스터 상태 출력 (변경된 것만)
            self._print_register_changes()
            
            if next_address:
                current_address = next_address
            else:
                current_address = insn.address + insn.size
                
            # 간접 점프면 중단
            if insn.mnemonic == 'jmp' and any(reg in insn.op_str for reg in ['r13', 'rax', 'rbx']):
                print(f"[!] 간접 점프로 시뮬레이션 종료: {insn.op_str}")
                break
                
            print("-" * 40)
        
        print(f"\n[*] 시뮬레이션 완료 - 총 {instruction_count}개 명령어 실행")
        print(f"[*] 최종 레지스터 상태:")
        for reg, val in self.registers.items():
            print(f"    {reg}: 0x{val:x}")

    def _simulate_instruction(self, insn) -> int:
        """
        개별 명령어를 시뮬레이션합니다.
        """
        mnemonic = insn.mnemonic
        op_str = insn.op_str
        
        if mnemonic == 'mov':
            return self._simulate_mov(op_str)
        elif mnemonic == 'add':
            return self._simulate_add(op_str)
        elif mnemonic == 'sub':
            return self._simulate_sub(op_str)
        elif mnemonic == 'and':
            return self._simulate_and(op_str)
        elif mnemonic == 'jmp':
            return self._simulate_jmp(op_str, insn.address)
        else:
            print(f"        → 지원하지 않는 명령어: {mnemonic}")
            return None
    
    def _simulate_mov(self, op_str: str) -> int:
        """MOV 명령어 시뮬레이션"""
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        # 소스 값 가져오기
        src_val = self._get_operand_value(src)
        
        # 목적지에 저장
        self._set_operand_value(dst, src_val)
        
        print(f"        → {dst} = 0x{src_val:x}")
        return None
    
    def _simulate_add(self, op_str: str) -> int:
        """ADD 명령어 시뮬레이션"""
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        dst_val = self._get_operand_value(dst)
        src_val = self._get_operand_value(src)
        result = (dst_val + src_val) & 0xFFFFFFFFFFFFFFFF  # 64비트 마스크
        
        self._set_operand_value(dst, result)
        print(f"        → {dst} = 0x{dst_val:x} + 0x{src_val:x} = 0x{result:x}")
        return None
    
    def _simulate_sub(self, op_str: str) -> int:
        """SUB 명령어 시뮬레이션"""
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        dst_val = self._get_operand_value(dst)
        src_val = self._get_operand_value(src)
        result = (dst_val - src_val) & 0xFFFFFFFFFFFFFFFF
        
        self._set_operand_value(dst, result)
        print(f"        → {dst} = 0x{dst_val:x} - 0x{src_val:x} = 0x{result:x}")
        return None
    
    def _simulate_and(self, op_str: str) -> int:
        """AND 명령어 시뮬레이션"""
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        dst_val = self._get_operand_value(dst)
        src_val = self._get_operand_value(src)
        result = dst_val & src_val
        
        self._set_operand_value(dst, result)
        print(f"        → {dst} = 0x{dst_val:x} & 0x{src_val:x} = 0x{result:x}")
        return None
    
    def _simulate_jmp(self, op_str: str, current_addr: int) -> int:
        """JMP 명령어 시뮬레이션"""
        if op_str.startswith('0x'):
            # 직접 점프
            target = int(op_str, 16)
            print(f"        → 점프: 0x{target:x}")
            return target
        elif op_str in self.registers:
            # 간접 점프
            target = self.registers[op_str]
            print(f"        → 간접 점프: {op_str} (0x{target:x})")
            return target
        else:
            print(f"        → 지원하지 않는 점프: {op_str}")
            return None
    
    def _get_operand_value(self, operand: str) -> int:
        """피연산자 값 가져오기"""
        operand = operand.strip()
        
        # 즉시값
        if operand.startswith('0x'):
            return int(operand, 16)
        elif operand.isdigit() or (operand.startswith('-') and operand[1:].isdigit()):
            return int(operand)
        
        # 레지스터
        if operand in self.registers:
            return self.registers[operand]
        
        # 메모리 참조 (간단한 구현)
        if 'ptr [' in operand:
            # 예: qword ptr [rbp + 0xf8]
            print(f"        → 메모리 접근: {operand} (임시값 0x1234 반환)")
            return 0x1234  # 임시값
        
        print(f"        → 알 수 없는 피연산자: {operand}")
        return 0
    
    def _set_operand_value(self, operand: str, value: int):
        """피연산자에 값 설정"""
        operand = operand.strip()
        
        # 레지스터
        if operand in self.registers:
            self.registers[operand] = value
            return
        
        # 메모리 (간단한 구현)
        if 'ptr [' in operand:
            print(f"        → 메모리 저장: {operand} = 0x{value:x}")
            return
        
        print(f"        → 알 수 없는 목적지: {operand}")
    
    def _print_register_changes(self):
        """변경된 레지스터만 출력"""
        # 간단한 구현 - 0이 아닌 값들만 출력
        changed = {k: v for k, v in self.registers.items() if v != 0 and k not in ['rbp', 'rsp']}
        if changed:
            print(f"        레지스터: {', '.join([f'{k}=0x{v:x}' for k, v in changed.items()])}")

if __name__ == "__main__":
    # 사용 예시:
    # "target.bin"을 실제 바이너리 파일로 교체하세요.
    # BASE_ADDRESS와 ENTRY_ADDRESS를 적절히 조정하세요.
    
    # 자리표시자 값 - 실제 데이터로 교체
    binary_file_path = "L2.bin" # 이 파일을 생성하거나 제공해야 합니다
    BASE_ADDRESS  = 0x7ff64dbcf6f4  # 예시: 바이너리 로드 주소
    ENTRY_ADDRESS = 0x7ff64dbfc67a # 예시: tail-call 시작 주소
    
    try:
        with open(binary_file_path, "rb") as f:
            code = f.read()
        print(f"[*] {binary_file_path}에서 {len(code)} 바이트를 성공적으로 읽었습니다\n")
    except FileNotFoundError:
        print(f"[!] 오류: 바이너리 파일 '{binary_file_path}'을 찾을 수 없습니다.")
        print("더미 'target.bin'을 생성하거나 테스트할 유효한 경로를 제공하세요.")
        # 존재하지 않는 경우 더미용 더미 파일 생성
        print("테스트용 간단한 jmp 명령어로 더미 'target.bin'을 생성합니다.")
        try:
            # 간단한 "jmp 0x10" (현재 위치 기준 상대)
            # 0:  eb 0e                   jmp    0x10
            # 절대 주소로 jmp하려면 (예: BASE_ADDRESS + 0x100)
            # 현재 EIP에서 상대 오프셋을 계산해야 합니다.
            # 간단히 하기 위해 nop들과 ret만 넣습니다.
            # 00: 90 (nop) * 10
            # 0A: c3 (ret)
            dummy_code = b'\x90' * 10 + b'\xc3'
            with open(binary_file_path, "wb") as f_dummy:
                f_dummy.write(dummy_code)
            code = dummy_code
            print(f"[*] {len(code)} 바이트로 더미 '{binary_file_path}'을 생성했습니다.")
            # 더미 코드의 경우 진입점 조정
            # ENTRY_ADDRESS = BASE_ADDRESS # 더미 코드의 시작부터 시작
        except Exception as e_create:
            print(f"[!] 더미 파일 생성에 실패했습니다: {e_create}")
            code = None
    except Exception as e:
        print(f"[!] '{binary_file_path}' 읽기 중 오류가 발생했습니다: {e}")
        code = None

    if code:
        analyzer = VMAnalyzer(code, BASE_ADDRESS)
        
        print("[*] 분석 모드를 선택하세요:")
        print("1. 상세 tail-call 추적 (기존)")
        print("2. 고수준 VM 패턴 분석 (새로운 기능)")
        print("3. 실행 시뮬레이션 (실제 연산 계산) 🔥")
        
        # 기본적으로 tail-call 추적 사용 (사용자의 원래 목적)
        analysis_mode = 3  # 시뮬레이션을 기본으로
        
        if analysis_mode == 2 or str(analysis_mode) == "2":
            print("\n[*] 고수준 VM 패턴 분석을 시작합니다...")
            analyzer.analyze_vm_patterns(ENTRY_ADDRESS, max_chains=5)
        elif analysis_mode == 3 or str(analysis_mode) == "3":
            print("\n[*] 실행 시뮬레이션을 시작합니다...")
            analyzer.simulate_execution(ENTRY_ADDRESS, max_instructions=50)
        else:
            print("\n[*] 상세 tail-call 추적을 시작합니다...")
            # 더미 코드의 경우 시작부터 추적합니다.
            # 실제 바이너리를 사용하는 경우 ENTRY_ADDRESS가 올바른지 확인하세요.
            if binary_file_path == "target.bin" and len(code) == 11 and code.startswith(b'\x90\x90'): # 더미인지 확인
                 print("\n[*] 더미 코드를 사용하여 기본 주소부터 추적을 시작합니다.")
                 analyzer.trace_tail_calls(BASE_ADDRESS)
            else:
                 analyzer.trace_tail_calls(ENTRY_ADDRESS)

        print("\n[*] 분석이 완료되었습니다.")
