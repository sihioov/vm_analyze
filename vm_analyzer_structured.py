from capstone import Cs, CS_ARCH_X86, CS_MODE_64, x86_const
import datetime

# ============================================================================
# VM 분석기 - 향상된 메모리 추적 및 동적 수정 기능
# ============================================================================
# 
# 새로운 기능들:
# 1. 실시간 메모리 변화 추적: 모든 메모리 쓰기를 추적하고 기록
# 2. 메모리 접근 모니터링: 특정 주소의 읽기/쓰기 접근 감지
# 3. 조건부 메모리 수정: 특정 조건에서만 메모리 값 변경
# 4. 메모리 범위 패치: 연속된 메모리 영역에 값 배치
# 5. 상세한 메모리 분석 리포트: 수정 패턴, 빈도, 타이밍 분석
#
# 사용 예시:
# - analyzer.vm_state.monitor_memory_access(0x주소)  # 주소 모니터링
# - analyzer.vm_state.set_memory_conditional(addr, value, condition_func)  # 조건부 수정
# - analyzer.vm_state.patch_memory_range(start_addr, [값1, 값2, 값3])  # 범위 패치
# ============================================================================

# ============================================================================
# 출력 관리 클래스
# ============================================================================
class OutputWriter:
    """분석 결과를 파일과 콘솔에 출력합니다."""
    
    def __init__(self, mode: str = None):
        self.mode = mode
        self.file_handle = None
        self.filename = None
        self.file_enabled = True
        
        if mode:
            self._setup_output_file()
    
    def _setup_output_file(self):
        """분석 모드에 따라 출력 파일을 설정합니다."""
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if self.mode == "1":
                self.filename = "tail_call_analysis.txt"
            elif self.mode == "2":
                self.filename = "vm_pattern_analysis.txt"
            elif self.mode == "3":
                self.filename = "execution_simulation.txt"
            else:
                self.filename = f"vm_analysis_{timestamp}.txt"
            
            # 파일을 쓰기 모드로 열기 (기존 파일 덮어쓰기)
            self.file_handle = open(self.filename, 'w', encoding='utf-8')
            self.write(f"=== VM 분석 결과 ===")
            self.write(f"생성 시간: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            self.write(f"분석 모드: {self._get_mode_name()}")
            self.write("=" * 60)
            print(f"[*] 결과가 '{self.filename}' 파일에 저장됩니다.")
            
        except Exception as e:
            print(f"[!] 파일 생성 실패: {e}")
            print(f"[!] 파일명: {self.filename}")
            print(f"[*] 콘솔 출력만 사용합니다.")
            self.file_enabled = False
            self.file_handle = None
    
    def _get_mode_name(self) -> str:
        """모드 번호를 이름으로 변환합니다."""
        mode_names = {
            "1": "상세 tail-call 추적",
            "2": "고수준 VM 패턴 분석",
            "3": "실행 시뮬레이션"
        }
        return mode_names.get(self.mode, "알 수 없음")
    
    def write(self, text: str):
        """텍스트를 파일과 콘솔에 출력합니다."""
        print(text)  # 콘솔에는 항상 출력
        
        if self.file_enabled and self.file_handle:
            try:
                self.file_handle.write(text + '\n')
                self.file_handle.flush()  # 즉시 파일에 쓰기
            except Exception as e:
                if self.file_enabled:  # 첫 번째 에러에서만 메시지 출력
                    print(f"[!] 파일 쓰기 실패: {e}")
                    print(f"[*] 콘솔 출력만 계속 사용합니다.")
                    self.file_enabled = False
    
    def close(self):
        """파일 핸들을 닫습니다."""
        if self.file_handle:
            try:
                self.write("\n=== 분석 완료 ===")
                self.file_handle.close()
                if self.file_enabled:
                    print(f"[*] 결과가 '{self.filename}' 파일에 저장되었습니다.")
            except Exception as e:
                print(f"[!] 파일 닫기 실패: {e}")
            finally:
                self.file_handle = None

# ============================================================================
# 메모리 및 레지스터 관리 클래스
# ============================================================================
class VMState:
    """VM의 레지스터와 메모리 상태를 관리합니다."""
    
    def __init__(self, output_writer: OutputWriter = None, initial_rbp: int = None, initial_rsp: int = None, 
                 code_bytes: bytes = None, base_address: int = None):
        # 기본값은 일반적인 스택 영역 주소를 사용하되, 설정 가능하게 함
        default_stack_addr = 0x7fff12340000
        
        # 바이너리 데이터 접근을 위한 속성 추가
        self.code_bytes = code_bytes
        self.base_address = base_address
        
        self.registers = {
            'rax': 0x7ff6ec0abbd9, 'rbx': 0x158, 
            'rcx': 0x7ff6ebea0000, 'rdx':0x7ff6ec0aba81,
            'rsi': 0x7ff6ebf9186a, 'rdi': 0, 'rbp': 0x7ff6ebf9186a,
            'rsp': 0x3beb8ff738,  
            'r8': 0xf, 'r9': 0x122d0, 'r10': 0x15fbf680000,
            'r11': 0x3beb8ff7b0, 'r12': 0, 'r13': 0, 'r14': 0x7ff6ebea0000, 'r15': 0

            # 'rax': 0x7ff7bc12c059, 'rbx': 0x5d8, 'rcx': 0x7ff7bbf20000, 'rdx':0x20ba81,
            # 'rsi': 0x7ff7bc054c32, 'rdi': 0x49,             
            # 'rbp': 0x7ff7bc01186a,
            # 'rsp': 0xdce09dfb50,  
            # 'r8': 0x7ff7bbf20000, 'r9': 0x122d0, 'r10': 0xdce09df7d9,
            # 'r11': 0xdce09df3a0, 'r12': 0, 'r13': 0, 'r14': 0, 'r15': 0


            # 'rax': 0, 'rbx': 0, 'rcx': 0, 'rdx': 0,
            # 'rsi': 0, 'rdi': 0, 
            # 'rbp': initial_rbp if initial_rbp is not None else default_stack_addr,
            # 'rsp': initial_rsp if initial_rsp is not None else default_stack_addr, 
            # 'r8': 0, 'r9': 0, 'r10': 0,
            # 'r11': 0, 'r12': 0, 'r13': 0, 'r14': 0, 'r15': 0
        }
        self.memory = {
            # 0xe9faeff840: (0x0204b6cd542, False),
            # 0xe9faeff858: (0xe9faeff090, False),
            # 0xe9faeff8a0: (0x7f, False),
            # 0x7ff7544919c6: (0x0, False),
            # 0xe9faeff8a8: (0x0, False),
            #0x7f5ab1f7c8: (0x000000000000000a, False),

            # 0x7ff6af24bbd9: (0x7ff6af11c69d, False),
            # 0x7ff6af131956: (0x15883e9700450a00, False),
            # 0x7ff6af131962: (0x45bb, False),
            # 0x7ff6af13189d: (0x240000, False),
            # 0x7ff6af1318cb: (0x7ff6af1feb32, False),
            # 0x7ff6af1319da: (0x699bbd22bc8bbcab, False),
            # 0x7ff6af1feb34: (0x0128fff1c3ab0005, False),
            # 0x7ff6af1feb36: (0x050128fff1c3ab, False),
            # 0x7ff6af1318e7: (0x7ff6af24ba, False),
            # 0x7ff6af1feb32: (0xfff1c3ab00050128, False),

            # 0x7ff7bc0118e7: (0x7ff7bc12ba81, False),
            # 0x7ff7bc0118c6: (0x02bf1cbe91c11b55, False),
            # 0x7ff7bc0119aa: (0x90ddd9f6f000, False),
            # 0x7ff7bc011937: (0x097030000000008f, False),
            # 0x7ff7bc01d45c: (0x497fdc9cbbf58149, False),
            # 0x7ff7bc0118cb: (0x7ff7bc02bf1c, False),
            # 0x7ff7bc02bf1c: (0x0e97c6570003842f, False),
            # 0x7ff7bc02bf24: (0xd01bd3f57a012866, False),
            # 0x7ff7bc01199a: (0x0, False),
            # 0x7ff7bc01187c: (0x0fdf, False),
            # 0x7ff7bc02bf20: (0x7a0128660e97c657, False),
            # 0x7ff7bc02bf25: (0x09d01bd3f57a0128, False),
            # 0x7ff7bc02bf27: (0x085509d01bd3f57a, False),
            # 0x7ff7bc130ec9: (0xe9000003ece9e889, False),
            # 0x7ff7bc0216ab: (0xf62949000003b1e9, False),
            # 0x7ff7bc12bad9: (0x7ff7bc01f053, False),
            # 0x7ff7bc06434f: (0x6801286f3aa14df8, False),
            # 0x7ff7bc064353: (0xffd633516801286f, False),
            # 0x7ff7bc064358: (0x0f0128ffffffd633, False),
            # 0x7ff7bc064354: (0xffffd63351680128, False),
            # 0x7ff7bc064356: (0x28ffffffd6335168, False),
            # 0x7ff7bc0119c5: (0x3fe9, False),
            # 0x7ff7bc154401: (0x0000006e00000000, False),
            # 0x7ff7bc06434b: (0x3aa14df80000000e, False),
            # 0x7ff7bc12bae9: (0x7ff7bbff43df, False),
            # 0x7ff7bc011956: (0xe7db3efd7fcf793f, False),


            # 0x7ff7bc01189d: (0, False),
            # 0x7ff7bc0119da: (0, False),
            # 0x7ff7bc0118cb: (0x7ff7bc0d8749, False),
            # 0x7ff7bc0118e7: (0x7ff7bc12ba81, False),
            # 0x7ff7bc12ba81: (0x7ff7bc03e17e, False),
            # 0x7ff7bc0118c7: (0, False),
            # 0x7ff7bc42b8f8: (0x75731d754bdc69c3, False),
            # 0x9bdd2ff748: (0x68745f5f00746e63, False),
            # 0x9bdd2ff6c0: (0x6e6f636c5f5f0065, False),
            # 0x9bdd2ff6e8: (0x696f69785f5f0063, False),


            # 0x7ff67597189d: (0x0, False),
            # 0x7ff6759718c7: (0xa34f7a7a, False),
            # 0x7ff675971962: (0x0, False),
            # 0x7ff6759719da: (0x0, False),
            # 0x7ff6759718cb: (0x75a38749, False),
            # 0x7ff6759718e7: (0x7ff675a8ba81, False),
            # 0x7ff675a8ba81: (0x7ff67599e17e, False),
            # 스택 메모리: 현재 RSP 위치에 테스트용 반환 주소 설정
            # 0x39587cf840: (0x7ff67597186a, False),  # 현재 RSP에 반환 주소 설정 (임시)
            #0x7ff67599e17e: (0x7ff67597186a, False),
            }  # {address: (value, is_estimated)}
        self.flags = {
            'ZF': False,  # Zero Flag
            'CF': False,  # Carry Flag  
            'SF': False,  # Sign Flag
            'DF': False   # Direction Flag
        }
        self.use_real_values = False
        self.output = output_writer or OutputWriter()
        
        # 초기 rbp/rsp 값이 설정된 경우 알림
        if initial_rbp is not None or initial_rsp is not None:
            self.output.write("[*] 초기 레지스터 값 설정:")
            if initial_rbp is not None:
                self.output.write(f"    rbp = 0x{initial_rbp:x}")
            if initial_rsp is not None:
                self.output.write(f"    rsp = 0x{initial_rsp:x}")

    def set_real_memory_values(self, memory_values: dict):
        """실제 메모리 값들을 설정합니다."""
        for addr, val in memory_values.items():
            self.memory[addr] = (val, False)  # 실제값으로 저장
        self.use_real_values = True
        self.output.write(f"[*] 실제 메모리 값 {len(memory_values)}개 설정됨:")
        for addr, val in memory_values.items():
            self.output.write(f"    [0x{addr:x}] = 0x{val:x}")

    def set_real_registers(self, register_values: dict):
        """실제 레지스터 값들을 설정합니다."""
        self.registers.update(register_values)
        self.output.write(f"[*] 실제 레지스터 값 {len(register_values)}개 설정됨:")
        for reg, val in register_values.items():
            self.output.write(f"    {reg} = 0x{val:x}")

    def get_register(self, reg_name: str) -> int:
        return self.registers.get(reg_name, 0)

    def set_register(self, reg_name: str, value: int):
        old_value = self.registers.get(reg_name, 0)
        self.registers[reg_name] = value
        
        # 중요한 레지스터 변화 추적 (특히 RBP, RSP)
        if reg_name in ['rbp', 'rsp'] and old_value != value:
            self.output.write(f"        📌 [레지스터 변화] {reg_name.upper()}: 0x{old_value:x} → 0x{value:x}")
            
            # RBP가 0이 되는 경우 특별 추적
            if reg_name == 'rbp' and value == 0:
                self.output.write(f"        ⚠️  [RBP=0 경고] RBP가 0으로 설정됨 - VM 플랫 구조로 전환")

    def get_memory(self, address: int) -> tuple[int, bool]:
        """메모리 값을 가져옵니다. (값, 추정값여부) 반환"""
        # 모니터링된 주소 접근 체크
        if hasattr(self, 'monitored_addresses') and address in self.monitored_addresses:
            self.output.write(f"        👁️  [모니터] 0x{address:x} 읽기 접근 감지")
        
        if address in self.memory:
            value, is_estimated = self.memory[address]
            return value, is_estimated
        else:
            # 1단계: 바이너리 파일에서 값 찾기 시도
            binary_value = self._get_value_from_binary(address)
            if binary_value is not None:
                self.memory[address] = (binary_value, False)  # 실제값으로 저장
                self.output.write(f"        📖 [바이너리에서 읽음] 0x{address:x} = 0x{binary_value:x}")
                return binary_value, False
            
            # 2단계: 바이너리에서도 찾을 수 없으면 추정값 사용
            estimated_value = self._estimate_memory_value(address)
            self.memory[address] = (estimated_value, True)  # 추정값으로 저장
            return estimated_value, True

    def set_memory(self, address: int, value: int):
        """메모리 값을 설정합니다. (항상 실제값으로 처리)"""
        # 기존 값 확인 (변화 추적용)
        old_value = None
        if address in self.memory:
            old_value, _ = self.memory[address]
        
        # 새 값 설정
        self.memory[address] = (value, False)  # 새로 설정된 값은 실제값
        
        # 메모리 변화 로깅
        if old_value is not None and old_value != value:
            self.output.write(f"        🔄 [메모리 수정] 0x{address:x}: 0x{old_value:x} → 0x{value:x}")
        elif old_value is None:
            self.output.write(f"        ✨ [메모리 생성] 0x{address:x} ← 0x{value:x}")
        
        return old_value  # 이전 값 반환

    def set_memory_conditional(self, address: int, value: int, condition_func=None):
        """조건부 메모리 값 설정"""
        if condition_func is None or condition_func(address, self):
            old_value = self.set_memory(address, value)
            self.output.write(f"        🎯 [조건부 설정] 0x{address:x} = 0x{value:x}")
            return old_value
        return None

    def patch_memory_range(self, start_addr: int, values: list):
        """메모리 범위에 값들을 연속으로 설정"""
        self.output.write(f"        🔧 [메모리 패치] 0x{start_addr:x} ~ 0x{start_addr + len(values)*8:x}")
        for i, value in enumerate(values):
            addr = start_addr + (i * 8)
            self.set_memory(addr, value)

    def monitor_memory_access(self, address: int):
        """특정 메모리 주소 접근 모니터링"""
        if not hasattr(self, 'monitored_addresses'):
            self.monitored_addresses = set()
        self.monitored_addresses.add(address)
        self.output.write(f"        👁️  [모니터 등록] 0x{address:x} 접근 추적 시작")

    def _get_value_from_binary(self, address: int) -> int:
        """바이너리 파일에서 주소에 해당하는 값을 읽어옵니다."""
        if not self.code_bytes or not self.base_address:
            return None
        
        # 주소가 바이너리 범위 내에 있는지 확인
        if address < self.base_address or address >= self.base_address + len(self.code_bytes):
            return None
        
        try:
            offset = address - self.base_address
            # 8바이트 읽기 (Little Endian)
            if offset + 8 <= len(self.code_bytes):
                value_bytes = self.code_bytes[offset:offset + 8]
                value = int.from_bytes(value_bytes, byteorder='little')
                return value
            # 8바이트를 읽을 수 없으면 4바이트 시도
            elif offset + 4 <= len(self.code_bytes):
                value_bytes = self.code_bytes[offset:offset + 4]
                value = int.from_bytes(value_bytes, byteorder='little')
                return value
            # 4바이트도 안되면 남은 바이트만 읽기
            else:
                remaining = len(self.code_bytes) - offset
                if remaining > 0:
                    value_bytes = self.code_bytes[offset:offset + remaining]
                    # 부족한 바이트는 0으로 패딩
                    value_bytes += b'\x00' * (8 - len(value_bytes))
                    value = int.from_bytes(value_bytes, byteorder='little')
                    return value
                else:
                    return None
        except Exception as e:
            self.output.write(f"        ❌ [바이너리 읽기 오류] 0x{address:x}: {e}")
            return None

    def _estimate_memory_value(self, address: int) -> int:
        """VM 초기 메모리 상태 추정"""
        if self.use_real_values:
            return 0x0
        
        # 스택 영역 감지 (RSP 기준)
        rsp = self.registers['rsp']
        if abs(address - rsp) < 0x1000:  # RSP 근처 4KB 범위
            return 0x0  # 스택은 기본적으로 0으로 초기화
        
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
            self.output.write(f"        레지스터: {reg_str}")


# ============================================================================
# 디스어셈블리 엔진
# ============================================================================
class DisassemblyEngine:
    """코드 디스어셈블리를 담당합니다."""
    
    def __init__(self, code_bytes: bytes, base_address: int, output_writer: OutputWriter = None):
        self.code_bytes = code_bytes
        self.base_address = base_address
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self.output = output_writer or OutputWriter()

    def get_code_slice(self, address: int, size: int) -> bytes:
        offset = address - self.base_address
        
        # 디버깅 정보 추가
        if offset < 0 or offset >= len(self.code_bytes):
            self.output.write(f"[!] 오류: 주소 0x{address:x}가 범위를 벗어났습니다.")
            self.output.write(f"    요청 주소: 0x{address:x}")
            self.output.write(f"    베이스 주소: 0x{self.base_address:x}")
            self.output.write(f"    계산된 오프셋: 0x{offset:x} ({offset} 바이트)")
            self.output.write(f"    파일 크기: {len(self.code_bytes)} 바이트")
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
    
    def __init__(self, disasm_engine: DisassemblyEngine, output_writer: OutputWriter = None):
        self.disasm = disasm_engine
        self.output = output_writer or OutputWriter()

    def trace(self, entry_address: int, max_instructions_per_block: int = 50, max_revisits: int = 3):
        visited_addresses = {}
        addresses_to_visit = [entry_address]
        tail_call_count = 0

        self.output.write(f"[*] 0x{entry_address:x}에서 tail-call 추적을 시작합니다\n")

        while addresses_to_visit:
            current_address = addresses_to_visit.pop(0)
            
            visit_count = visited_addresses.get(current_address, 0)
            if visit_count >= max_revisits:
                self.output.write(f"[!] 0x{current_address:x} 최대 재방문 횟수 도달. 건너뜁니다.")
                continue
            
            visited_addresses[current_address] = visit_count + 1
            
            if visit_count > 0:
                self.output.write(f"[-] 재방문: 0x{current_address:x} (방문 횟수: {visit_count + 1})")
            
            self.output.write(f"--- 0x{current_address:x}에서 블록 추적 중 ---")
            
            instructions = self.disasm.disassemble_at(current_address, 
                                                    size=max_instructions_per_block * 8)
            if not instructions:
                self.output.write(f"[!] 0x{current_address:x}에서 명령어를 찾을 수 없습니다.")
                continue

            instruction_count = 0
            for insn in instructions:
                # 바이너리 파일 오프셋 계산
                file_offset = insn.address - self.disasm.base_address
                self.output.write(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str} ({file_offset:08x})")
                instruction_count += 1

                if insn.mnemonic == "jmp":
                    if insn.operands and insn.operands[0].type == x86_const.X86_OP_IMM:
                        target_address = insn.operands[0].imm
                        tail_call_count += 1
                        self.output.write(f"\n[+] Tail call #{tail_call_count} → 0x{target_address:x}\n")
                        
                        target_visit_count = visited_addresses.get(target_address, 0)
                        if target_visit_count < max_revisits:
                            addresses_to_visit.append(target_address)
                        break
                    else:
                        self.output.write(f"[*] 간접 점프: {insn.mnemonic} {insn.op_str}. 추적 계속 진행.")
                        # 간접 점프에서도 추적을 계속 진행
                elif insn.mnemonic == "ret":
                    self.output.write(f"\n[-] 반환. 추적 중단.\n")
                    break
                
                if instruction_count >= max_instructions_per_block:
                    self.output.write(f"[!] 최대 명령어 수({max_instructions_per_block})에 도달. 추적 중단.")
                    break


# ============================================================================
# 패턴 분석기
# ============================================================================
class PatternAnalyzer:
    """VM 패턴을 분석합니다."""
    
    def __init__(self, disasm_engine: DisassemblyEngine, output_writer: OutputWriter = None):
        self.disasm = disasm_engine
        self.output = output_writer or OutputWriter()

    def analyze(self, entry_address: int, max_chains: int = 10):
        self.output.write(f"[*] VM 패턴 분석 시작 (주소: 0x{entry_address:x})")
        self.output.write("=" * 60)
        
        dispatcher_targets = self._detect_dispatcher_table(entry_address)
        
        if dispatcher_targets:
            self._analyze_dispatcher_handlers(dispatcher_targets, max_chains)
        else:
            self.output.write("디스패처 테이블을 찾을 수 없습니다.")

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
            self.output.write(f"[감지] {consecutive_jumps}개의 연속 점프 → VM 디스패처")
            return jump_targets
        return []

    def _analyze_dispatcher_handlers(self, dispatcher_targets: list, max_chains: int):
        valid_handlers = [addr for addr in dispatcher_targets 
                         if self.disasm.is_address_valid(addr)]
        
        self.output.write(f"[*] 총 {len(dispatcher_targets)}개 핸들러 중 {len(valid_handlers)}개 유효")
        self.output.write("-" * 40)
        
        for i, target_addr in enumerate(valid_handlers[:max_chains]):
            self.output.write(f"\n[핸들러 #{i}] 0x{target_addr:x}")
            result = self._analyze_single_handler(target_addr)
            self.output.write(f"[결과] {result}")
            
        self.output.write(f"\n[완료] {len(valid_handlers)}개 핸들러 분석 완료")

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
    
    def __init__(self, disasm_engine: DisassemblyEngine, vm_state: VMState, output_writer: OutputWriter = None):
        self.disasm_engine = disasm_engine
        self.vm_state = vm_state
        self.output = output_writer or OutputWriter()
        self.jump_counts = {}  # 점프 대상 주소별 방문 횟수 추적
        self.memory_changes = {}  # 메모리 변화 추적: {address: [(old_value, new_value, instruction_num), ...]}
        self.memory_writes = {}  # 메모리 쓰기 패턴 추적: {address: [instruction_nums]}
        self.initial_registers = {}  # 초기 레지스터 값
        self.final_registers = {}  # 최종 레지스터 값
        self.instruction_count = 0  # 현재 명령어 번호

    def simulate(self, entry_address: int, max_instructions: int = 200):
        """명령어 실행을 시뮬레이션합니다."""
        self.output.write(f"[*] 실행 시뮬레이션을 시작합니다...")
        self.output.write(f"[*] 설정: 최대 {max_instructions}개 명령어")
        self.output.write(f"[*] 실행 시뮬레이션 시작: 0x{entry_address:x}")
        self.output.write("=" * 60)
        
        # 초기 상태 저장
        self.initial_registers = self.vm_state.registers.copy()
        
        current_address = entry_address
        instruction_count = 0
        
        try:
            while instruction_count < max_instructions and current_address is not None:
                instruction_count += 1
                self.instruction_count = instruction_count  # 클래스 변수 업데이트
                
                # 디스어셈블리
                instructions = self.disasm_engine.disassemble_at(current_address, 16)
                if not instructions:
                    self.output.write(f"[!] 주소 0x{current_address:x}에서 디스어셈블리 실패")
                    break
                
                insn = instructions[0]
                
                # 바이너리 파일 오프셋 계산
                file_offset = insn.address - self.disasm_engine.base_address
                
                # 명령어 실행
                self.output.write(f"{instruction_count:3d}. 0x{insn.address:x}: {insn.mnemonic} {insn.op_str} ({file_offset:08x})")
                
                try:
                    # 명령어 시뮬레이션 실행
                    next_address = self._simulate_instruction(insn)
                    
                    # CALL 명령어인 경우 반환 주소를 올바르게 설정
                    if insn.mnemonic.lower() == 'call' and next_address is not None:
                        return_address = current_address + insn.size
                        # 스택에 올바른 반환 주소 설정
                        current_rsp = self.vm_state.get_register('rsp')
                        self.vm_state.set_memory(current_rsp, return_address)
                        self.output.write(f"        📞 [CALL 수정] 올바른 반환주소 0x{return_address:x} 설정")
                    
                    # 레지스터 상태 출력
                    self.vm_state.print_registers()
                    
                    if next_address is not None and next_address != current_address + insn.size:
                        # 점프가 발생한 경우
                        visit_info = ""
                        if next_address in self.jump_counts:
                            visit_info = f" (#{self.jump_counts[next_address]}번째 방문)"
                        self.output.write(f"        🔄 점프: 0x{current_address:x} → 0x{next_address:x}{visit_info}")
                        current_address = next_address
                    elif next_address is None and insn.mnemonic == 'ret':
                        # RET에서 None 반환 = VM 종료 신호
                        self.output.write(f"        🏁 [VM 종료] ret 명령어에서 종료 신호 받음")
                        break
                    else:
                        # 다음 명령어로 이동
                        current_address += insn.size
                    
                    self.output.write("-" * 40)
                    
                except Exception as e:
                    self.output.write(f"        ❌ [실행 오류] {e}")
                    break
                    
        except KeyboardInterrupt:
            self.output.write("\n[!] 사용자에 의해 중단됨")
        
        # 최종 상태 저장 및 분석
        self.final_registers = self.vm_state.registers.copy()
        self._analyze_execution_results(instruction_count)
        
        self.output.write(f"\n[*] 시뮬레이션 완료 - 총 {instruction_count}개 명령어 실행")

    def _analyze_execution_results(self, instruction_count: int):
        """VM 실행 결과를 분석합니다."""
        self.output.write("\n" + "=" * 60)
        self.output.write("📊 **VM 실행 결과 분석**")
        self.output.write("=" * 60)
        
        # 1. 레지스터 변화 분석
        self.output.write("\n🔄 **레지스터 변화 분석:**")
        changed_regs = []
        for reg in self.initial_registers:
            initial = self.initial_registers.get(reg, 0)
            final = self.final_registers.get(reg, 0)
            if initial != final:
                changed_regs.append((reg, initial, final))
        
        if changed_regs:
            for reg, initial, final in changed_regs:
                self.output.write(f"  {reg}: 0x{initial:x} → 0x{final:x}")
        else:
            self.output.write("  변화된 레지스터 없음")
        
        # 2. 메모리 변화 분석
        self.output.write("\n💾 **메모리 변화 분석:**")
        if self.memory_changes:
            self.output.write(f"  총 {len(self.memory_changes)}개 주소에서 메모리 수정 발생:")
            for addr, changes in self.memory_changes.items():
                self.output.write(f"  📍 [0x{addr:x}]: {len(changes)}회 수정")
                for i, (old_val, new_val, insn_num) in enumerate(changes[-3:]):  # 최근 3개만 표시
                    self.output.write(f"    #{insn_num}: 0x{old_val:x} → 0x{new_val:x}")
                if len(changes) > 3:
                    self.output.write(f"    ... 및 {len(changes) - 3}회 더")
        else:
            self.output.write("  메모리 쓰기 없음")
            
        # 현재 메모리 상태 요약
        if self.vm_state.memory:
            self.output.write(f"\n📋 **현재 메모리 상태:**")
            sorted_memory = sorted(self.vm_state.memory.items())
            for addr, (value, is_estimated) in sorted_memory[:10]:  # 상위 10개만 표시
                status = "추정값" if is_estimated else "실제값"
                self.output.write(f"  [0x{addr:x}] = 0x{value:x} ({status})")
            if len(sorted_memory) > 10:
                self.output.write(f"  ... 및 {len(sorted_memory) - 10}개 주소 더")
        
        # 3. 실행 패턴 분석
        self.output.write(f"\n📈 **실행 통계:**")
        self.output.write(f"  총 실행 명령어: {instruction_count}개")
        self.output.write(f"  메모리 쓰기: {len(self.memory_changes)}개 주소")
        self.output.write(f"  메모리 읽기: {len(self.vm_state.memory)}개 주소")
        
        # 메모리 쓰기 패턴 분석
        if self.memory_writes:
            write_frequency = sum(len(writes) for writes in self.memory_writes.values())
            self.output.write(f"  총 메모리 쓰기 횟수: {write_frequency}회")
            
            # 가장 자주 수정된 주소들
            frequent_writes = sorted(self.memory_writes.items(), 
                                   key=lambda x: len(x[1]), reverse=True)
            if frequent_writes:
                self.output.write(f"  가장 자주 수정된 주소:")
                for addr, writes in frequent_writes[:5]:  # 상위 5개
                    self.output.write(f"    0x{addr:x}: {len(writes)}회 (명령어 #{writes[0]} ~ #{writes[-1]})")

        # 점프 횟수 통계 추가
        if self.jump_counts:
            self.output.write(f"")
            self.output.write(f"🔄 **점프 횟수 통계:**")
            # 방문 횟수별로 정렬
            sorted_jumps = sorted(self.jump_counts.items(), key=lambda x: x[1], reverse=True)
            for addr, count in sorted_jumps[:10]:  # 상위 10개만 표시
                self.output.write(f"  0x{addr:x}: {count}회 방문")
            
            if len(sorted_jumps) > 10:
                self.output.write(f"  ... 및 {len(sorted_jumps) - 10}개 주소 더")

        self.output.write(f"")

        # 4. VM 목적 추정
        self.output.write(f"\n🎯 **VM 목적 추정:**")
        self._estimate_vm_purpose(changed_regs)

    def _simulate_instruction(self, insn):
        """개별 명령어 시뮬레이션"""
        mnemonic = insn.mnemonic
        op_str = insn.op_str
        
        if mnemonic == 'mov':
            return self._simulate_mov(op_str)
        elif mnemonic == 'movzx':
            return self._simulate_movzx(op_str)
        elif mnemonic == 'movabs':
            return self._simulate_movabs(op_str)
        elif mnemonic == 'movsxd':
            return self._simulate_movsxd(op_str)
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
        elif mnemonic == 'test':
            return self._simulate_test(op_str)
        elif mnemonic == 'je':
            return self._simulate_je(op_str)
        elif mnemonic == 'jns':
            return self._simulate_jns(op_str)
        elif mnemonic == 'jne':
            return self._simulate_jne(op_str)
        elif mnemonic == 'jz':
            return self._simulate_jz(op_str)
        elif mnemonic == 'jnz':
            return self._simulate_jnz(op_str)
        elif mnemonic == 'jmp':
            return self._simulate_jmp(op_str)
        elif mnemonic == 'push':
            return self._simulate_push(op_str)
        elif mnemonic == 'pushfq':
            return self._simulate_pushfq(op_str)
        elif mnemonic == 'pop':
            return self._simulate_pop(op_str)
        elif mnemonic == 'popfq':
            return self._simulate_popfq(op_str)
        elif mnemonic == 'xchg':
            return self._simulate_xchg(op_str)
        elif mnemonic == 'ret':
            return self._simulate_ret(op_str)
        elif mnemonic == 'neg':
            return self._simulate_neg(op_str)
        elif mnemonic.startswith('lock'):
            # lock 접두사가 있는 명령어 처리
            if 'sub' in mnemonic:
                return self._simulate_lock_sub(op_str)
            else:
                actual_mnemonic = mnemonic.split()[1] if len(mnemonic.split()) > 1 else mnemonic[4:]
                self.output.write(f"        → 지원하지 않는 lock 명령어: {mnemonic}")
                return None
        elif mnemonic == 'jb':
            return self._simulate_jb(op_str)
        elif mnemonic == 'call':
            return self._simulate_call(op_str)
        elif mnemonic == 'lea':
            return self._simulate_lea(op_str)
        elif mnemonic == 'stc':
            return self._simulate_stc(op_str)
        elif mnemonic == 'clc':
            return self._simulate_clc(op_str)
        elif mnemonic == 'std':
            return self._simulate_std(op_str)
        elif mnemonic == 'cld':
            return self._simulate_cld(op_str)
        elif mnemonic == 'out':
            return self._simulate_out(op_str)
        elif mnemonic == 'in':
            return self._simulate_in(op_str)
        elif mnemonic == 'syscall':
            return self._simulate_syscall(op_str)
        else:
            self.output.write(f"        → 지원하지 않는 명령어: {mnemonic}")
            return None

    def _simulate_mov(self, op_str: str):
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        src_val = self._get_operand_value(src)
        self._set_operand_value(dst, src_val)
        
        self.output.write(f"        → {dst} = 0x{src_val:x}")
        return None

    def _simulate_movzx(self, op_str: str):
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        src_val = self._get_operand_value(src)
        self._set_operand_value(dst, src_val)
        
        self.output.write(f"        → {dst} = 0x{src_val:x}")
        return None

    def _simulate_movabs(self, op_str: str):
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        src_val = self._get_operand_value(src)
        self._set_operand_value(dst, src_val)
        
        self.output.write(f"        → {dst} = 0x{src_val:x}")
        return None

    def _simulate_movsxd(self, op_str: str):
        """MOVSXD 명령어 시뮬레이션 - 32비트를 64비트로 부호 확장"""
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        src_val = self._get_operand_value(src) & 0xFFFFFFFF  # 32비트로 마스크
        
        # 부호 확장: 32비트 MSB가 1이면 상위 32비트를 1로 채움
        if src_val & 0x80000000:
            extended_val = src_val | 0xFFFFFFFF00000000
        else:
            extended_val = src_val
        
        self._set_operand_value(dst, extended_val)
        
        self.output.write(f"        → {dst} = 부호확장(0x{src_val:x}) = 0x{extended_val:x}")
        return None

    def _simulate_add(self, op_str: str):
        """ADD 명령어 시뮬레이션"""
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        dst_val = self._get_operand_value(dst)
        src_val = self._get_operand_value(src)
        
        # 64비트 결과와 오버플로우 체크
        result_full = dst_val + src_val
        result = result_full & 0xFFFFFFFFFFFFFFFF
        
        # CF 플래그: 64비트 오버플로우 발생 시 설정
        self.vm_state.flags['CF'] = (result_full > 0xFFFFFFFFFFFFFFFF)
        # ZF와 SF 플래그 설정
        self.vm_state.flags['ZF'] = (result == 0)
        self.vm_state.flags['SF'] = (result & 0x8000000000000000) != 0
        
        self._set_operand_value(dst, result)
        
        # 플래그 상태 표시
        flag_str = []
        if self.vm_state.flags['ZF']: flag_str.append('ZF')
        if self.vm_state.flags['SF']: flag_str.append('SF')
        if self.vm_state.flags['CF']: flag_str.append('CF')
        
        flag_info = f" ({', '.join(flag_str)})" if flag_str else ""
        
        # 스택 포인터 특별 처리
        if dst.lower() == 'rsp':
            self.output.write(f"        → rsp = 0x{dst_val:x} + 0x{src_val:x} = 0x{result:x}{flag_info}")
        else:
            self.output.write(f"        → {dst} = 0x{dst_val:x} + 0x{src_val:x} = 0x{result:x}{flag_info}")
        return None

    def _simulate_sub(self, op_str: str):
        """SUB 명령어 시뮬레이션"""
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        dst_val = self._get_operand_value(dst)
        src_val = self._get_operand_value(src)
        result = (dst_val - src_val) & 0xFFFFFFFFFFFFFFFF
        
        # 플래그 설정
        self.vm_state.flags['ZF'] = (result == 0)
        self.vm_state.flags['SF'] = (result & 0x8000000000000000) != 0
        # CF 플래그: dst < src (부호 없는 비교)일 때 설정 (언더플로우)
        self.vm_state.flags['CF'] = (dst_val < src_val)
        
        self._set_operand_value(dst, result)
        
        # 플래그 상태 표시
        flag_str = []
        if self.vm_state.flags['ZF']: flag_str.append('ZF')
        if self.vm_state.flags['SF']: flag_str.append('SF')
        if self.vm_state.flags['CF']: flag_str.append('CF')
        
        flag_info = f" ({', '.join(flag_str)})" if flag_str else ""
        
        # 스택 포인터 특별 처리
        if dst.lower() == 'rsp':
            self.output.write(f"        → rsp = 0x{dst_val:x} - 0x{src_val:x} = 0x{result:x}{flag_info}")
        else:
            self.output.write(f"        → {dst} = 0x{dst_val:x} - 0x{src_val:x} = 0x{result:x}{flag_info}")
        return None

    def _simulate_xor(self, op_str: str):
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        dst_val = self._get_operand_value(dst)
        src_val = self._get_operand_value(src)
        result = (dst_val ^ src_val) & 0xFFFFFFFFFFFFFFFF
        
        # 플래그 설정 (XOR은 CF와 OF를 0으로 클리어)
        self.vm_state.flags['ZF'] = (result == 0)
        self.vm_state.flags['SF'] = (result & 0x8000000000000000) != 0
        self.vm_state.flags['CF'] = False
        self.vm_state.flags['OF'] = False
        # 패리티 플래그 계산 (하위 8비트의 1의 개수가 짝수면 PF=1)
        self.vm_state.flags['PF'] = (bin(result & 0xFF).count('1') % 2) == 0
        
        self._set_operand_value(dst, result)
        
        # 플래그 상태 표시
        flag_str = []
        if self.vm_state.flags['ZF']: flag_str.append('ZF')
        if self.vm_state.flags['SF']: flag_str.append('SF')
        if self.vm_state.flags['PF']: flag_str.append('PF')
        
        flag_info = f" ({', '.join(flag_str)})" if flag_str else ""
        self.output.write(f"        → {dst} = 0x{dst_val:x} ^ 0x{src_val:x} = 0x{result:x}{flag_info}")
        return None

    def _simulate_and(self, op_str: str):
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        dst_val = self._get_operand_value(dst)
        src_val = self._get_operand_value(src)
        result = (dst_val & src_val) & 0xFFFFFFFFFFFFFFFF
        
        # 플래그 설정 (AND는 CF와 OF를 0으로 클리어)
        self.vm_state.flags['ZF'] = (result == 0)
        self.vm_state.flags['SF'] = (result & 0x8000000000000000) != 0
        self.vm_state.flags['CF'] = False
        self.vm_state.flags['OF'] = False
        # 패리티 플래그 계산
        self.vm_state.flags['PF'] = (bin(result & 0xFF).count('1') % 2) == 0
        
        self._set_operand_value(dst, result)
        
        # 플래그 상태 표시
        flag_str = []
        if self.vm_state.flags['ZF']: flag_str.append('ZF')
        if self.vm_state.flags['SF']: flag_str.append('SF')
        if self.vm_state.flags['PF']: flag_str.append('PF')
        
        flag_info = f" ({', '.join(flag_str)})" if flag_str else ""
        self.output.write(f"        → {dst} = 0x{dst_val:x} & 0x{src_val:x} = 0x{result:x}{flag_info}")
        return None

    def _simulate_or(self, op_str: str):
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        dst_val = self._get_operand_value(dst)
        src_val = self._get_operand_value(src)
        result = (dst_val | src_val) & 0xFFFFFFFFFFFFFFFF
        
        # 플래그 설정 (OR은 CF와 OF를 0으로 클리어)
        self.vm_state.flags['ZF'] = (result == 0)
        self.vm_state.flags['SF'] = (result & 0x8000000000000000) != 0
        self.vm_state.flags['CF'] = False
        self.vm_state.flags['OF'] = False
        # 패리티 플래그 계산
        self.vm_state.flags['PF'] = (bin(result & 0xFF).count('1') % 2) == 0
        
        self._set_operand_value(dst, result)
        
        # 플래그 상태 표시
        flag_str = []
        if self.vm_state.flags['ZF']: flag_str.append('ZF')
        if self.vm_state.flags['SF']: flag_str.append('SF')
        if self.vm_state.flags['PF']: flag_str.append('PF')
        
        flag_info = f" ({', '.join(flag_str)})" if flag_str else ""
        self.output.write(f"        → {dst} = 0x{dst_val:x} | 0x{src_val:x} = 0x{result:x}{flag_info}")
        return None

    def _simulate_shl(self, op_str: str):
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        dst_val = self._get_operand_value(dst)
        src_val = self._get_operand_value(src)
        result = (dst_val << src_val) & 0xFFFFFFFFFFFFFFFF
        
        # 플래그 설정
        self.vm_state.flags['ZF'] = (result == 0)
        self.vm_state.flags['SF'] = (result & 0x8000000000000000) != 0
        # CF: 마지막에 시프트 아웃된 비트
        if src_val > 0 and src_val <= 64:
            self.vm_state.flags['CF'] = bool(dst_val & (1 << (64 - src_val)))
        # 패리티 플래그 계산
        self.vm_state.flags['PF'] = (bin(result & 0xFF).count('1') % 2) == 0
        
        self._set_operand_value(dst, result)
        
        # 플래그 상태 표시
        flag_str = []
        if self.vm_state.flags['ZF']: flag_str.append('ZF')
        if self.vm_state.flags['SF']: flag_str.append('SF')
        if self.vm_state.flags['CF']: flag_str.append('CF')
        if self.vm_state.flags['PF']: flag_str.append('PF')
        
        flag_info = f" ({', '.join(flag_str)})" if flag_str else ""
        self.output.write(f"        → {dst} = 0x{dst_val:x} << 0x{src_val:x} = 0x{result:x}{flag_info}")
        return None

    def _simulate_shr(self, op_str: str):
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        dst_val = self._get_operand_value(dst)
        src_val = self._get_operand_value(src)
        result = (dst_val >> src_val) & 0xFFFFFFFFFFFFFFFF
        
        # 플래그 설정
        self.vm_state.flags['ZF'] = (result == 0)
        self.vm_state.flags['SF'] = (result & 0x8000000000000000) != 0
        # CF: 마지막에 시프트 아웃된 비트
        if src_val > 0:
            self.vm_state.flags['CF'] = bool(dst_val & (1 << (src_val - 1)))
        # 패리티 플래그 계산
        self.vm_state.flags['PF'] = (bin(result & 0xFF).count('1') % 2) == 0
        
        self._set_operand_value(dst, result)
        
        # 플래그 상태 표시
        flag_str = []
        if self.vm_state.flags['ZF']: flag_str.append('ZF')
        if self.vm_state.flags['SF']: flag_str.append('SF')
        if self.vm_state.flags['CF']: flag_str.append('CF')
        if self.vm_state.flags['PF']: flag_str.append('PF')
        
        flag_info = f" ({', '.join(flag_str)})" if flag_str else ""
        self.output.write(f"        → {dst} = 0x{dst_val:x} >> 0x{src_val:x} = 0x{result:x}{flag_info}")
        return None

    def _simulate_cmp(self, op_str: str):
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        dst_val = self._get_operand_value(dst)
        src_val = self._get_operand_value(src)
        result = (dst_val - src_val) & 0xFFFFFFFFFFFFFFFF
        
        # 플래그 설정
        self.vm_state.flags['ZF'] = (result == 0)
        self.vm_state.flags['SF'] = (result & 0x8000000000000000) != 0
        # CF 플래그: dst < src (부호 없는 비교)일 때 설정
        self.vm_state.flags['CF'] = (dst_val < src_val)
        
        # 플래그 상태 표시
        flag_str = []
        if self.vm_state.flags['ZF']: flag_str.append('ZF')
        if self.vm_state.flags['SF']: flag_str.append('SF')
        if self.vm_state.flags['CF']: flag_str.append('CF')
        
        flag_info = f" ({', '.join(flag_str)})" if flag_str else ""
        self.output.write(f"        → {dst} - {src} = 0x{result:x}{flag_info}")
        return None

    def _simulate_test(self, op_str: str):
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        dst_val = self._get_operand_value(dst)
        src_val = self._get_operand_value(src)
        result = (dst_val & src_val) & 0xFFFFFFFFFFFFFFFF
        
        # 플래그 설정
        self.vm_state.flags['ZF'] = (result == 0)
        self.vm_state.flags['SF'] = (result & 0x8000000000000000) != 0
        # TEST 명령어는 CF를 항상 0으로 설정
        self.vm_state.flags['CF'] = False
        
        # 플래그 상태 표시
        flag_str = []
        if self.vm_state.flags['ZF']: flag_str.append('ZF')
        if self.vm_state.flags['SF']: flag_str.append('SF')
        if self.vm_state.flags['CF']: flag_str.append('CF')
        
        flag_info = f" ({', '.join(flag_str)})" if flag_str else ""
        self.output.write(f"        → {dst} & {src} = 0x{result:x}{flag_info}")
        return None

    def _track_jump(self, target_address: int) -> str:
        """점프 횟수를 추적하고 방문 정보를 반환합니다"""
        if target_address in self.jump_counts:
            self.jump_counts[target_address] += 1
            visit_info = f"(#{self.jump_counts[target_address]}번째 방문)"
        else:
            self.jump_counts[target_address] = 1
            visit_info = "(첫 방문)"
        return visit_info

    def _simulate_je(self, op_str: str):
        """JE (Jump if Equal) - ZF가 설정되어 있으면 점프"""
        if self.vm_state.flags['ZF']:
            if op_str.startswith('0x'):
                target = int(op_str, 16)
                self.output.write(f"        → 조건 점프 실행 (ZF=1): 0x{target:x} {self._track_jump(target)}")
                return target
            else:
                self.output.write(f"        → 지원하지 않는 점프 대상: {op_str}")
                return None
        else:
            self.output.write(f"        → 조건 점프 건너뜀 (ZF=0)")
            return None

    def _simulate_jns(self, op_str: str):
        """JNS (Jump if Not Sign) - SF가 설정되어 있지 않으면 점프"""
        if not self.vm_state.flags['SF']:
            if op_str.startswith('0x'):
                target = int(op_str, 16)
                self.output.write(f"        → 조건 점프 실행 (SF=0): 0x{target:x} {self._track_jump(target)}")
                return target
            else:
                self.output.write(f"        → 지원하지 않는 점프 대상: {op_str}")
                return None
        else:
            self.output.write(f"        → 조건 점프 건너뜀 (SF=1)")
            return None

    def _simulate_jne(self, op_str: str):
        """JNE (Jump if Not Equal) - ZF가 설정되어 있지 않으면 점프"""
        if not self.vm_state.flags['ZF']:
            if op_str.startswith('0x'):
                target = int(op_str, 16)
                self.output.write(f"        → 조건 점프 실행 (ZF=0): 0x{target:x} {self._track_jump(target)}")
                return target
            else:
                self.output.write(f"        → 지원하지 않는 점프 대상: {op_str}")
                return None
        else:
            self.output.write(f"        → 조건 점프 건너뜀 (ZF=1)")
            return None

    def _simulate_jz(self, op_str: str):
        """JZ (Jump if Zero) - ZF가 설정되어 있으면 점프"""
        if self.vm_state.flags['ZF']:
            if op_str.startswith('0x'):
                target = int(op_str, 16)
                self.output.write(f"        → 조건 점프 실행 (ZF=1): 0x{target:x} {self._track_jump(target)}")
                return target
            else:
                self.output.write(f"        → 지원하지 않는 점프 대상: {op_str}")
                return None
        else:
            self.output.write(f"        → 조건 점프 건너뜀 (ZF=0)")
            return None

    def _simulate_jnz(self, op_str: str):
        """JNZ (Jump if Not Zero) - ZF가 설정되어 있지 않으면 점프"""
        if not self.vm_state.flags['ZF']:
            if op_str.startswith('0x'):
                target = int(op_str, 16)
                self.output.write(f"        → 조건 점프 실행 (ZF=0): 0x{target:x} {self._track_jump(target)}")
                return target
            else:
                self.output.write(f"        → 지원하지 않는 점프 대상: {op_str}")
                return None
        else:
            self.output.write(f"        → 조건 점프 건너뜀 (ZF=1)")
            return None

    def _simulate_jmp(self, op_str: str):
        if op_str.startswith('0x'):
            target = int(op_str, 16)
            self.output.write(f"        → 점프: 0x{target:x} {self._track_jump(target)}")
            return target
        elif op_str in self.vm_state.registers:
            target = self.vm_state.get_register(op_str)
            self.output.write(f"        → 간접 점프: {op_str} (0x{target:x}) {self._track_jump(target)}")
            return target
        elif 'ptr [' in op_str:
            # 메모리 참조 점프: jmp qword ptr [rax]
            self.output.write(f"        🔍 [메모리 점프] {op_str} 분석 중...")
            target_value = self._get_operand_value(op_str)
            if target_value is not None:
                self.output.write(f"        → 메모리 점프: {op_str} → 0x{target_value:x} {self._track_jump(target_value)}")
                return target_value
            else:
                self.output.write(f"        ❌ [점프 실패] 메모리 값 읽기 실패: {op_str}")
                return None
        else:
            self.output.write(f"        ❓ [알 수 없는 점프] {op_str}")
            return None

    def _simulate_jb(self, op_str: str):
        """JB (Jump if Below) - CF가 설정되어 있으면 점프"""
        if self.vm_state.flags['CF']:
            if op_str.startswith('0x'):
                target = int(op_str, 16)
                self.output.write(f"        → 조건 점프 실행 (CF=1): 0x{target:x} {self._track_jump(target)}")
                return target
            else:
                self.output.write(f"        → 조건 점프 건너뜀 (CF=0)")
                return None
        else:
            self.output.write(f"        → 조건 점프 건너뜀 (CF=0)")
            return None

    def _simulate_push(self, op_str: str):
        """PUSH 명령어 시뮬레이션 - 스택에 값 푸시"""
        src_val = self._get_operand_value(op_str.strip())
        
        # RSP 감소 후 메모리에 값 저장
        rsp = self.vm_state.get_register('rsp')
        rsp -= 8
        self.vm_state.set_register('rsp', rsp)
        self.vm_state.set_memory(rsp, src_val)
        
        self.output.write(f"        → push {op_str} (0x{src_val:x}) to [0x{rsp:x}]")
        return None

    def _simulate_pushfq(self, op_str: str):
        """PUSHFQ 명령어 시뮬레이션 - 플래그 레지스터 푸시"""
        # 더 완전한 RFLAGS 값 계산
        flags_val = 0x202  # 기본값: IF=1 (Interrupt Flag) + 예약 비트
        
        # 주요 플래그들 설정
        if self.vm_state.flags.get('CF', False): flags_val |= 0x1     # Carry Flag
        if self.vm_state.flags.get('PF', False): flags_val |= 0x4     # Parity Flag  
        if self.vm_state.flags.get('AF', False): flags_val |= 0x10    # Auxiliary Flag
        if self.vm_state.flags.get('ZF', False): flags_val |= 0x40    # Zero Flag
        if self.vm_state.flags.get('SF', False): flags_val |= 0x80    # Sign Flag
        if self.vm_state.flags.get('TF', False): flags_val |= 0x100   # Trap Flag
        if self.vm_state.flags.get('IF', True):  flags_val |= 0x200   # Interrupt Flag (기본 true)
        if self.vm_state.flags.get('DF', False): flags_val |= 0x400   # Direction Flag
        if self.vm_state.flags.get('OF', False): flags_val |= 0x800   # Overflow Flag
        
        # 디버깅을 위한 플래그 상태 출력
        active_flags = []
        if flags_val & 0x1:   active_flags.append('CF')
        if flags_val & 0x4:   active_flags.append('PF') 
        if flags_val & 0x10:  active_flags.append('AF')
        if flags_val & 0x40:  active_flags.append('ZF')
        if flags_val & 0x80:  active_flags.append('SF')
        if flags_val & 0x100: active_flags.append('TF')
        if flags_val & 0x200: active_flags.append('IF')
        if flags_val & 0x400: active_flags.append('DF')
        if flags_val & 0x800: active_flags.append('OF')
        
        # RSP 감소 후 플래그 저장
        rsp = self.vm_state.get_register('rsp')
        rsp -= 8
        self.vm_state.set_register('rsp', rsp)
        self.vm_state.set_memory(rsp, flags_val)
        
        self.output.write(f"        → pushfq (0x{flags_val:x}) to [0x{rsp:x}]")
        if active_flags:
            self.output.write(f"        🏁 [플래그 상태] {', '.join(active_flags)}")
        return None

    def _simulate_pop(self, op_str: str):
        """POP 명령어 시뮬레이션 - 스택에서 값 팝"""
        # 스택에서 값 읽기
        rsp = self.vm_state.get_register('rsp')
        val, _ = self.vm_state.get_memory(rsp)
        
        # 대상 오퍼랜드에 값 저장
        self._set_operand_value(op_str.strip(), val)
        
        # RSP 증가
        rsp += 8
        self.vm_state.set_register('rsp', rsp)
        
        self.output.write(f"        → pop {op_str} (0x{val:x}) from [0x{rsp-8:x}]")
        return None

    def _simulate_popfq(self, op_str: str):
        """POPFQ 명령어 시뮬레이션 - 스택에서 플래그 팝"""
        # 스택에서 플래그 값 읽기
        rsp = self.vm_state.get_register('rsp')
        flags_val, _ = self.vm_state.get_memory(rsp)
        
        # 플래그 레지스터 설정
        self.vm_state.flags['ZF'] = bool(flags_val & 0x40)
        self.vm_state.flags['SF'] = bool(flags_val & 0x80)
        self.vm_state.flags['CF'] = bool(flags_val & 0x1)
        
        # RSP 증가
        rsp += 8
        self.vm_state.set_register('rsp', rsp)
        
        # 디버그 정보 출력
        flag_str = []
        if self.vm_state.flags['ZF']: flag_str.append('ZF')
        if self.vm_state.flags['SF']: flag_str.append('SF')
        if self.vm_state.flags['CF']: flag_str.append('CF')
        
        self.output.write(f"        → popfq (0x{flags_val:x}) from [0x{rsp-8:x}]")
        if flag_str:
            self.output.write(f"        → 설정된 플래그: {', '.join(flag_str)}")
        return None

    def _simulate_xchg(self, op_str: str):
        """XCHG 명령어 시뮬레이션 - 두 오퍼랜드 값 교환"""
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        dst_val = self._get_operand_value(dst)
        src_val = self._get_operand_value(src)
        
        # 값 교환
        self._set_operand_value(dst, src_val)
        self._set_operand_value(src, dst_val)
        
        self.output.write(f"        → xchg {dst}, {src} (0x{dst_val:x} ↔ 0x{src_val:x})")
        return None

    def _simulate_ret(self, op_str: str):
        """RET 명령어 시뮬레이션 - VM 스택 프레임 분석 포함"""
        # 스택 조정값 파싱
        stack_adjust = 0
        if op_str.strip():
            try:
                stack_adjust = int(op_str.strip(), 16) if op_str.strip().startswith('0x') else int(op_str.strip())
            except ValueError:
                self.output.write(f"        [RET 경고] 스택 조정값 파싱 실패: {op_str}")
        
        # 현재 스택 프레임 분석
        rsp = self.vm_state.get_register('rsp')
        rbp = self.vm_state.get_register('rbp')
        
        self.output.write(f"        📊 [스택 프레임 분석] RSP=0x{rsp:x}, RBP=0x{rbp:x}")
        
        # 스택 프레임 구조 분석
        frame_info = self._analyze_stack_frame(rsp, rbp)
        
        # 스택에서 반환 주소 읽기
        ret_addr, is_estimated = self.vm_state.get_memory(rsp)
        
        # RSP 조정 (반환 주소 pop + 추가 조정)
        new_rsp = rsp + 8 + stack_adjust
        self.vm_state.set_register('rsp', new_rsp)
        
        self.output.write(f"        → ret {stack_adjust} (0x{ret_addr:x}) + stack adjust 0x{stack_adjust:x}")
        self.output.write(f"        📈 [스택 업데이트] RSP: 0x{rsp:x} → 0x{new_rsp:x}")
        
        # VM 환경에서의 RET 처리
        if ret_addr == 0 or ret_addr is None:
            self.output.write(f"        🔍 [VM RET] 반환 주소 0x0 감지")
            
            # 스택 프레임 기반 VM 상태 분석
            vm_exit_reason = self._determine_vm_exit_reason(frame_info, rsp, rbp)
            self.output.write(f"        💡 [VM 분석] {vm_exit_reason}")
            
            # VM 컨텍스트에서 대안적 처리 시도
            # 1. 스택 프레임 기반 다음 주소 찾기
            possible_next = self._find_vm_next_from_frame(frame_info)
            if possible_next:
                self.output.write(f"        🎯 [VM 프레임] 다음 실행 주소: 0x{possible_next:x} {self._track_jump(possible_next)}")
                return possible_next
            
            # 2. VM 상태에서 다음 실행 주소 찾기
            possible_next = self._find_vm_next_address()
            if possible_next:
                self.output.write(f"        🎯 [VM 레지스터] 다음 실행 주소: 0x{possible_next:x} {self._track_jump(possible_next)}")
                return possible_next
            
            # 3. 스택의 다른 위치에서 주소 찾기
            alt_addr = self._find_alternative_return_address(rsp)
            if alt_addr:
                self.output.write(f"        🔄 [VM 스택 검색] 대체 실행 주소: 0x{alt_addr:x} {self._track_jump(alt_addr)}")
                return alt_addr
            
            # 4. 그래도 없으면 분석 종료
            self.output.write(f"        🛑 [VM 종료] 더 이상 실행할 주소를 찾을 수 없음")
            self.output.write(f"        📊 스택 프레임 분석 완료 - VM 정상 종료")
            return None
        else:
            # 유효한 반환 주소가 있는 경우
            if is_estimated:
                self.output.write(f"        ⚠️  [RET 경고] 추정된 반환 주소: 0x{ret_addr:x}")
            
            # 주소 유효성 검사
            if not self.disasm_engine.is_address_valid(ret_addr):
                self.output.write(f"        ❌ [RET 오류] 잘못된 주소 범위: 0x{ret_addr:x}")
                return None
            
            # 반환 주소 타입 분석
            ret_type = self._analyze_return_address_type(ret_addr, frame_info)
            self.output.write(f"        ✅ [RET 성공] {ret_type}: 0x{ret_addr:x} {self._track_jump(ret_addr)}")
            return ret_addr

    def _find_vm_next_address(self) -> int:
        """VM 상태에서 다음 실행 주소를 추정합니다"""
        self.output.write(f"        🔍 [VM 레지스터 분석] 다음 실행 주소 탐색")
        
        # VM의 일반적인 패턴들 확인
        # 1. 레지스터에 저장된 코드 포인터 확인 (우선순위 순)
        code_regs = [
            ('r14', 'VM 코드 포인터'), ('r15', 'VM 핸들러 포인터'), 
            ('r13', 'VM 디스패처'), ('r12', 'VM 스택 포인터'),
            ('rbx', 'VM 베이스'), ('rsi', 'VM 소스'), ('rdi', 'VM 목적지'),
            ('r8', 'VM 임시1'), ('r9', 'VM 임시2'), ('r10', 'VM 임시3'), ('r11', 'VM 임시4')
        ]
        
        for reg, desc in code_regs:
            addr = self.vm_state.get_register(reg)
            if addr and addr != 0 and self.disasm_engine.is_address_valid(addr):
                self.output.write(f"        🎯 [VM 힌트] {reg}({desc})에서 유효한 주소: 0x{addr:x}")
                
                # 주소가 실제 명령어인지 확인
                if self._is_valid_instruction_address(addr):
                    self.output.write(f"        ✅ [확인됨] 0x{addr:x}는 유효한 명령어 주소")
                    return addr
                else:
                    self.output.write(f"        ⚠️  [주의] 0x{addr:x}는 데이터일 수 있음")
        
        # 2. 레지스터 값들을 조합해서 주소 계산 시도
        combined_addr = self._try_register_combinations()
        if combined_addr:
            return combined_addr
        
        # 3. VM 컨텍스트 추정 (일반적인 VM 패턴 기반)
        context_addr = self._estimate_vm_context()
        if context_addr:
            return context_addr
        
        return None

    def _is_valid_instruction_address(self, addr: int) -> bool:
        """주소가 유효한 명령어를 가리키는지 확인"""
        try:
            instructions = self.disasm_engine.disassemble_at(addr, 16)
            return len(instructions) > 0
        except:
            return False

    def _try_register_combinations(self) -> int:
        """레지스터 값들을 조합해서 주소 계산"""
        self.output.write(f"        🧮 [조합 계산] 레지스터 값 조합 시도")
        
        # 일반적인 VM 주소 계산 패턴들
        patterns = [
            # (base_reg, offset_reg, description)
            ('rbp', 'rax', 'RBP + RAX'),
            ('rbp', 'rcx', 'RBP + RCX'), 
            ('rsi', 'rax', 'RSI + RAX'),
            ('rdi', 'rax', 'RDI + RAX'),
            ('r14', 'rax', 'R14 + RAX'),
            ('r15', 'rax', 'R15 + RAX'),
        ]
        
        for base_reg, offset_reg, desc in patterns:
            base = self.vm_state.get_register(base_reg)
            offset = self.vm_state.get_register(offset_reg)
            
            if base and offset:
                calculated = (base + offset) & 0xFFFFFFFFFFFFFFFF
                if self.disasm_engine.is_address_valid(calculated) and self._is_valid_instruction_address(calculated):
                    self.output.write(f"        🎯 [조합 성공] {desc}: 0x{calculated:x}")
                    return calculated
        
        return None

    def _estimate_vm_context(self) -> int:
        """VM 컨텍스트를 기반으로 다음 주소 추정"""
        self.output.write(f"        🎭 [VM 컨텍스트] 실행 패턴 분석")
        
        # 점프 히스토리에서 패턴 찾기
        if hasattr(self, 'jump_counts') and self.jump_counts:
            # 가장 자주 방문한 주소들 중에서 후보 찾기
            frequent_addrs = sorted(self.jump_counts.items(), key=lambda x: x[1], reverse=True)
            
            for addr, count in frequent_addrs[:5]:  # 상위 5개만 확인
                if self.disasm_engine.is_address_valid(addr):
                    # 주변 주소들도 확인 (VM 핸들러는 보통 근처에 있음)
                    for offset in [0, 8, 16, 32, 64]:
                        candidate = addr + offset
                        if (self.disasm_engine.is_address_valid(candidate) and 
                            self._is_valid_instruction_address(candidate)):
                            self.output.write(f"        🎯 [패턴 기반] 0x{candidate:x} (빈도 기반)")
                            return candidate
        
        return None

    def _analyze_stack_frame(self, rsp: int, rbp: int) -> dict:
        """스택 프레임 구조를 분석합니다"""
        frame_info = {
            'rsp': rsp,
            'rbp': rbp,
            'frame_size': 0,
            'saved_rbp': None,
            'return_addresses': [],
            'local_vars': {},
            'is_vm_frame': False,
            'is_vm_flat_stack': False
        }
        
        # RBP=0 특별 처리 (VM 플랫 스택 구조)
        if rbp == 0:
            self.output.write(f"        🔧 [VM 특성] RBP=0 감지 - VM 플랫 스택 구조")
            frame_info['is_vm_flat_stack'] = True
            frame_info['frame_size'] = 128  # VM 스택 탐색 범위 확장
        else:
            # 프레임 크기 계산 (표준 구조)
            if rbp > rsp:
                frame_info['frame_size'] = rbp - rsp
                self.output.write(f"        📐 [프레임 크기] {frame_info['frame_size']} 바이트")
            
            # 저장된 RBP 읽기 (표준 프레임 구조)
            saved_rbp, _ = self.vm_state.get_memory(rbp)
            frame_info['saved_rbp'] = saved_rbp
            self.output.write(f"        💾 [저장된 RBP] 0x{saved_rbp:x}")
        
        # 스택의 여러 위치에서 잠재적 반환 주소들 수집
        search_range = min(128, max(64, frame_info['frame_size']))  # 범위 확장
        self.output.write(f"        🔍 [스택 탐색] {search_range} 바이트 범위 검색")
        
        for offset in range(0, search_range, 8):
            addr = rsp + offset
            value, _ = self.vm_state.get_memory(addr)
            if value and self.disasm_engine.is_address_valid(value):
                frame_info['return_addresses'].append((addr, value))
                offset_info = f"+{offset}" if offset > 0 else ""
                self.output.write(f"        🔗 [잠재적 반환주소] [RSP{offset_info}] 0x{addr:x} = 0x{value:x}")
        
        # VM 특성 감지
        frame_info['is_vm_frame'] = self._detect_vm_frame_characteristics(frame_info)
        
        return frame_info

    def _determine_vm_exit_reason(self, frame_info: dict, rsp: int, rbp: int) -> str:
        """VM 종료 이유를 분석합니다"""
        reasons = []
        
        # 스택 프레임 크기 분석
        if frame_info['frame_size'] == 0:
            reasons.append("빈 스택 프레임 - VM 초기/종료 상태")
        elif frame_info['frame_size'] < 32:
            reasons.append("작은 프레임 - VM 핸들러 종료")
        else:
            reasons.append("큰 프레임 - VM 디스패처 종료")
        
        # 저장된 반환 주소들 분석
        if not frame_info['return_addresses']:
            reasons.append("반환 주소 없음 - VM 최상위 종료")
        elif len(frame_info['return_addresses']) == 1:
            reasons.append("단일 반환 주소 - 핸들러→디스패처")
        else:
            reasons.append("다중 반환 주소 - 중첩 호출 구조")
        
        # VM 특성 분석
        if frame_info['is_vm_frame']:
            reasons.append("VM 특성 감지됨")
        
        return " | ".join(reasons)

    def _find_vm_next_from_frame(self, frame_info: dict) -> int:
        """스택 프레임에서 다음 실행 주소를 찾습니다"""
        # 잠재적 반환 주소들 중에서 유효한 것 선택
        for addr, value in frame_info['return_addresses']:
            if value != 0 and self.disasm_engine.is_address_valid(value):
                self.output.write(f"        🎯 [프레임 힌트] 0x{addr:x}에서 발견: 0x{value:x}")
                return value
        
        # 저장된 RBP를 통한 상위 프레임 탐색
        if frame_info['saved_rbp'] and frame_info['saved_rbp'] != 0:
            parent_ret_addr, _ = self.vm_state.get_memory(frame_info['saved_rbp'] + 8)
            if parent_ret_addr and self.disasm_engine.is_address_valid(parent_ret_addr):
                self.output.write(f"        🎯 [상위 프레임] 0x{parent_ret_addr:x}")
                return parent_ret_addr
        
        return None

    def _analyze_return_address_type(self, ret_addr: int, frame_info: dict) -> str:
        """반환 주소의 타입을 분석합니다"""
        # 주소 범위 분석
        if ret_addr < self.disasm_engine.base_address:
            return "시스템 라이브러리 반환"
        elif ret_addr >= self.disasm_engine.base_address + len(self.disasm_engine.code_bytes):
            return "외부 모듈 반환"
        
        # VM 내부 주소 분석
        offset = ret_addr - self.disasm_engine.base_address
        
        # 대략적인 VM 구조 추정
        if offset < 0x1000:
            return "VM 디스패처 복귀"
        elif offset < 0x10000:
            return "VM 핸들러 체이닝"
        else:
            return "VM 내부 함수 반환"

    def _detect_vm_frame_characteristics(self, frame_info: dict) -> bool:
        """VM 프레임의 특성을 감지합니다"""
        vm_indicators = 0
        
        # 특정 크기 패턴 (VM은 보통 고정 크기 프레임 사용)
        if frame_info['frame_size'] in [32, 48, 64, 128]:
            vm_indicators += 1
        
        # 다중 반환 주소 (VM 핸들러 체이닝)
        if len(frame_info['return_addresses']) > 2:
            vm_indicators += 1
        
        # RBP와 RSP의 특정 관계
        if frame_info['rbp'] and frame_info['rsp']:
            diff = frame_info['rbp'] - frame_info['rsp']
            if diff in [24, 32, 40, 48]:  # VM에서 자주 사용되는 프레임 크기
                vm_indicators += 1
        
        return vm_indicators >= 2

    def _find_alternative_return_address(self, current_rsp: int) -> int:
        """스택의 다른 위치에서 유효한 주소를 찾습니다"""
        # 스택의 인근 위치들을 확인 (8바이트씩 증가)
        for offset in [8, 16, 24, 32, 40]:
            alt_rsp = current_rsp + offset
            addr, _ = self.vm_state.get_memory(alt_rsp)
            if addr and addr != 0 and self.disasm_engine.is_address_valid(addr):
                self.output.write(f"        🔍 [스택 검색] 0x{alt_rsp:x}에서 유효한 주소: 0x{addr:x} {self._track_jump(addr)}")
                return addr
        
        return None

    def _simulate_neg(self, op_str: str):
        parts = [p.strip() for p in op_str.split(',')]
        dst = parts[0]
        
        dst_val = self._get_operand_value(dst)
        result = -dst_val & 0xFFFFFFFFFFFFFFFF
        
        self._set_operand_value(dst, result)
        self.output.write(f"        → {dst} = -0x{dst_val:x} = 0x{result:x}")
        return None

    def _simulate_lock_sub(self, op_str: str):
        """LOCK SUB 명령어 시뮬레이션 - 원자적 감산"""
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        dst_val = self._get_operand_value(dst)
        src_val = self._get_operand_value(src)
        result = (dst_val - src_val) & 0xFFFFFFFFFFFFFFFF
        
        self._set_operand_value(dst, result)
        self.output.write(f"        → lock {dst} = 0x{dst_val:x} - 0x{src_val:x} = 0x{result:x}")
        return None

    def _get_operand_value(self, operand: str) -> int:
        operand = operand.strip()
        if operand in self.vm_state.registers:
            return self.vm_state.get_register(operand)
        elif self._is_32bit_register(operand):
            # 32비트 레지스터의 경우 하위 32비트만 반환
            reg_64 = self._map_32bit_to_64bit(operand)
            return self.vm_state.get_register(reg_64) & 0xFFFFFFFF
        elif self._is_16bit_register(operand):
            # 16비트 레지스터의 경우 하위 16비트만 반환
            reg_64 = self._map_16bit_to_64bit(operand)
            return self.vm_state.get_register(reg_64) & 0xFFFF
        elif self._is_8bit_register(operand):
            # 8비트 레지스터 값 읽기
            reg_64 = self._map_8bit_to_64bit(operand)
            reg_value = self.vm_state.get_register(reg_64)
            if operand in ['ah', 'bh', 'ch', 'dh']:
                # 상위 8비트 레지스터 (비트 8-15)
                return (reg_value >> 8) & 0xFF
            else:
                # 하위 8비트 레지스터 (비트 0-7)
                return reg_value & 0xFF
        elif operand.startswith('0x'):
            return int(operand, 16)
        elif operand.isdigit():
            return int(operand)
        elif 'ptr [' in operand:
            # 메모리 참조 파싱
            address = self._parse_memory_reference(operand)
            if address is not None:
                value, is_estimated = self.vm_state.get_memory(address)
                
                # 추정값 여부를 명확히 표시
                if is_estimated:
                    self.output.write(f"        🔮 [추정값] 0x{address:x} = 0x{value:x} ← L2.bin에서도 찾을 수 없음")
                else:
                    self.output.write(f"        📖 [실제값] 0x{address:x} = 0x{value:x}")
                
                # 메모리 크기에 따른 값 반환
                if 'qword ptr' in operand:
                    return value & 0xFFFFFFFFFFFFFFFF
                elif 'dword ptr' in operand:
                    return value & 0xFFFFFFFF
                elif 'word ptr' in operand:
                    return value & 0xFFFF
                elif 'byte ptr' in operand:
                    return value & 0xFF
                else:
                    # 기본적으로 qword로 처리
                    return value
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
        elif self._is_16bit_register(operand):
            # 16비트 레지스터의 경우 하위 16비트만 변경, 상위 48비트는 보존
            reg_64 = self._map_16bit_to_64bit(operand)
            current_value = self.vm_state.get_register(reg_64)
            new_value = (current_value & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF)
            self.vm_state.set_register(reg_64, new_value)
        elif self._is_8bit_register(operand):
            # 8비트 레지스터의 경우 하위 8비트만 변경, 상위 56비트는 보존
            reg_64 = self._map_8bit_to_64bit(operand)
            current_value = self.vm_state.get_register(reg_64)
            if operand in ['ah', 'bh', 'ch', 'dh']:
                # 상위 8비트 레지스터 (비트 8-15) 변경
                new_value = (current_value & 0xFFFFFFFFFFFF00FF) | ((value & 0xFF) << 8)
            else:
                # 하위 8비트 레지스터 (비트 0-7) 변경
                new_value = (current_value & 0xFFFFFFFFFFFFFF00) | (value & 0xFF)
            self.vm_state.set_register(reg_64, new_value)
        elif 'ptr [' in operand:
            # 메모리 참조 파싱
            address = self._parse_memory_reference(operand)
            if address is not None:
                # 기존 값 확인 (메모리 변화 추적용)
                old_value, _ = self.vm_state.get_memory(address)
                
                # 메모리 값 설정
                self.vm_state.set_memory(address, value)
                
                # 메모리 변화 추적
                if old_value != value:
                    self._track_memory_change(address, old_value, value)
                
                self.output.write(f"        💾 [메모리 저장] 0x{address:x} ← 0x{value:x}")

    def _is_32bit_register(self, operand: str) -> bool:
        """32비트 레지스터인지 확인"""
        return operand in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp',
                          'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']

    def _is_16bit_register(self, operand: str) -> bool:
        """16비트 레지스터인지 확인"""
        return operand in ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'sp', 'bp',
                          'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w']

    def _is_8bit_register(self, operand: str) -> bool:
        """8비트 레지스터인지 확인"""
        return operand in ['al', 'bl', 'cl', 'dl', 'sil', 'dil', 'spl', 'bpl',
                          'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b',
                          'ah', 'bh', 'ch', 'dh']  # 상위 8비트 레지스터도 포함

    def _map_32bit_to_64bit(self, reg_32: str) -> str:
        """32비트 레지스터를 64비트로 매핑"""
        mapping = {
            'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
            'esi': 'rsi', 'edi': 'rdi', 'esp': 'rsp', 'ebp': 'rbp',
            'r8d': 'r8', 'r9d': 'r9', 'r10d': 'r10', 'r11d': 'r11',
            'r12d': 'r12', 'r13d': 'r13', 'r14d': 'r14', 'r15d': 'r15'
        }
        return mapping.get(reg_32, reg_32)

    def _map_16bit_to_64bit(self, reg_16: str) -> str:
        """16비트 레지스터를 64비트로 매핑"""
        mapping = {
            'ax': 'rax', 'bx': 'rbx', 'cx': 'rcx', 'dx': 'rdx',
            'si': 'rsi', 'di': 'rdi', 'sp': 'rsp', 'bp': 'rbp',
            'r8w': 'r8', 'r9w': 'r9', 'r10w': 'r10', 'r11w': 'r11',
            'r12w': 'r12', 'r13w': 'r13', 'r14w': 'r14', 'r15w': 'r15'
        }
        return mapping.get(reg_16, reg_16)

    def _map_8bit_to_64bit(self, reg_8: str) -> str:
        """8비트 레지스터를 64비트로 매핑"""
        mapping = {
            'al': 'rax', 'bl': 'rbx', 'cl': 'rcx', 'dl': 'rdx',
            'sil': 'rsi', 'dil': 'rdi', 'spl': 'rsp', 'bpl': 'rbp',
            'r8b': 'r8', 'r9b': 'r9', 'r10b': 'r10', 'r11b': 'r11',
            'r12b': 'r12', 'r13b': 'r13', 'r14b': 'r14', 'r15b': 'r15',
            # 상위 8비트 레지스터들
            'ah': 'rax', 'bh': 'rbx', 'ch': 'rcx', 'dh': 'rdx'
        }
        return mapping.get(reg_8, reg_8)

    def _parse_memory_reference(self, operand: str) -> int:
        """메모리 참조를 파싱하여 주소를 계산합니다."""
        try:
            # "qword ptr [rax]" → "rax"
            # "dword ptr [rbp + 0xf8]" → "rbp + 0xf8"
            # "word ptr [rsp + rax*2 + 0x20]" → "rsp + rax*2 + 0x20"
            start = operand.find('[') + 1
            end = operand.find(']')
            expr = operand[start:end].strip()
            
            # 복잡한 SIB 형태 파싱: [base + index*scale + displacement]
            # 예: rsp + rax*2 + 0x20
            
            base_addr = 0
            index_addr = 0
            scale = 1
            displacement = 0
            
            # '+' 기준으로 분할하여 각 부분 파싱
            parts = [part.strip() for part in expr.replace('-', '+-').split('+')]
            
            for part in parts:
                part = part.strip()
                if not part:
                    continue
                    
                if '*' in part:
                    # index*scale 형태 파싱
                    index_part, scale_part = part.split('*')
                    index_reg = index_part.strip()
                    scale = int(scale_part.strip())
                    index_addr = self.vm_state.get_register(index_reg) * scale
                    self.output.write(f"        [SIB] index: {index_reg}*{scale} = 0x{index_addr:x}")
                    
                elif part.startswith('0x') or (part.startswith('-0x')):
                    # displacement 파싱
                    displacement = int(part, 16)
                    self.output.write(f"        [SIB] displacement: {part} = 0x{displacement:x}")
                    
                elif part.isdigit() or (part.startswith('-') and part[1:].isdigit()):
                    # 10진수 displacement
                    displacement = int(part)
                    self.output.write(f"        [SIB] displacement: {part} = 0x{displacement:x}")
                    
                elif self._is_displacement(part):
                    # 개선된 displacement 파싱 (공백 처리 포함)
                    displacement = self._parse_displacement(part)
                    self.output.write(f"        [SIB] displacement: {part} = 0x{displacement:x}")
                    
                elif part in self.vm_state.registers:
                    # base register
                    base_addr = self.vm_state.get_register(part)
                    self.output.write(f"        [SIB] base: {part} = 0x{base_addr:x}")
                    
                else:
                    self.output.write(f"        [SIB 경고] 알 수 없는 부분: '{part}'")
            
            final_addr = base_addr + index_addr + displacement
            self.output.write(f"        [SIB] 최종 주소: 0x{base_addr:x} + 0x{index_addr:x} + 0x{displacement:x} = 0x{final_addr:x}")
            return final_addr
            
        except (ValueError, IndexError, KeyError) as e:
            self.output.write(f"        [!] 메모리 참조 파싱 실패: {operand} (오류: {e})")
            return None

    def _is_displacement(self, part: str) -> bool:
        """displacement인지 확인합니다 (공백 처리 포함)"""
        # 공백 제거 후 확인
        clean_part = part.replace(' ', '')
        
        # 16진수 형태: -0x1c, 0x20 등
        if clean_part.startswith('0x') or clean_part.startswith('-0x'):
            return True
            
        # 10진수 형태: -28, 32 등
        if clean_part.isdigit() or (clean_part.startswith('-') and clean_part[1:].isdigit()):
            return True
            
        return False

    def _parse_displacement(self, part: str) -> int:
        """displacement 값을 파싱합니다"""
        # 공백 제거
        clean_part = part.replace(' ', '')
        
        # 16진수 파싱
        if '0x' in clean_part:
            return int(clean_part, 16)
        # 10진수 파싱
        else:
            return int(clean_part)

    def _estimate_vm_purpose(self, changed_regs):
        """VM의 목적을 추정합니다."""
        if not changed_regs:
            self.output.write("  레지스터 변화가 없어 목적 추정 어려움")
            return
        
        # 변화된 레지스터 분석
        has_arithmetic = any(reg in ['rax', 'rdx', 'rcx'] for reg, _, _ in changed_regs)
        has_data_movement = any(reg in ['rsi', 'rdi'] for reg, _, _ in changed_regs)
        has_complex_calc = len(changed_regs) > 5
        
        purposes = []
        if has_arithmetic:
            purposes.append("산술 연산/계산")
        if has_data_movement:
            purposes.append("데이터 이동/복사")
        if has_complex_calc:
            purposes.append("복잡한 알고리즘 실행")
        
        if purposes:
            self.output.write(f"  추정 목적: {', '.join(purposes)}")
        else:
            self.output.write("  목적 불명 - 추가 분석 필요")
        
        # 메모리 패턴 분석
        memory_pattern = self._analyze_memory_pattern()
        if memory_pattern:
            self.output.write(f"  메모리 패턴: {memory_pattern}")

    def _analyze_memory_pattern(self):
        """메모리 접근 패턴을 분석합니다"""
        if not self.memory_changes:
            return "메모리 접근 없음"
        
        addresses = list(self.memory_changes.keys())
        addresses.sort()
        
        # 연속적인 메모리 접근 확인
        gaps = []
        for i in range(1, len(addresses)):
            gap = addresses[i] - addresses[i-1]
            gaps.append(gap)
        
        if not gaps:
            return "단일 메모리 접근"
        elif all(gap <= 8 for gap in gaps):
            return "연속적 메모리 접근 (스택/배열)"
        elif any(gap > 0x1000 for gap in gaps):
            return "분산적 메모리 접근 (포인터 추적)"
        else:
            return "불규칙적 메모리 접근"

    def _simulate_jb(self, op_str: str):
        """JB (Jump if Below) - CF가 설정되어 있으면 점프"""
        if self.vm_state.flags['CF']:
            if op_str.startswith('0x'):
                target = int(op_str, 16)
                self.output.write(f"        → 조건 점프 실행 (CF=1): 0x{target:x} {self._track_jump(target)}")
                return target
            else:
                self.output.write(f"        → 조건 점프 건너뜀 (CF=0)")
                return None
        else:
            self.output.write(f"        → 조건 점프 건너뜀 (CF=0)")
            return None

    def _simulate_call(self, op_str: str):
        """CALL 명령어 시뮬레이션 - 반환 주소를 스택에 push하고 대상 주소로 점프"""
        current_rsp = self.vm_state.get_register('rsp')
        
        # 반환 주소는 현재 명령어의 다음 주소여야 하지만, 
        # 여기서는 0으로 설정 (실제로는 시뮬레이션 루프에서 설정해야 함)
        return_address = 0x0  # 임시값
        
        # 반환 주소를 스택에 push (RSP를 8바이트 감소시키고 값 저장)
        new_rsp = current_rsp - 8
        self.vm_state.set_register('rsp', new_rsp)
        self.vm_state.set_memory(new_rsp, return_address)
        
        # 호출 대상 주소 계산 및 점프
        if op_str.startswith('0x'):
            target = int(op_str, 16)
            visit_info = self._track_jump(target)
            self.output.write(f"        → call 0x{target:x} {visit_info}")
            self.output.write(f"        📞 [CALL] 반환주소 0x{return_address:x}를 스택에 push")
            self.output.write(f"        📞 [CALL] RSP: 0x{current_rsp:x} → 0x{new_rsp:x}")
            return target
        elif op_str in self.vm_state.registers:
            target = self.vm_state.get_register(op_str)
            visit_info = self._track_jump(target)
            self.output.write(f"        → call {op_str} (0x{target:x}) {visit_info}")
            self.output.write(f"        📞 [CALL] 반환주소 0x{return_address:x}를 스택에 push")
            self.output.write(f"        📞 [CALL] RSP: 0x{current_rsp:x} → 0x{new_rsp:x}")
            return target
        else:
            # 메모리 참조나 복잡한 표현식
            try:
                target = self._parse_memory_reference(op_str)
                if target is not None:
                    visit_info = self._track_jump(target)
                    self.output.write(f"        → call {op_str} (0x{target:x}) {visit_info}")
                    self.output.write(f"        📞 [CALL] 반환주소 0x{return_address:x}를 스택에 push")
                    self.output.write(f"        📞 [CALL] RSP: 0x{current_rsp:x} → 0x{new_rsp:x}")
                    return target
                else:
                    self.output.write(f"        → call {op_str} (주소 계산 실패)")
                    return None
            except:
                self.output.write(f"        → call {op_str} (복잡한 주소 - VM 내부 호출)")
                return None

    def _simulate_push(self, op_str: str):
        """PUSH 명령어 시뮬레이션 - 스택에 값 푸시"""
        src_val = self._get_operand_value(op_str.strip())
        
        # RSP 감소 후 메모리에 값 저장
        rsp = self.vm_state.get_register('rsp')
        rsp -= 8
        self.vm_state.set_register('rsp', rsp)
        self.vm_state.set_memory(rsp, src_val)
        
        self.output.write(f"        → push {op_str} (0x{src_val:x}) to [0x{rsp:x}]")
        return None

    def _simulate_lea(self, op_str: str):
        """LEA (Load Effective Address) 명령어 시뮬레이션 - 주소 계산만 수행, 메모리 접근 없음"""
        parts = [p.strip() for p in op_str.split(',')]
        dst, src = parts[0], parts[1]
        
        # LEA는 메모리 주소를 계산하지만 실제 메모리에 접근하지는 않음
        # src는 항상 메모리 참조 형태여야 함 (예: [rbp + 0x10])
        if 'ptr [' in src or '[' in src:
            # 메모리 참조에서 주소만 계산 (실제 메모리 값 읽지 않음)
            effective_address = self._parse_memory_reference(src)
            if effective_address is not None:
                self._set_operand_value(dst, effective_address)
                self.output.write(f"        → lea {dst}, {src} = 0x{effective_address:x} (주소 계산만)")
            else:
                self.output.write(f"        → lea {dst}, {src} (주소 계산 실패)")
        else:
            self.output.write(f"        → lea {dst}, {src} (잘못된 형태 - 메모리 참조가 아님)")
        
        return None

    def _simulate_stc(self, op_str: str):
        """STC (Set Carry Flag) 명령어 시뮬레이션 - CF를 1로 설정"""
        self.vm_state.flags['CF'] = True
        self.output.write(f"        → stc (CF=1 설정)")
        return None

    def _simulate_clc(self, op_str: str):
        """CLC (Clear Carry Flag) 명령어 시뮬레이션 - CF를 0으로 클리어"""
        self.vm_state.flags['CF'] = False
        self.output.write(f"        → clc (CF=0 설정)")
        return None

    def _simulate_std(self, op_str: str):
        """STD (Set Direction Flag) 명령어 시뮬레이션 - DF를 1로 설정"""
        self.vm_state.flags['DF'] = True
        self.output.write(f"        → std (DF=1 설정, 문자열 연산 감소 방향)")
        return None

    def _simulate_cld(self, op_str: str):
        """CLD (Clear Direction Flag) 명령어 시뮬레이션 - DF를 0으로 클리어"""
        self.vm_state.flags['DF'] = False
        self.output.write(f"        → cld (DF=0 설정, 문자열 연산 증가 방향)")
        return None

    def _simulate_out(self, op_str: str):
        """OUT 명령어 시뮬레이션 - 포트로 데이터 출력"""
        parts = [p.strip() for p in op_str.split(',')]
        
        if len(parts) == 2:
            port, data_reg = parts[0], parts[1]
            
            # 포트 번호 파싱
            if port.startswith('0x'):
                port_num = int(port, 16)
            elif port.isdigit():
                port_num = int(port)
            elif port == 'dx':
                port_num = self.vm_state.get_register('dx') & 0xFFFF
            else:
                port_num = 0
            
            # 데이터 값 가져오기
            data_val = self._get_operand_value(data_reg)
            
            self.output.write(f"        → out 포트(0x{port_num:x}), {data_reg}(0x{data_val:x}) [I/O 출력 시뮬레이션]")
        else:
            self.output.write(f"        → out {op_str} [I/O 출력 - 형식 미지원]")
        
        return None

    def _simulate_in(self, op_str: str):
        """IN 명령어 시뮬레이션 - 포트에서 데이터 입력"""
        parts = [p.strip() for p in op_str.split(',')]
        
        if len(parts) == 2:
            data_reg, port = parts[0], parts[1]
            
            # 포트 번호 파싱
            if port.startswith('0x'):
                port_num = int(port, 16)
            elif port.isdigit():
                port_num = int(port)
            elif port == 'dx':
                port_num = self.vm_state.get_register('dx') & 0xFFFF
            else:
                port_num = 0
            
            # 가상의 입력 값 (실제 하드웨어가 없으므로)
            input_val = 0x0  # 기본값으로 0 반환
            
            self._set_operand_value(data_reg, input_val)
            self.output.write(f"        → in {data_reg}, 포트(0x{port_num:x}) = 0x{input_val:x} [I/O 입력 시뮬레이션]")
        else:
            self.output.write(f"        → in {op_str} [I/O 입력 - 형식 미지원]")
        
        return None

    def _simulate_syscall(self, op_str: str):
        """SYSCALL 명령어 시뮬레이션 - 시스템 호출 실행"""
        # rax에서 시스템 콜 번호 가져오기
        syscall_num = self.vm_state.get_register('rax')
        
        # 시스템 콜 인자들 가져오기 (Linux x64 ABI)
        arg1 = self.vm_state.get_register('rdi')  # 첫 번째 인자
        arg2 = self.vm_state.get_register('rsi')  # 두 번째 인자
        arg3 = self.vm_state.get_register('rdx')  # 세 번째 인자
        arg4 = self.vm_state.get_register('r10')  # 네 번째 인자
        arg5 = self.vm_state.get_register('r8')   # 다섯 번째 인자
        arg6 = self.vm_state.get_register('r9')   # 여섯 번째 인자
        
        # 시스템 콜 이름 매핑 (주요 시스템 콜들)
        syscall_names = {
            0: 'sys_read',
            1: 'sys_write', 
            2: 'sys_open',
            3: 'sys_close',
            4: 'sys_stat',
            5: 'sys_fstat',
            6: 'sys_lstat',
            7: 'sys_poll',
            8: 'sys_lseek',
            9: 'sys_mmap',
            10: 'sys_mprotect',
            11: 'sys_munmap',
            12: 'sys_brk',
            13: 'sys_rt_sigaction',
            14: 'sys_rt_sigprocmask',
            15: 'sys_rt_sigreturn',
            16: 'sys_ioctl',
            17: 'sys_pread64',
            18: 'sys_pwrite64',
            19: 'sys_readv',
            20: 'sys_writev',
            21: 'sys_access',
            22: 'sys_pipe',
            23: 'sys_select',
            24: 'sys_sched_yield',
            25: 'sys_mremap',
            26: 'sys_msync',
            27: 'sys_mincore',
            28: 'sys_madvise',
            29: 'sys_shmget',
            30: 'sys_shmat',
            31: 'sys_shmctl',
            32: 'sys_dup',
            33: 'sys_dup2',
            34: 'sys_pause',
            35: 'sys_nanosleep',
            36: 'sys_getitimer',
            37: 'sys_alarm',
            38: 'sys_setitimer',
            39: 'sys_getpid',
            40: 'sys_sendfile',
            41: 'sys_socket',
            42: 'sys_connect',
            43: 'sys_accept',
            44: 'sys_sendto',
            45: 'sys_recvfrom',
            46: 'sys_sendmsg',
            47: 'sys_recvmsg',
            48: 'sys_shutdown',
            49: 'sys_bind',
            50: 'sys_listen',
            51: 'sys_getsockname',
            52: 'sys_getpeername',
            53: 'sys_socketpair',
            54: 'sys_setsockopt',
            55: 'sys_getsockopt',
            56: 'sys_clone',
            57: 'sys_fork',
            58: 'sys_vfork',
            59: 'sys_execve',
            60: 'sys_exit',
            61: 'sys_wait4',
            62: 'sys_kill',
            63: 'sys_uname',
            231: 'sys_exit_group'
        }
        
        syscall_name = syscall_names.get(syscall_num, f'sys_unknown_{syscall_num}')
        
        # 시스템 콜 정보 출력
        self.output.write(f"        🔧 [SYSCALL] {syscall_name} (rax={syscall_num})")
        if arg1 != 0: self.output.write(f"            arg1(rdi) = 0x{arg1:x}")
        if arg2 != 0: self.output.write(f"            arg2(rsi) = 0x{arg2:x}")
        if arg3 != 0: self.output.write(f"            arg3(rdx) = 0x{arg3:x}")
        if arg4 != 0: self.output.write(f"            arg4(r10) = 0x{arg4:x}")
        if arg5 != 0: self.output.write(f"            arg5(r8)  = 0x{arg5:x}")
        if arg6 != 0: self.output.write(f"            arg6(r9)  = 0x{arg6:x}")
        
        # 특정 시스템 콜에 대한 특별 처리
        return_value = self._handle_specific_syscall(syscall_num, syscall_name, 
                                                   arg1, arg2, arg3, arg4, arg5, arg6)
        
        # SYSCALL 실행 후 레지스터 상태 변경
        # rax에 반환값 저장
        self.vm_state.set_register('rax', return_value)
        
        # rcx와 r11은 SYSCALL에 의해 덮어씀 (Linux x64 ABI)
        # rcx = return address (다음 명령어 주소), r11 = RFLAGS
        # 여기서는 시뮬레이션이므로 적절한 값으로 설정
        self.vm_state.set_register('rcx', 0x0)  # 가상의 반환 주소
        self.vm_state.set_register('r11', 0x202)  # 가상의 RFLAGS
        
        self.output.write(f"        → syscall 반환값: rax = 0x{return_value:x}")
        
        return None  # syscall은 점프가 아니므로 None 반환

    def _handle_specific_syscall(self, syscall_num: int, syscall_name: str, 
                                arg1: int, arg2: int, arg3: int, arg4: int, arg5: int, arg6: int) -> int:
        """특정 시스템 콜에 대한 상세 처리"""
        
        if syscall_num == 1:  # sys_write
            fd, buf_addr, count = arg1, arg2, arg3
            self.output.write(f"            💾 [sys_write] fd={fd}, buf=0x{buf_addr:x}, count={count}")
            
            # 버퍼 내용 읽기 시도 (가능한 경우)
            if buf_addr and count < 1024:  # 합리적인 크기만
                try:
                    buffer_content = ""
                    for i in range(min(count, 64)):  # 최대 64바이트만 표시
                        byte_val, _ = self.vm_state.get_memory(buf_addr + i)
                        if 32 <= (byte_val & 0xFF) <= 126:  # 출력 가능한 ASCII
                            buffer_content += chr(byte_val & 0xFF)
                        else:
                            buffer_content += f"\\x{byte_val & 0xFF:02x}"
                    
                    if buffer_content:
                        truncated = "..." if count > 64 else ""
                        self.output.write(f"            📝 [버퍼 내용] \"{buffer_content[:100]}{truncated}\"")
                except:
                    pass
            
            return count  # 성공적으로 쓴 바이트 수 반환
            
        elif syscall_num == 0:  # sys_read
            fd, buf_addr, count = arg1, arg2, arg3
            self.output.write(f"            📖 [sys_read] fd={fd}, buf=0x{buf_addr:x}, count={count}")
            return count  # 성공적으로 읽은 바이트 수 반환
            
        elif syscall_num == 2:  # sys_open
            filename_addr, flags, mode = arg1, arg2, arg3
            self.output.write(f"            📂 [sys_open] filename=0x{filename_addr:x}, flags=0x{flags:x}, mode=0x{mode:x}")
            
            # 파일명 읽기 시도
            if filename_addr:
                try:
                    filename = ""
                    for i in range(256):  # 최대 256문자
                        byte_val, _ = self.vm_state.get_memory(filename_addr + i)
                        if byte_val == 0:
                            break
                        if 32 <= byte_val <= 126:
                            filename += chr(byte_val)
                        else:
                            filename += f"\\x{byte_val:02x}"
                    
                    if filename:
                        self.output.write(f"            📄 [파일명] \"{filename}\"")
                except:
                    pass
            
            return 3  # 성공시 파일 디스크립터 반환 (가상)
            
        elif syscall_num == 3:  # sys_close
            fd = arg1
            self.output.write(f"            🔒 [sys_close] fd={fd}")
            return 0  # 성공
            
        elif syscall_num == 9:  # sys_mmap
            addr, length, prot, flags, fd, offset = arg1, arg2, arg3, arg4, arg5, arg6
            self.output.write(f"            🗺️  [sys_mmap] addr=0x{addr:x}, len=0x{length:x}, prot=0x{prot:x}")
            self.output.write(f"                         flags=0x{flags:x}, fd={fd}, offset=0x{offset:x}")
            return 0x7f0000000000 + (addr & 0xFFFF)  # 가상의 매핑 주소 반환
            
        elif syscall_num == 11:  # sys_munmap
            addr, length = arg1, arg2
            self.output.write(f"            🗺️  [sys_munmap] addr=0x{addr:x}, len=0x{length:x}")
            return 0  # 성공
            
        elif syscall_num == 39:  # sys_getpid
            self.output.write(f"            🆔 [sys_getpid]")
            return 1234  # 가상의 PID
            
        elif syscall_num == 60 or syscall_num == 231:  # sys_exit, sys_exit_group
            exit_code = arg1
            self.output.write(f"            🚪 [sys_exit] exit_code={exit_code}")
            self.output.write(f"            ⚠️  프로그램 종료 시그널 - 분석을 중단합니다")
            return exit_code
            
        elif syscall_num == 59:  # sys_execve
            filename_addr, argv_addr, envp_addr = arg1, arg2, arg3
            self.output.write(f"            🚀 [sys_execve] filename=0x{filename_addr:x}, argv=0x{argv_addr:x}")
            self.output.write(f"            ⚠️  새 프로그램 실행 - 분석이 여기서 끝날 수 있음")
            return 0
            
        else:
            # 기본 처리: 성공 반환값 0
            return 0

    def _track_memory_change(self, address: int, old_value: int, new_value: int):
        """메모리 변화를 추적합니다."""
        # 메모리 변화 기록
        if address not in self.memory_changes:
            self.memory_changes[address] = []
        self.memory_changes[address].append((old_value, new_value, self.instruction_count))
        
        # 메모리 쓰기 패턴 기록
        if address not in self.memory_writes:
            self.memory_writes[address] = []
        self.memory_writes[address].append(self.instruction_count)
        
        # 상세 로깅
        self.output.write(f"        📝 [메모리 추적] #{self.instruction_count}: [0x{address:x}] 0x{old_value:x} → 0x{new_value:x}")


# ============================================================================
# 메인 VM 분석기
# ============================================================================
class VMAnalyzer:
    """통합 VM 분석기"""
    
    def __init__(self, code_bytes: bytes, base_address: int, output_writer: OutputWriter = None, 
                 initial_rbp: int = None, initial_rsp: int = None):
        self.output = output_writer or OutputWriter()
        self.disasm = DisassemblyEngine(code_bytes, base_address, self.output)
        self.vm_state = VMState(self.output, initial_rbp, initial_rsp, code_bytes, base_address)
        self.tail_tracker = TailCallTracker(self.disasm, self.output)
        self.pattern_analyzer = PatternAnalyzer(self.disasm, self.output)
        self.simulator = ExecutionSimulator(self.disasm, self.vm_state, self.output)

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

    def close_output(self):
        """출력 파일을 닫습니다."""
        self.output.close()


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

def main():
    try:
        # 파일 읽기
        with open('L2.bin', 'rb') as f:
            code_bytes = f.read()
        
        base_address = 0x7ff6ebea1000
        entry_address = 0x7ff6ebfdf031
        
        # 출력 라이터 생성
        output_writer = OutputWriter('simulation')
        
        # VM 분석기 생성
        analyzer = VMAnalyzer(
            code_bytes=code_bytes, 
            base_address=base_address, 
            output_writer=output_writer
        )
        
        # 🎯 실제 초기 스택 프레임 데이터 설정
        print("🔧 실제 디버깅 데이터를 기반으로 초기 스택 값 설정...")
        
        # 실제 스택 메모리 값들 (디버깅에서 확인된 값들)
        real_stack_values = {
            # pushfq에서 push되어야 할 올바른 RFLAGS 값
            0x3beb8ff7c8: 0x1fe,  # pushfq 결과
            
            # 올바른 다음 실행 주소들
            0x3beb8ff7d0: 0x7ff6ebeb1cd0,  # 실제 다음 주소
            0x3beb8ff7d8: 0x7ff6ebea1000,  # 베이스 주소
            
            # 추가 스택 프레임 데이터 (필요시)
            0x3beb8ff7e0: 0x0,
            0x3beb8ff7e8: 0x0,
        }
        
        # 실제 레지스터 값들 
        real_register_values = {
            'rdx': 0x1fe,  # 실제 rdx 값
        }
        
        # VM 상태에 실제 값들 설정
        analyzer.set_real_memory_values(real_stack_values)
        analyzer.set_real_registers(real_register_values)
        
        print(f"📍 베이스 주소: 0x{base_address:x}")
        print(f"🎯 엔트리 포인트: 0x{entry_address:x}")
        
        choice = get_user_choice()
        
        if choice == '1':
            max_per_block, max_revisits = get_trace_settings()
            analyzer.trace_tail_calls(entry_address, max_per_block, max_revisits)
        elif choice == '2':
            max_chains = int(input("최대 체인 수 (기본 10): ") or "10")
            analyzer.analyze_vm_patterns(entry_address, max_chains)
        elif choice == '3':
            max_instructions = get_simulation_settings()
            analyzer.simulate_execution(entry_address, max_instructions)
        
        analyzer.close_output()
        
    except FileNotFoundError:
        print("❌ L2.bin 파일을 찾을 수 없습니다.")
    except Exception as e:
        print(f"❌ 오류 발생: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()