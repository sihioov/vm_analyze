'use strict';

/* ---------- 공용 헬퍼 ---------- */

// 안전하게 심볼 구하기
function getExport(moduleName, symbol) {
    try {
        return Process.getModuleByName(moduleName).getExportByName(symbol);
    } catch (_) {
        // 모듈이 아직 안 올라왔거나 delay-load된 경우 전체에서 검색
        try { return Module.getGlobalExportByName(symbol); }
        catch (_) { return null; }
    }
}

// kernel32!GetFinalPathNameByHandleW → 경로 변환
const GetFinalPathNameByHandleW = new NativeFunction(
    getExport('kernel32.dll', 'GetFinalPathNameByHandleW'),
    'uint',
    ['pointer', 'pointer', 'uint', 'uint']
);

function wideToString(ptr) { return ptr.readUtf16String(); }

// NT 경로를 일반 Windows 경로로 변환
function cleanPath(rawPath) {
    if (!rawPath) return '(unknown)';
    
    // NT Object Manager 경로 정리
    let cleaned = rawPath
        .replace(/^\\\?\?\\/g, '')          // \??\ 접두사 제거
        .replace(/^UNC\\/g, '\\\\')         // UNC 경로 처리
        .replace(/\0/g, '');                // null 문자 제거
    
    // 비ASCII 문자가 깨진 경우 안전하게 처리
    try {
        // 유효한 Windows 경로인지 확인
        if (/^[A-Za-z]:\\/i.test(cleaned) || cleaned.startsWith('\\\\')) {
            return cleaned;
        }
    } catch (e) {
        // 인코딩 오류 시 원본 반환
    }
    
    return rawPath;
}

// CMD 창에서 안전한 출력을 위한 함수
function safeLog(message) {
    console.log(message);
}

function pathFromHandle(h) {
    const buf = Memory.alloc(1024 * 2);
    const len = GetFinalPathNameByHandleW(h, buf, 1024, 0);
    return len ? wideToString(buf) : '(unknown)';
}

// 헥스 덤프(앞 64바이트)
function dump(ptr, len) {
    return hexdump(ptr, { length: Math.min(len, 64), header: false, ansi: false });
}

// 핸들 ↔ 경로 매핑
const handleMap = new Map();
const save = (h, p) => handleMap.set(h.toString(), p);
const get  = h => handleMap.get(h.toString()) || pathFromHandle(h);
const drop = h => handleMap.delete(h.toString());

/* ---------- NtCreateFile ---------- */
{
    const addr = getExport('ntdll.dll', 'NtCreateFile');
    if (addr)
        Interceptor.attach(addr, {
            onEnter(args) {
                this.phandle  = args[0];  // PHANDLE
                this.objAttr  = args[2];  // POBJECT_ATTRIBUTES
            },
            onLeave(retval) {
                if (retval.toInt32() < 0) return;            // 실패
                const h = this.phandle.readPointer();

                // OBJECT_ATTRIBUTES.ObjectName → UNICODE_STRING
                const usPtr = this.objAttr.add(16).readPointer();
                let path = '(unknown)';
                if (!usPtr.isNull()) {
                    try {
                        const byteLen = usPtr.readU16();
                        const pwstr   = usPtr.add(8).readPointer();
                        if (byteLen > 0 && !pwstr.isNull()) {
                            const rawPath = pwstr.readUtf16String(byteLen / 2);
                            path = cleanPath(rawPath);
                        }
                    } catch (e) {
                        // UTF-16 읽기 실패 시 대체 방법 사용
                        path = pathFromHandle(h);
                    }
                } else {
                    path = pathFromHandle(h);
                }
                save(h, path);
                safeLog(`[NtCreateFile] 0x${h.toString(16)} ← ${path}`);
            }
        });
    else console.log('❌ NtCreateFile not found');
}

/* ---------- 라이선스 파일 패턴 정의 ---------- */
const licenseFilePatterns = [
    'license', 'licence', 'key', 'serial', 'activation', 
    'register', 'trial', 'demo', 'crack', 'patch',
    'staticcache.dat', 'config.dat', 'settings.dat'
];

/* ---------- NtReadFile ---------- */
{
    const addr = getExport('ntdll.dll', 'NtReadFile');
    if (addr)
        Interceptor.attach(addr, {
            onEnter(args) {
                this.h    = args[0];
                this.buf  = args[5];
                this.len  = args[6].toUInt32();
                this.iosb = args[4];
            },
            onLeave(retval) {
                if (retval.toInt32() < 0) return;
                const done = this.iosb.add(8).readU64().toNumber();
                if (!done) return;
                
                const filePath = get(this.h);
                console.log(`[NtReadFile]  0x${this.h.toString(16)} (${filePath})`);
                console.log(dump(this.buf, done));
                
                // 라이선스 파일 감지 및 조작
                const isLicenseFile = licenseFilePatterns.some(pattern => 
                    filePath.toLowerCase().includes(pattern.toLowerCase())
                );
                
                if (isLicenseFile) {
                    console.log(`[🔑 LICENSE] 라이선스 파일 읽기 감지: ${filePath}`);
                    
                    // staticcache.dat 파일 특화 조작
                    if (filePath.toLowerCase().includes('staticcache.dat')) {
                        try {
                            // 특정 바이트 위치 조작 (라이선스 상태 변경)
                            if (done >= 8) {
                                const bufPtr = this.buf;
                                const fake = new Uint8Array([0xFF, 0xFF]); // 유효 플래그
                                Memory.writeByteArray(bufPtr.add(4), fake);
                                console.log(`[🛡️ LICENSE] staticcache.dat 라이선스 플래그 조작됨`);
                            }
                        } catch (e) {
                            console.log(`[❌] 라이선스 데이터 조작 실패: ${e.message}`);
                        }
                    }
                }
            }
        });
    else console.log('❌ NtReadFile not found');
}

/* ---------- NtWriteFile ---------- */
{
    const addr = getExport('ntdll.dll', 'NtWriteFile');
    if (addr)
        Interceptor.attach(addr, {
            onEnter(args) {
                this.h   = args[0];
                this.buf = args[5];
                this.len = args[6].toUInt32();
            },
            onLeave(retval) {
                if (retval.toInt32() < 0 || !this.len) return;
                console.log(`[NtWriteFile] 0x${this.h.toString(16)} (${get(this.h)})`);
                console.log(dump(this.buf, this.len));
            }
        });
    else console.log('❌ NtWriteFile not found');
}

/* ---------- NtClose ---------- */
{
    const addr = getExport('ntdll.dll', 'NtClose');
    if (addr)
        Interceptor.attach(addr, {
            onEnter(args) { this.h = args[0]; },
            onLeave(retval) {
                if (retval.toInt32() >= 0) {
                    console.log(`[NtClose]     0x${this.h.toString(16)} (${get(this.h)})`);
                    drop(this.h);
                }
            }
        });
    else console.log('❌ NtClose not found');
}

console.log('▶ 파일 I/O 훅 최신 API로 설치 완료');

/* ---------- 안티 디버거 우회 ---------- */

// 1. NtQueryInformationProcess → DebugPort/DebugFlags 조작
const NtQIP = getExport('ntdll.dll', 'NtQueryInformationProcess');
if (NtQIP) {
    Interceptor.attach(NtQIP, {
        onEnter(args) { 
            this.infoClass = args[1].toInt32(); 
            this.buf = args[2]; 
        },
        onLeave(ret) {
            if (ret.toInt32() >= 0 && (this.infoClass === 7 || this.infoClass === 0x1e)) {
                if (this.infoClass === 7) {   // ProcessDebugPort
                    const debugPort = this.buf.readPointer();
                    console.log(`[🔍 ANTI-DEBUG 탐지] ProcessDebugPort 확인됨! 값: ${debugPort}`);
                    Memory.writePointer(this.buf, ptr('0'));  // 우회 활성화
                    console.log(`[🛡️ 우회] ProcessDebugPort → 0으로 변경`);
                } else {                      // ProcessDebugFlags  
                    const debugFlags = this.buf.readU32();
                    console.log(`[🔍 ANTI-DEBUG 탐지] ProcessDebugFlags 확인됨! 값: ${debugFlags}`);
                    Memory.writeU32(this.buf, 1);  // 우회 활성화
                    console.log(`[🛡️ 우회] ProcessDebugFlags → 1로 변경`);
                }
            }
        }
    });
    console.log('✓ NtQueryInformationProcess 모니터링 시작');
} else {
    console.log('❌ NtQueryInformationProcess not found');
}

// 2. IsDebuggerPresent 우회
const IsDebuggerPresent = getExport('kernel32.dll', 'IsDebuggerPresent');
if (IsDebuggerPresent) {
    Interceptor.attach(IsDebuggerPresent, {
        onLeave(retval) {
            const isDebugging = retval.toInt32();
            console.log(`[🔍 ANTI-DEBUG 탐지] IsDebuggerPresent 호출됨! 반환값: ${isDebugging}`);
            retval.replace(ptr('0'));  // 우회 활성화
            console.log(`[🛡️ 우회] IsDebuggerPresent → FALSE로 변경`);
        }
    });
    console.log('✓ IsDebuggerPresent 모니터링 시작');
}

// 3. CheckRemoteDebuggerPresent 우회
const CheckRemoteDebuggerPresent = getExport('kernel32.dll', 'CheckRemoteDebuggerPresent');
if (CheckRemoteDebuggerPresent) {
    Interceptor.attach(CheckRemoteDebuggerPresent, {
        onEnter(args) {
            this.pbDebuggerPresent = args[1];
        },
        onLeave(retval) {
            if (retval.toInt32() !== 0) {  // 성공 시
                const debuggerPresent = this.pbDebuggerPresent.readU8();
                console.log(`[🔍 ANTI-DEBUG 탐지] CheckRemoteDebuggerPresent 호출됨! 결과: ${debuggerPresent}`);
                Memory.writeU8(this.pbDebuggerPresent, 0);  // 우회 활성화
                console.log(`[🛡️ 우회] CheckRemoteDebuggerPresent → FALSE로 변경`);
            }
        }
    });
    console.log('✓ CheckRemoteDebuggerPresent 모니터링 시작');
}

// 4. OutputDebugStringA/W 우회 (디버거 탐지용)
['OutputDebugStringA', 'OutputDebugStringW'].forEach(funcName => {
    const func = getExport('kernel32.dll', funcName);
    if (func) {
        Interceptor.attach(func, {
            onEnter(args) {
                const str = funcName.endsWith('A') ? 
                    args[0].readAnsiString() : 
                    args[0].readUtf16String();
                console.log(`[🔍 ANTI-DEBUG 탐지] ${funcName} 호출됨: "${str}"`);
            }
        });
        console.log(`✓ ${funcName} 모니터링 시작`);
    }
});

// 5. NtSetInformationThread (ThreadHideFromDebugger) 우회
const NtSetInformationThread = getExport('ntdll.dll', 'NtSetInformationThread');
if (NtSetInformationThread) {
    Interceptor.attach(NtSetInformationThread, {
        onEnter(args) {
            const infoClass = args[1].toInt32();
            if (infoClass === 0x11) {  // ThreadHideFromDebugger
                console.log('[🔍 ANTI-DEBUG 탐지] ThreadHideFromDebugger 시도 감지됨!');
                this.shouldBlock = true;  // 우회 활성화
            }
        },
        onLeave(retval) {
            if (this.shouldBlock) {
                retval.replace(ptr('0'));  // 우회 활성화
                console.log(`[🛡️ 우회] ThreadHideFromDebugger 차단됨`);
            }
        }
    });
    console.log('✓ NtSetInformationThread 모니터링 시작');
}

// 6. PEB 상태 확인 (BeingDebugged 플래그)
try {
    const peb = Process.getCurrentProcess().getModuleByName('ntdll.dll').base.add(0x60);
    const beingDebuggedOffset = 0x02;
    const beingDebugged = Memory.readU8(peb.add(beingDebuggedOffset));
    console.log(`[🔍 ANTI-DEBUG 상태] PEB.BeingDebugged 현재값: ${beingDebugged}`);
    Memory.writeU8(peb.add(beingDebuggedOffset), 0);  // 우회 활성화
    console.log(`[🛡️ 우회] PEB.BeingDebugged → 0으로 변경`);
} catch (e) {
    console.log('[❌] PEB 읽기 실패');
}

// 7. 시간 기반 탐지 우회 (GetTickCount)
const GetTickCount = getExport('kernel32.dll', 'GetTickCount');
if (GetTickCount) {
    let lastTick = 0;
    Interceptor.attach(GetTickCount, {
        onLeave(retval) {
            const currentTick = retval.toInt32();
            if (lastTick > 0) {
                const diff = currentTick - lastTick;
                if (diff > 1000) {  // 1초 이상 차이나면
                    console.log(`[🔍 ANTI-DEBUG 탐지] 시간 기반 탐지 가능성: ${diff}ms 지연`);
                }
            }
            lastTick = currentTick;
        }
    });
    console.log('✓ GetTickCount 시간 모니터링 시작');
}

// 8. 추가: NtClose 후킹으로 디버거 핸들 탐지
const NtCloseForDebug = getExport('ntdll.dll', 'NtClose');
if (NtCloseForDebug) {
    Interceptor.attach(NtCloseForDebug, {
        onEnter(args) {
            this.handle = args[0];
        },
        onLeave(retval) {
            // 유효하지 않은 핸들을 닫으려 할 때 (안티 디버깅 기법)
            if (retval.toInt32() < 0) {
                console.log(`[🔍 ANTI-DEBUG 탐지] 잘못된 핸들 닫기 시도: 0x${this.handle.toString(16)}`);
            }
        }
    });
    console.log('✓ NtClose 디버거 탐지 모니터링 시작');
}

console.log('▶ 안티 디버거 탐지 + 우회 시스템 활성화 완료!');

/* ---------- 라이선스 검증 우회 ---------- */

// 라이선스 관련 레지스트리 키 패턴
const licenseRegPatterns = [
    'license', 'licence', 'serial', 'key', 'activation',
    'register', 'trial', 'demo', 'expired', 'valid'
];

// 1. 파일 읽기 내용 조작은 기존 NtReadFile 후킹에서 처리
// 중복 후킹 방지를 위해 주석 처리

// 2. 레지스트리 읽기 우회
const RegQueryValueExW = getExport('advapi32.dll', 'RegQueryValueExW');
if (RegQueryValueExW) {
    Interceptor.attach(RegQueryValueExW, {
        onEnter(args) {
            this.hKey = args[0];
            this.lpValueName = args[1];
            this.lpData = args[4];
            this.lpcbData = args[5];
            
            this.valueName = '';
            if (!this.lpValueName.isNull()) {
                this.valueName = this.lpValueName.readUtf16String().toLowerCase();
            }
            
            this.isLicenseReg = licenseRegPatterns.some(pattern => 
                this.valueName.includes(pattern)
            );
        },
        onLeave(retval) {
            if (retval.toInt32() === 0 && this.isLicenseReg) { // ERROR_SUCCESS
                console.log(`[🔑 LICENSE] 라이선스 레지스트리 읽기: "${this.valueName}"`);
                
                // 라이선스 관련 값 조작
                if (this.valueName.includes('trial') || this.valueName.includes('demo')) {
                    // 체험판 -> 정품으로 변경
                    if (!this.lpData.isNull() && !this.lpcbData.isNull()) {
                        const dataSize = this.lpcbData.readU32();
                        if (dataSize >= 4) {
                            Memory.writeU32(this.lpData, 0); // 체험판 비활성화
                            console.log(`[🛡️ LICENSE] 체험판 플래그 비활성화`);
                        }
                    }
                } else if (this.valueName.includes('expired') || this.valueName.includes('expire')) {
                    // 만료 상태 -> 유효로 변경
                    if (!this.lpData.isNull() && !this.lpcbData.isNull()) {
                        const dataSize = this.lpcbData.readU32();
                        if (dataSize >= 4) {
                            Memory.writeU32(this.lpData, 0); // 만료되지 않음
                            console.log(`[🛡️ LICENSE] 만료 플래그 비활성화`);
                        }
                    }
                } else if (this.valueName.includes('valid') || this.valueName.includes('license')) {
                    // 라이선스 유효성 -> 유효로 설정
                    if (!this.lpData.isNull() && !this.lpcbData.isNull()) {
                        const dataSize = this.lpcbData.readU32();
                        if (dataSize >= 4) {
                            Memory.writeU32(this.lpData, 1); // 유효함
                            console.log(`[🛡️ LICENSE] 라이선스 유효성 활성화`);
                        }
                    }
                }
            }
        }
    });
    console.log('✓ 라이선스 레지스트리 후킹 완료');
}

// 3. 시간 기반 라이선스 우회 (GetSystemTime, GetLocalTime)
['GetSystemTime', 'GetLocalTime'].forEach(funcName => {
    const func = getExport('kernel32.dll', funcName);
    if (func) {
        Interceptor.attach(func, {
            onEnter(args) {
                this.lpSystemTime = args[0];
            },
            onLeave(retval) {
                // 시간을 과거로 조작 (라이선스 만료 방지)
                if (!this.lpSystemTime.isNull()) {
                    const year = this.lpSystemTime.readU16();
                    if (year > 2020) {  // 2020년 이후라면
                        this.lpSystemTime.writeU16(2020);  // 2020년으로 변경
                        console.log(`[🔑 LICENSE] 시스템 시간 조작: ${year} → 2020`);
                    }
                }
            }
        });
        console.log(`✓ ${funcName} 시간 조작 후킹 완료`);
    }
});

// 4. 일반적인 라이선스 검증 함수들 우회
const commonLicenseFunctions = [
    'CheckLicense', 'VerifyLicense', 'ValidateLicense', 'IsLicenseValid',
    'CheckSerial', 'VerifySerial', 'ValidateSerial', 'IsSerialValid',
    'CheckTrial', 'IsTrialExpired', 'GetTrialDays', 'CheckExpiry',
    'IsRegistered', 'CheckRegistration', 'VerifyRegistration'
];

// 메인 모듈에서 라이선스 함수 검색
setTimeout(() => {
    try {
        const mainModule = Process.enumerateModules()[0];
        const exports = mainModule.enumerateExports();
        
        exports.forEach(exp => {
            const funcName = exp.name.toLowerCase();
            const isLicenseFunc = commonLicenseFunctions.some(pattern => 
                funcName.includes(pattern.toLowerCase())
            );
            
            if (isLicenseFunc) {
                console.log(`[🔍 LICENSE] 라이선스 함수 발견: ${exp.name}`);
                
                Interceptor.attach(exp.address, {
                    onLeave(retval) {
                        // 모든 라이선스 검증을 성공으로 변경
                        retval.replace(ptr('1'));  // TRUE 반환
                        console.log(`[🛡️ LICENSE] ${exp.name} → TRUE 강제 반환`);
                    }
                });
            }
        });
    } catch (e) {
        console.log(`[❌] 라이선스 함수 검색 실패: ${e.message}`);
    }
}, 3000);  // 3초 후 실행

// 5. 문자열 기반 라이선스 메시지 탐지
const MessageBoxW = getExport('user32.dll', 'MessageBoxW');
if (MessageBoxW) {
    Interceptor.attach(MessageBoxW, {
        onEnter(args) {
            this.hWnd = args[0];
            this.lpText = args[1];
            this.lpCaption = args[2];
            this.uType = args[3];
            
            const text = this.lpText.readUtf16String().toLowerCase();
            const caption = this.lpCaption.readUtf16String().toLowerCase();
            
            // 라이선스 관련 메시지 탐지
            const licenseMessages = ['license', 'trial', 'expired', 'register', 'serial', 'activation'];
            this.isLicenseMsg = licenseMessages.some(msg => 
                text.includes(msg) || caption.includes(msg)
            );
            
            if (this.isLicenseMsg) {
                markLicenseFailure();
                // 레지스터 우회 (x64 RAX)
                if (this.context && this.context.rax) {
                    this.context.rax = ptr('0');
                }
                console.log(`[🔑 LICENSE] 라이선스 메시지 탐지:`);
                console.log(`  제목: ${caption}`);
                console.log(`  내용: ${text}`);
                
                // 콜스택 분석하여 실패 함수 자동 탐지
                const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                             .map(DebugSymbol.fromAddress);
                console.log('[🔍 LICENSE] Backtrace (상위 10개):');
                bt.slice(0, 10).forEach((sym, idx) => {
                    console.log(`  [${idx}] ${sym}`);
                });

                const skipNames = ['SysFreeString', 'free', 'operator delete', 'RtlFreeHeap', 'MessageBox', 'DispatchMessage'];
                let patched = false;
                for (let i = 1; i < bt.length; i++) {
                    const sym = bt[i];
                    const funcName = (sym.name || '').toLowerCase();
                    if (!skipNames.some(n => funcName.includes(n.toLowerCase()))) {
                        const target = sym.address;
                        const key = target.toString();
                        if (!globalThis.__licensePatched) globalThis.__licensePatched = {};
                        if (!globalThis.__licensePatched[key]) {
                            console.log(`[🛠️ LICENSE] 자동 패치 @ ${target} (${sym.name || 'unknown'})`);
                            try {
                                const stub = new NativeCallback(function(){ return 1; }, 'int', []);
                                Interceptor.replace(target, stub);
                                globalThis.__licensePatched[key] = true;
                                console.log('[🛡️ LICENSE] inline stub 패치 완료 → TRUE 반환');
                            } catch (e3) {
                                console.log(`[❌] inline stub 실패: ${e3.message}`);
                            }
                        }
                        patched = true;
                        break;
                    }
                }
                if (!patched) console.log('[ℹ️ LICENSE] 패치 가능한 프레임을 찾지 못함');
                
                // 메시지 박스 표시 차단
                this.shouldBlock = true;
            }
        },
        onLeave(retval) {
            if (this.shouldBlock) {
                retval.replace(ptr('1'));  // IDOK 반환
                console.log(`[🛡️ LICENSE] 라이선스 메시지 박스 차단됨`);
            }
        }
    });
    console.log('✓ 라이선스 메시지 박스 후킹 완료');
}

console.log('▶ 라이선스 검증 우회 시스템 활성화 완료!');

/* ---------- BlackSector Solutions 특화 우회 ---------- */

// 6. 특정 프로그램 라이선스 키 검증 우회
const blacksectorPatterns = [
    'blacksector', 'login', 'invalid', 'license key', 'authentication',
    'verify', 'check', 'validate', 'authorized', 'registered'
];

// 문자열 비교 함수들 후킹 (라이선스 키 비교)
['lstrcmpW', 'lstrcmpA', 'wcscmp', 'strcmp'].forEach(funcName => {
    const func = getExport('kernel32.dll', funcName) || getExport('msvcrt.dll', funcName);
    if (func) {
        Interceptor.attach(func, {
            onEnter(args) {
                try {
                    const str1 = funcName.includes('W') ? 
                        args[0].readUtf16String() : 
                        args[0].readAnsiString();
                    const str2 = funcName.includes('W') ? 
                        args[1].readUtf16String() : 
                        args[1].readAnsiString();
                    
                    this.str1 = str1 || '';
                    this.str2 = str2 || '';
                    this.isLicenseCheck = false;
                    
                    // 라이선스 키 형태 감지 (길이 16-32, 영숫자+하이픈)
                    const licensePattern = /^[A-Z0-9]{4,8}(-[A-Z0-9]{4,8}){1,4}$/i;
                    if (licensePattern.test(this.str1) || licensePattern.test(this.str2)) {
                        this.isLicenseCheck = true;
                        console.log(`[🔑 LICENSE] 라이선스 키 비교 감지:`);
                        console.log(`  입력된 키: "${this.str1}"`);
                        console.log(`  비교 대상: "${this.str2}"`);
                    }
                } catch (e) {
                    // 문자열 읽기 실패 시 무시
                }
            },
            onLeave(retval) {
                if (this.isLicenseCheck) {
                    retval.replace(ptr('0'));  // 문자열 일치로 변경
                    console.log(`[🛡️ LICENSE] 라이선스 키 비교 우회됨`);
                }
            }
        });
        console.log(`✓ ${funcName} 문자열 비교 후킹 완료`);
    }
});

// 7. 네트워크 기반 라이선스 검증 우회
const networkFunctions = ['InternetOpenW', 'InternetConnectW', 'HttpOpenRequestW', 'HttpSendRequestW'];
networkFunctions.forEach(funcName => {
    const func = getExport('wininet.dll', funcName);
    if (func) {
        Interceptor.attach(func, {
            onEnter(args) {
                if (funcName === 'InternetOpenW' && !args[0].isNull()) {
                    const userAgent = args[0].readUtf16String();
                    console.log(`[🔑 LICENSE] 네트워크 라이선스 검증 시도: ${userAgent}`);
                }
            },
            onLeave(retval) {
                if (funcName === 'HttpSendRequestW') {
                    // 네트워크 라이선스 검증 실패로 변경
                    retval.replace(ptr('0'));
                    console.log(`[🛡️ LICENSE] 네트워크 라이선스 검증 차단됨`);
                }
            }
        });
        console.log(`✓ ${funcName} 네트워크 후킹 완료`);
    }
});

// 8. 암호화 함수 우회 (라이선스 키 해시 검증)
const cryptoFunctions = ['CryptHashData', 'CryptVerifySignatureW', 'CryptDecrypt'];
cryptoFunctions.forEach(funcName => {
    const func = getExport('advapi32.dll', funcName);
    if (func) {
        Interceptor.attach(func, {
            onEnter(args) {
                console.log(`[🔑 LICENSE] 암호화 검증 시도: ${funcName}`);
            },
            onLeave(retval) {
                // 모든 암호화 검증을 성공으로 변경
                retval.replace(ptr('1'));
                console.log(`[🛡️ LICENSE] 암호화 검증 우회: ${funcName}`);
            }
        });
        console.log(`✓ ${funcName} 암호화 후킹 완료`);
    }
});

// 9. 특정 에러 코드 우회
const errorCodes = {
    'ERROR_ACCESS_DENIED': 5,
    'ERROR_INVALID_DATA': 13,
    'ERROR_INVALID_PARAMETER': 87,
    'ERROR_NOT_FOUND': 1168
};

// GetLastError 후킹
const GetLastError = getExport('kernel32.dll', 'GetLastError');
if (GetLastError) {
    Interceptor.attach(GetLastError, {
        onLeave(retval) {
            const errorCode = retval.toInt32();
            if (Object.values(errorCodes).includes(errorCode)) {
                retval.replace(ptr('0'));  // ERROR_SUCCESS
                console.log(`[🛡️ LICENSE] 에러 코드 우회: ${errorCode} → 0`);
            }
        }
    });
    console.log('✓ GetLastError 후킹 완료');
}

// 10. 라이선스 파일 생성 (존재하지 않는 경우)
const CreateFileW = getExport('kernel32.dll', 'CreateFileW');
if (CreateFileW) {
    Interceptor.attach(CreateFileW, {
        onEnter(args) {
            const filename = args[0].readUtf16String().toLowerCase();
            this.isLicenseFile = licenseFilePatterns.some(pattern => 
                filename.includes(pattern.toLowerCase())
            );
            this.filename = filename;
        },
        onLeave(retval) {
            if (this.isLicenseFile && retval.toInt32() === -1) {  // INVALID_HANDLE_VALUE
                console.log(`[🔑 LICENSE] 라이선스 파일 생성 필요: ${this.filename}`);
                // 실제로는 파일을 생성하지 않고 가짜 핸들 반환
                retval.replace(ptr('0x12345678'));
                console.log(`[🛡️ LICENSE] 가짜 라이선스 파일 핸들 생성됨`);
            }
        }
    });
    console.log('✓ CreateFileW 라이선스 파일 후킹 완료');
}

console.log('▶ BlackSector Solutions 특화 우회 완료!');

/* ---------- Process 종료 차단 (라이선스 실패 시) ---------- */

let licenseFailure = false; // 라이선스 실패 감지 플래그

function markLicenseFailure() {
    licenseFailure = true;
}

// 메시지 박스 라이선스 오류 탐지 시 플래그 설정 (기존 코드 위치에서 호출)
// => 아래 코드에서 이미 탐지한 부분(라이선스 메시지)에 markLicenseFailure() 추가

/* 추가: 라이선스 메시지 탐지 블록 중 ... */

// 패킹된 프로그램을 위한 지연 초기화
function delayedInit() {
    console.log('[*] 지연 초기화 시작...');
    
    // 메인 모듈이 언패킹될 때까지 대기
    const mainModule = Process.enumerateModules()[0];
    console.log(`[*] 메인 모듈: ${mainModule.name} (Base: ${mainModule.base})`);
    
    // 2초 대기 후 후킹 시작
    setTimeout(() => {
        console.log('[*] 후킹 시작...');
        initializeHooks();
    }, 2000);
}

// 기존 초기화 코드를 함수로 래핑
function initializeHooks() {
    // 기존 초기화 코드를 여기에 추가
}

// 차단 대상 함수 목록
const exitFunctions = [
    ['kernel32.dll', 'ExitProcess', 'void', ['uint']],
    ['kernel32.dll', 'TerminateProcess', 'int', ['pointer', 'uint']],
    ['ntdll.dll',    'NtTerminateProcess', 'uint', ['pointer', 'uint']]
];

exitFunctions.forEach(([dll, name]) => {
    const addr = getExport(dll, name);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter(args) {
                this.shouldBlock = licenseFailure;
                if (this.shouldBlock) {
                    console.log(`[🛡️ LICENSE] ${name} 호출 차단 (라이선스 실패)`);
                }
            },
            onLeave(retval) {
                if (this.shouldBlock) {
                    retval.replace(ptr('0'));
                }
            }
        });
        console.log(`✓ ${name} 종료 차단 후킹 완료`);
    }
});

// 11. 메모리 비교 함수 우회 (memcmp / RtlCompareMemory)
const cmpTargets = [
    ['msvcrt.dll', 'memcmp'],
    ['ntdll.dll',  'RtlCompareMemory']
];

cmpTargets.forEach(([dll, name]) => {
    const addr = getExport(dll, name);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter(args) {
                this.len = args[2] ? Number(args[2]) : 0; // size_t length
            },
            onLeave(retval) {
                if (licenseFailure && this.len <= 64) { // 짧은 비교 우회
                    if (name === 'memcmp') {
                        if (retval.toInt32() !== 0) {
                            console.log(`[🛡️ LICENSE] ${name} 우회 len=${this.len}`);
                            retval.replace(ptr('0'));
                        }
                    } else { // RtlCompareMemory
                        const equal = retval.toInt32();
                        if (equal !== this.len) {
                            console.log(`[🛡️ LICENSE] ${name} 우회 len=${this.len}`);
                            retval.replace(ptr(this.len));
                        }
                    }
                }
            }
        });
        console.log(`✓ ${name} 비교 우회 후킹 완료`);
    }
});
