# hex_to_bin_improved.py
import re

def load_hex_string_from_file(filename="hex_data.txt"):
    """
    텍스트 파일에서 hex 데이터를 읽어옵니다.
    파일이 없으면 빈 문자열을 반환합니다.
    """
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
        print(f"[*] {filename}에서 hex 데이터를 읽었습니다 ({len(content)} 글자).")
        return content
    except FileNotFoundError:
        print(f"[!] {filename} 파일을 찾을 수 없습니다. 빈 바이너리를 생성합니다.")
        return ""
    except Exception as e:
        print(f"[!] {filename} 읽기 오류: {e}")
        return ""

def main():
    # 파일에서 hex 데이터 로드
    hex_string_dump = load_hex_string_from_file("hex_data.txt")
    
    if not hex_string_dump.strip():
        print("[!] hex 데이터가 비어있습니다.")
        return
    
    output_filename = "L2.bin"
    
    try:
        processed_lines = []
        for line in hex_string_dump.strip().split('\n'):
            # Binary Ninja 형태의 hex dump 파싱
            match = re.search(r':\s*([0-9a-fA-F\s]+?)\s{2,}', line)
            if match:
                hex_bytes_part = match.group(1).strip()
                processed_lines.append(hex_bytes_part)
            elif ':' in line:
                parts = line.split(':', 1)
                if len(parts) > 1:
                    hex_candidate = parts[1].strip()
                    ascii_parts = re.split(r'\s{2,}', hex_candidate, 1)
                    hex_only = ascii_parts[0]
                    filtered_hex = "".join(re.findall(r'[0-9a-fA-F\s]+', hex_only))
                    if filtered_hex.strip():
                        processed_lines.append(filtered_hex.strip())
        
        cleaned_hex_string = "".join("".join(processed_lines).split())
        
        if not cleaned_hex_string:
            raise ValueError("16진수 문자열이 비어있습니다 (처리 후).")
        
        binary_data = bytes.fromhex(cleaned_hex_string)
        with open(output_filename, "wb") as f:
            f.write(binary_data)
        print(f"[*] '{output_filename}' 파일생성 완료 ({len(binary_data)} 바이트).")
        print(f"[*] 이 파일이 vm_analyze.py와 동일한 디렉토리에 있는지 확인하거나, vm_analyze.py 내부의 파일 경로를 업데이트하세요.")
        
    except ValueError as e:
        print(f"[!] 오류: 잘못된 16진수 문자열입니다. 정리 후 문자열에 16진수 문자(0-9, a-f, A-F)만 포함되어 있는지, 추가 문자나 공백이 없는지 확인하세요. 세부 정보: {e}")
    except Exception as e:
        print(f"[!] 예상치 못한 오류가 발생했습니다: {e}")

if __name__ == "__main__":
    main() 