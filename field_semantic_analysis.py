import json
import os
import openai # Upstage API 호출
from custom_ai import promt # Upstage API 쿼리용 프롬프트 모듈

# openai를 이용하여 각 필드의 의미를 분석하는 코드로 수정 필요

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULT_DIR = os.path.join(BASE_DIR, "result")
RESULT_SUBDIR = os.path.join(RESULT_DIR, "field")
TARGET_DIR = "./SBOM_json"

def semantic_field_analysis(directory_path, output_file=None):
    if not os.path.exists(directory_path):
        print(f"[!] 경로를 찾을 수 없습니다: {directory_path}")
        return

    if output_file is None:
        output_file = os.path.join(RESULT_SUBDIR, "sbom_semantic_field_analysis.json")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    files = [f for f in os.listdir(directory_path) if f.endswith('.json')]
    
    if not files:
        print(f"[!] '{directory_path}' 폴더 안에 JSON 파일이 없습니다.")
        return

    # 전체 분석 결과를 담을 딕셔너리
    total_analysis = {
        "summary": {
            "total_files": len(files),
            "directory": directory_path
        },
        "files": {}
    }

    for file_name in files:
        file_path = os.path.join(directory_path, file_name)
        file_semantic_info = {}

        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
                
                # 각 상위 필드의 의미 분석 (openai를 사용하기)
                for key, value in data.items():
                    semantic_info = {"type": str(type(value).__name__)}
                    
                    if isinstance(value, dict):
                        semantic_info["sub_keys"] = list(value.keys())
                    elif isinstance(value, list):
                        semantic_info["item_count"] = len(value)
                        if len(value) > 0 and isinstance(value[0], dict):
                            semantic_info["item_example_keys"] = list(value[0].keys())
                    else:
                        # 기본 값은 샘플로 앞부분만 저장 (문자열일 경우)
                        semantic_info["sample_value"] = str(value)[:50]
                        
                    file_semantic_info[key] = semantic_info
                
                total_analysis["files"][file_name] = file_semantic_info
                
            except Exception as e:
                total_analysis["files"][file_name] = {"error": str(e)}

    # 결과를 JSON 파일로 저장
    with open(output_file, 'w', encoding='utf-8') as out_f:
        json.dump(total_analysis, out_f, indent=4, ensure_ascii=False)
    
    print(f"[+] 의미 필드 분석 결과가 '{output_file}'에 저장되었습니다.")

if __name__ == "__main__":
    semantic_field_analysis(TARGET_DIR)