import json
import os

def analyze_and_export_schema(directory_path, output_file="sbom_schema_analysis.json"):
    if not os.path.exists(directory_path):
        print(f"[!] 경로를 찾을 수 없습니다: {directory_path}")
        return

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
        file_schema = {}

        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
                
                # 각 상위 필드 분석
                for key, value in data.items():
                    info = {"type": str(type(value).__name__)}
                    
                    if isinstance(value, dict):
                        info["sub_keys"] = list(value.keys())
                    elif isinstance(value, list):
                        info["item_count"] = len(value)
                        if len(value) > 0 and isinstance(value[0], dict):
                            info["item_example_keys"] = list(value[0].keys())
                    else:
                        # 기본 값은 샘플로 앞부분만 저장 (문자열일 경우)
                        info["sample_value"] = str(value)[:50]
                        
                    file_schema[key] = info
                
                total_analysis["files"][file_name] = file_schema
                
            except Exception as e:
                total_analysis["files"][file_name] = {"error": str(e)}

    # 최종 결과를 JSON 파일로 저장
    with open(output_file, 'w', encoding='utf-8') as out_f:
        json.dump(total_analysis, out_f, indent=4, ensure_ascii=False)

    print(f"[*] 분석이 완료되었습니다. 결과 파일: {output_file}")

if __name__ == "__main__":
    TARGET_DIR = "./SBOM_json"
    analyze_and_export_schema(TARGET_DIR)