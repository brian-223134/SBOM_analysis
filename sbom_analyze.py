import json
import os
import pandas as pd
import matplotlib.pyplot as plt

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULT_DIR = os.path.join(BASE_DIR, "result")
RESULT_SUBDIR = os.path.join(RESULT_DIR, "analysis")

def extract_packages_heuristically(data):
    """JSON 구조에 상관없이 패키지명과 버전을 재귀적으로 추출"""
    found_packages = {}
    def search_recursive(node):
        if isinstance(node, dict):
            name_keys = ['name', 'package', 'component', 'artifactId']
            version_keys = ['version', 'versionInfo', 'ver']
            p_name, p_version = None, ""
            for k, v in node.items():
                k_lower = k.lower()
                if any(nk in k_lower for nk in name_keys) and isinstance(v, str):
                    p_name = v
                if any(vk in k_lower for vk in version_keys) and isinstance(v, (str, int, float)):
                    p_version = str(v)
            if p_name and len(p_name) > 1:
                found_packages[p_name] = p_version
            for v in node.values(): search_recursive(v)
        elif isinstance(node, list):
            for item in node: search_recursive(item)
    search_recursive(data)
    return found_packages

def analyze_sbom_directory(directory_path):
    all_files = [f for f in os.listdir(directory_path) if f.endswith('.json')]
    master_inventory = {} 
    
    for file_name in all_files:
        with open(os.path.join(directory_path, file_name), 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
                extracted = extract_packages_heuristically(data)
                for name, ver in extracted.items():
                    if name not in master_inventory: master_inventory[name] = {}
                    master_inventory[name][file_name] = ver
            except: continue

    analysis_results = []
    for name, apps in master_inventory.items():
        versions = [v for v in apps.values() if v]
        unique_versions = list(set(versions))
        
        status = "Consistent"
        if len(apps) == 1: status = "Unique"
        elif len(unique_versions) > 1: status = "Conflict"
        
        # 엑셀 출력을 위해 데이터를 평탄화
        row = {
            "Package_Name": name,
            "Status": status,
            "Detection_Count": len(apps),
            "Unique_Version_Count": len(unique_versions),
            "Versions_Found": ", ".join(unique_versions),
            "Files_Involved": ", ".join(apps.keys())
        }
        # 각 파일별 버전을 별도 컬럼으로 추가
        for f in all_files:
            row[f] = apps.get(f, "-")
            
        analysis_results.append(row)
    return analysis_results, all_files

def save_to_excel(results, output_file=None):
    """결과를 여러 시트가 포함된 엑셀 파일로 저장"""
    df = pd.DataFrame(results)
    if output_file is None:
        output_file = os.path.join(RESULT_SUBDIR, "SBOM_Analysis_Report.xlsx")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
        # 시트 1: 전체 패키지 매핑 리스트
        df.sort_values(by="Detection_Count", ascending=False).to_excel(writer, sheet_name="All_Packages", index=False)
        
        # 시트 2: 버전 충돌 항목 (별도 필터링)
        conflicts_df = df[df['Status'] == "Conflict"]
        conflicts_df.to_excel(writer, sheet_name="Version_Conflicts", index=False)
        
        # 시트 3: 요약 통계
        summary_data = {
            "Metric": ["Total Unique Packages", "Consistent Packages", "Conflicting Packages", "Unique to One File"],
            "Count": [
                len(df),
                len(df[df['Status'] == "Consistent"]),
                len(df[df['Status'] == "Conflict"]),
                len(df[df['Status'] == "Unique"])
            ]
        }
        pd.DataFrame(summary_data).to_excel(writer, sheet_name="Summary_Stats", index=False)

    print(f"[*] 엑셀 보고서 생성 완료: {output_file}")

def visualize_results(results):
    df = pd.DataFrame(results)
    status_counts = df['Status'].value_counts()
    
    plt.figure(figsize=(8, 6))
    plt.pie(status_counts, labels=status_counts.index, autopct='%1.1f%%', colors=['#66b3ff','#ff9999','#99ff99'])
    plt.title("SBOM Package Status Distribution")
    plt.show()

if __name__ == "__main__":
    DIR_PATH = "./SBOM_json" # JSON 파일들이 위치한 폴더 경로
    os.makedirs(RESULT_DIR, exist_ok=True)
    
    if os.path.exists(DIR_PATH):
        analysis_data, file_list = analyze_sbom_directory(DIR_PATH)
        
        # 1. 엑셀 파일 출력
        save_to_excel(analysis_data)
        
        # 2. JSON 결과 저장 (백업용)
        json_output_path = os.path.join(RESULT_SUBDIR, "analysis_result.json")
        with open(json_output_path, "w", encoding="utf-8") as jf:
            json.dump(analysis_data, jf, indent=2, ensure_ascii=False)
            
        # 3. 시각화 출력
        visualize_results(analysis_data)
    else:
        print(f"[!] 폴더를 찾을 수 없습니다: {DIR_PATH}")