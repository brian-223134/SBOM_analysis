import json
import os
from pyvis.network import Network

def get_sbom_files(directory):
    """지정한 디렉토리 내의 json 파일 목록을 반환합니다."""
    if not os.path.exists(directory):
        print(f" 에러: '{directory}' 폴더를 찾을 수 없습니다.")
        return []
    return [f for f in os.listdir(directory) if f.endswith('.json')]

def visualize_with_pyvis(file_path):
    """pyvis를 사용하여 인터랙티브한 HTML 의존성 그래프를 생성합니다."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            sbom = json.load(f)
    except Exception as e:
        print(f" 파일을 읽는 중 오류 발생: {e} ")
        return

    # 1. Network 설정 (배경색, 방향성, 물리 엔진 등)
    # font_color와 bgcolor를 조절하여 눈의 피로도를 줄였습니다.
    net = Network(height="900px", width="100%", bgcolor="#ffffff", font_color="black", directed=True)
    
    # 2. 물리 엔진(Force Atlas 2) 설정: 노드들이 서로 밀어내어 겹침을 방지합니다.
    net.force_atlas_2based(gravity=-50, central_gravity=0.01, spring_length=100, spring_strength=0.08, damping=0.4)

    name_map = {}
    
    # 3. 데이터 매핑 및 노드 추가
    # Metadata Root Component
    root_comp = sbom.get('metadata', {}).get('component', {})
    if root_comp:
        ref = root_comp.get('bom-ref')
        name = root_comp.get('name', 'Root')
        name_map[ref] = f"ROOT: {name}"
        # 루트 노드는 강조를 위해 색상과 크기를 다르게 설정
        net.add_node(ref, label=name_map[ref], title=f"Version: {root_comp.get('version')}", 
                     color="#FF5733", size=40, font={'size': 20})

    # Components
    for comp in sbom.get('components', []):
        ref = comp.get('bom-ref')
        name = comp.get('name')
        version = comp.get('version', '')
        name_map[ref] = f"{name}\n({version})"
        
        # 일반 노드 추가 (폰트 크기를 줄여 산만함 감소)
        net.add_node(ref, label=name_map[ref], title=f"purl: {comp.get('purl')}", 
                     color="#3498DB", size=20, font={'size': 12})

    # 4. 의존 관계(Edge) 추가
    dependencies = sbom.get('dependencies', [])
    for dep in dependencies:
        parent_ref = dep.get('ref')
        for child_ref in dep.get('dependsOn', []):
            # 두 노드가 모두 정의되어 있는 경우에만 연결
            if parent_ref in name_map and child_ref in name_map:
                net.add_edge(parent_ref, child_ref, color="#ABB2B9", width=1)

    # 5. UI 제어판 추가 (브라우저에서 직접 물리 법칙이나 색상을 튜닝할 수 있음)
    # net.show_buttons(filter_=['physics']) # 주석을 해제하면 브라우저에서 설정 조절 가능

    output_file = "sbom_dependency_graph.html"
    net.show(output_file, notebook=False)
    print(f"\n 시각화 완료! 브라우저에서 '{output_file}' 파일을 확인하세요.")

if __name__ == "__main__":
    target_dir = "SBOM_json"
    files = get_sbom_files(target_dir)

    if not files:
        print(f" '{target_dir}' 폴더에 분석할 JSON 파일이 없습니다.")
    else:
        print("\n--- [ SBOM 파일 목록 ] ---")
        for i, f in enumerate(files):
            print(f"[{i}] {f}")
        
        try:
            choice = int(input("\n시각화할 파일 번호를 입력하세요: "))
            if 0 <= choice < len(files):
                selected_file = os.path.join(target_dir, files[choice])
                visualize_with_pyvis(selected_file)
            else:
                print(" 잘못된 번호입니다.")
        except ValueError:
            print(" 숫자를 입력해 주세요.")