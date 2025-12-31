import json
import os
from langchain_upstage import ChatUpstage, UpstageEmbeddings
from langchain_chroma import Chroma
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from custom_ai.promt import generate_analysis_prompt

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULT_DIR = os.path.join(BASE_DIR, "result")
RESULT_SUBDIR = os.path.join(RESULT_DIR, "field")
TARGET_DIR = "./SBOM_json"
DB_PATH = "./SBOM_info/vectordb" # 미리 구축된 Vector DB 경로

def select_sbom_file(directory):
    """사용자가 분석할 파일을 선택하게 합니다."""
    files = [f for f in os.listdir(directory) if f.endswith('.json')]
    if not files:
        return None
    
    print("\n--- 분석 가능한 SBOM 파일 목록 ---")
    for i, f in enumerate(files):
        print(f"[{i+1}] {f}")
    
    choice = int(input("\n분석할 파일 번호를 입력하세요: ")) - 1
    return files[choice]

def semantic_field_analysis():
    # 1. API 키 및 환경 설정
    with open("secrets.json", 'r') as f:
        secrets = json.load(f)
    os.environ["UPSTAGE_API_KEY"] = secrets.get("UPSTAGE_API_KEY", "")

    # 2. 파일 선택
    selected_filename = select_sbom_file(TARGET_DIR)
    if not selected_filename:
        print("[!] 파일을 찾을 수 없습니다.")
        return

    # 3. 모델 및 Vector DB 로드
    llm = ChatUpstage(model="solar-pro")
    embeddings = UpstageEmbeddings(model="solar-embedding-1-large")
    vectorstore = Chroma(persist_directory=DB_PATH, embedding_function=embeddings)

    # 4. JSON 로드
    file_path = os.path.join(TARGET_DIR, selected_filename)
    with open(file_path, 'r', encoding='utf-8') as f:
        sbom_data = json.load(f)

    # Hatbom 구조 대응 (루트의 'sbom' 필드 혹은 전체 데이터)
    actual_data = sbom_data.get("sbom", sbom_data)
    
    print(f"[*] '{selected_filename}' 분석을 시작합니다...")
    analysis_results = []

    sys_msg_template, human_msg_template = generate_analysis_prompt()

    # 5. 각 필드별 RAG 분석 진행
    # 주요 상위 필드(metadata, components, dependencies 등) 분석
    for key, value in actual_data.items():
        # A. Vector DB 에서 관련 지식 검색
        docs = vectorstore.similarity_search(key, k=2)
        context = "\n\n".join([doc.page_content for doc in docs])

        # B. 템플릿 생성
        prompt_template = ChatPromptTemplate.from_messages([
            ("system", sys_msg_template),
            ("human", human_msg_template)
        ])
        
        # C. 체인 구성
        chain = prompt_template | llm | JsonOutputParser()
        
        try:
            # D. invoke 시점에 모든 변수를 전달합니다.
            # 이렇게 하면 LangChain이 내부적으로 중괄호를 안전하게 치환합니다.
            result = chain.invoke({
                "field_name": key,
                "field_value": str(value)[:500], # 데이터 샘플 전달
                "context": context
            })
            
            analysis_results.append(result)
            print(f"  > 필드 '{key}' 분석 완료")
            
        except Exception as e:
            print(f"  > 필드 '{key}' 분석 실패: {e}")

    # 6. 결과 저장 (파일명 규칙 적용)
    base_name = os.path.splitext(selected_filename)[0]
    output_filename = f"{base_name}_semantic_result.json"
    output_path = os.path.join(RESULT_SUBDIR, output_filename)
    
    os.makedirs(RESULT_SUBDIR, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as out_f:
        json.dump({"source_file": selected_filename, "analysis": analysis_results}, out_f, indent=4, ensure_ascii=False)

    print(f"\n[+] 분석 성공! 결과 저장: {output_path}")

if __name__ == "__main__":
    semantic_field_analysis()