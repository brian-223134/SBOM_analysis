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
DB_PATH = "./SBOM_info/vectordb"

def select_sbom_file_and_type(directory):
    """분석할 파일과 해당 파일의 SBOM 양식을 선택합니다."""
    # 1. 파일 선택
    files = [f for f in os.listdir(directory) if f.endswith('.json')]
    if not files:
        return None, None
    
    print("\n--- [1] 분석할 SBOM 파일 선택 ---")
    for i, f in enumerate(files):
        print(f"[{i+1}] {f}")
    
    f_choice = int(input("\n분석할 파일 번호를 입력하세요: ")) - 1
    selected_file = files[f_choice]

    # 2. 양식 선택 (Vector DB 필터링 및 프롬프트용)
    formats = ["cyclonedx", "github", "hatbom", "syft", "trivy"]
    print("\n--- [2] 해당 파일의 SBOM 양식 선택 ---")
    for i, fmt in enumerate(formats):
        print(f"[{i+1}] {fmt}")
    
    t_choice = int(input("\n양식 번호를 선택하세요: ")) - 1
    selected_format = formats[t_choice]

    return selected_file, selected_format

def semantic_field_analysis():
    # 1. API 키 및 환경 설정
    if not os.path.exists("secrets.json"):
        print("[!] 'secrets.json' 파일이 없습니다.")
        return

    with open("secrets.json", 'r') as f:
        secrets = json.load(f)
    os.environ["UPSTAGE_API_KEY"] = secrets.get("UPSTAGE_API_KEY", "")

    # 2. 파일 및 양식 선택
    selected_filename, sbom_type = select_sbom_file_and_type(TARGET_DIR)
    if not selected_filename:
        print("[!] 진행 가능한 파일이 없습니다.")
        return

    # 3. 모델 및 Vector DB 로드
    llm = ChatUpstage(model="solar-pro")
    embeddings = UpstageEmbeddings(model="solar-embedding-1-large")
    
    if not os.path.exists(DB_PATH):
        print(f"[!] Vector DB 가 {DB_PATH} 에 없습니다. 인덱싱을 먼저 진행하세요.")
        return
        
    vectorstore = Chroma(persist_directory=DB_PATH, embedding_function=embeddings)

    # 4. JSON 데이터 로드
    file_path = os.path.join(TARGET_DIR, selected_filename)
    with open(file_path, 'r', encoding='utf-8') as f:
        sbom_data = json.load(f)

    # 루트 필드가 'sbom'인 경우와 아닌 경우 대응
    actual_data = sbom_data.get("sbom", sbom_data)
    
    print(f"\n[*] '{selected_filename}' ({sbom_type}) 분석을 시작합니다...")
    analysis_results = []

    # 프롬프트 템플릿 뼈대 가져오기
    sys_msg_template, human_msg_template = generate_analysis_prompt()

    # 5. 각 필드별 RAG 분석 진행
    for key, value in actual_data.items():
        # A. 메타데이터 필터링을 적용하여 관련 지식 검색
        # 사용자가 선택한 sbom_type 과 일치하는 문서만 DB에서 가져옵니다.
        docs = vectorstore.similarity_search(
            key, 
            k=3, 
            filter={"sbom_type": sbom_type}
        )
        context = "\n\n".join([doc.page_content for doc in docs])

        # B. 템플릿 구성
        prompt_template = ChatPromptTemplate.from_messages([
            ("system", sys_msg_template),
            ("human", human_msg_template)
        ])
        
        # C. 체인 구성
        chain = prompt_template | llm | JsonOutputParser()
        
        try:
            # D. 모든 변수(sbom_type 포함)를 전달하여 분석 수행
            result = chain.invoke({
                "sbom_type": sbom_type,
                "field_name": key,
                "field_value": str(value)[:500],
                "context": context
            })
            
            analysis_results.append(result)
            print(f"  > 필드 '{key}' 분석 완료")
            
        except Exception as e:
            print(f"  > 필드 '{key}' 분석 실패: {e}")

    # 6. 결과 저장
    base_name = os.path.splitext(selected_filename)[0]
    output_filename = f"{base_name}_semantic_result.json"
    output_path = os.path.join(RESULT_SUBDIR, output_filename)
    
    os.makedirs(RESULT_SUBDIR, exist_ok=True)
    final_output = {
        "source_file": selected_filename,
        "sbom_type": sbom_type,
        "analysis": analysis_results
    }
    
    with open(output_path, 'w', encoding='utf-8') as out_f:
        json.dump(final_output, out_f, indent=4, ensure_ascii=False)

    print(f"\n[+] 분석 성공! 결과 저장: {output_path}")

if __name__ == "__main__":
    semantic_field_analysis()