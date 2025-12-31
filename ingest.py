import os
import json
from langchain_upstage import UpstageDocumentParseLoader, UpstageEmbeddings
from langchain_chroma import Chroma
from langchain_text_splitters import RecursiveCharacterTextSplitter

def select_file_and_format(directory_path):
    """사용자로부터 파일과 SBOM 양식을 입력받습니다."""
    # 1. 파일 선택
    files = [f for f in os.listdir(directory_path) if f.endswith(('.pdf', '.txt'))]
    if not files:
        print(f"[!] {directory_path} 에 분석 가능한 파일이 없습니다.")
        return None, None

    print("\n--- [1] 학습할 논문/문서 선택 ---")
    for i, f in enumerate(files):
        print(f"[{i+1}] {f}")
    
    file_idx = int(input("파일 번호를 선택하세요: ")) - 1
    selected_file = files[file_idx]

    # 2. SBOM 양식 선택
    formats = ["cyclonedx", "github", "hatbom", "syft", "trivy"]
    print("\n--- [2] 해당 문서의 SBOM 양식 선택 ---")
    for i, fmt in enumerate(formats):
        print(f"[{i+1}] {fmt}")
    
    fmt_idx = int(input("양식 번호를 선택하세요: ")) - 1
    selected_format = formats[fmt_idx]

    return selected_file, selected_format

def ingest_sbom_docs(directory_path="./SBOM_info/pdfs", db_path="./SBOM_info/vectordb"):
    # 1. 설정 및 API 키 로드
    with open("secrets.json", "r") as f:
        secrets = json.load(f)
    os.environ["UPSTAGE_API_KEY"] = secrets["UPSTAGE_API_KEY"]

    # 2. 파일 및 양식 선택
    filename, sbom_type = select_file_and_format(directory_path)
    if not filename: return

    print(f"\n[*] '{filename}'을(를) '{sbom_type}' 카테고리로 학습을 시작합니다...")

    # 3. 문서 로드 (Upstage Document Parse)
    file_full_path = os.path.join(directory_path, filename)
    loader = UpstageDocumentParseLoader(file_full_path, split="page")
    docs = loader.load()

    # 4. 문서 분할 및 메타데이터 주입
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=100)
    splits = text_splitter.split_documents(docs)

    for split in splits:
        # 각 데이터 조각에 SBOM 양식 정보를 추가합니다.
        split.metadata["sbom_type"] = sbom_type
        split.metadata["source_file"] = filename

    # 5. Vector DB 저장 (기존 DB가 있으면 데이터가 추가됩니다)
    embeddings = UpstageEmbeddings(model="solar-embedding-1-large")
    vectorstore = Chroma.from_documents(
        documents=splits, 
        embedding=embeddings, 
        persist_directory=db_path
    )
    
    print(f"\n[+] **Vector DB** 에 '{filename}' ({sbom_type}) 저장이 완료되었습니다.")
    print(f"저장된 경로: {db_path}")

if __name__ == "__main__":
    ingest_sbom_docs()