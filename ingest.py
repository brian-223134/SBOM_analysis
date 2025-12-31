import os
import json
from langchain_upstage import UpstageDocumentParseLoader, UpstageEmbeddings
from langchain_chroma import Chroma
from langchain_text_splitters import RecursiveCharacterTextSplitter


def ingest_sbom_docs(directory_path="./SBOM_info/pdfs", db_path="./SBOM_info/vectordb"):
    # 1. 문서 로드 (Upstage Document Parse 사용)
    with open("secrets.json", "r") as f:
        secrets = json.load(f)

    os.environ["UPSTAGE_API_KEY"] = secrets["UPSTAGE_API_KEY"]

    all_docs = []
    for filename in os.listdir(directory_path):
        if filename.endswith(".pdf") or filename.endswith(".txt"):
            loader = UpstageDocumentParseLoader(
                os.path.join(directory_path, filename), 
                split="page"
            )
            all_docs.extend(loader.load())

    # 2. 문서 분할 (Context 보존을 위해 적절한 크기로 분할)
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=100)
    splits = text_splitter.split_documents(all_docs)

    # 3. Vector DB 저장
    embeddings = UpstageEmbeddings(model="solar-embedding-1-large")
    vectorstore = Chroma.from_documents(
        documents=splits, 
        embedding=embeddings, 
        persist_directory=db_path
    )
    print(f"**Vector DB** 가 {db_path} 에 성공적으로 저장되었습니다.")
    return vectorstore

if __name__ == "__main__":
    ingest_sbom_docs()