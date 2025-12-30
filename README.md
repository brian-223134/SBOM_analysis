## Purpose

- Analyze SBOM JSON files to extract package inventories, detect version conflicts, visualize dependency graphs, and summarize schema fields.

## Python Scripts

- [sbom_analyze.py](sbom_analyze.py): Recursively extract package/version pairs from all JSONs in SBOM_json, classify status (Unique, Consistent, Conflict), and output Excel/JSON reports under result/analysis.
- [dependency_visualize.py](dependency_visualize.py): Build an interactive PyVis dependency graph from a selected SBOM JSON and save it to result/dependency.
- [field_extractor.py](field_extractor.py): Summarize top-level schema fields across SBOM JSONs and write the consolidated view to result/field.

## Directory Structure

- SBOM_json/ — Input SBOM JSON files to analyze.
- result/
  - analysis/ — Package inventory reports (JSON + Excel).
  - dependency/ — Interactive dependency graph HTML.
  - field/ — Schema summary JSON. It serves SBOM fields metadata which includes fields, number of data in each field.
- lib/ — Frontend assets (PyVis dependencies and UI libraries).
- requirements.txt — Python dependencies.

## Setup After Clone (Windows)

### Option A: venv

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Option B: uv

```bash
pip install uv
uv venv .venv
.venv\Scripts\activate
uv pip install -r requirements.txt
```

## Running

- Package analysis report: `python sbom_analyze.py`
- Dependency graph: `python dependency_visualize.py`
- Field/schema summary: `python field_schema_extractor.py`
