## Result Overview

- **analysis/**: Output from sbom_analyze.py. It aggregates all JSONs in SBOM_json, extracts package/version pairs recursively, tags each package as Consistent, Conflict, or Unique, and saves both a multi-sheet Excel report and a JSON snapshot at [result/analysis/analysis_result.json](analysis/analysis_result.json).
- **dependency/**: Output from dependency_visualize.py. It renders the chosen SBOM into an interactive directed graph (root highlighted, components as nodes, dependencies as edges) saved to [result/dependency/sbom_dependency_graph.html](dependency/sbom_dependency_graph.html).
- **field/**: Output from field_extractor.py. It scans top-level keys of each SBOM JSON, records simple type summaries (dict keys, list counts, sample values), and writes the consolidated schema audit to [result/field/sbom_schema_analysis.json](field/sbom_schema_analysis.json).
