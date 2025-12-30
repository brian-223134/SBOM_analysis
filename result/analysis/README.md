## Analysis Outputs

- [result/analysis/analysis_result.json](result/analysis/analysis_result.json): JSON snapshot of the flattened SBOM package inventory. Each entry lists `Package_Name`, `Status` (`Consistent`, `Conflict`, `Unique`), per-file versions, detection counts, and the files where the package was seen.
- [result/analysis/SBOM_Analysis_Report.xlsx](result/analysis/SBOM_Analysis_Report.xlsx): Multi-sheet Excel report generated from the same data.
  - All_Packages: full package list with file-wise versions, detection count, unique version count, and status.
  - Version_Conflicts: only packages marked `Conflict` (multiple versions across files).
  - Summary_Stats: quick counts of total packages, consistent items, conflicts, and packages unique to a single file.

## How This Is Produced

- Source script: `sbom_analyze.py` consumes every JSON file under `SBOM_json`.
- It recursively extracts package/version pairs, aggregates by package name, and assigns a status:
  - `Unique`: appears in exactly one file.
  - `Consistent`: appears in multiple files with the same version.
  - `Conflict`: appears in multiple files with differing versions.
- It writes both the Excel report and the JSON snapshot to this directory.

## Re-run

Execute from the project root (ensure the virtual environment is active):

```bash
python sbom_analyze.py
```
