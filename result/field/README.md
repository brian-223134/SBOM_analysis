## Field Schema Output

- [result/field/sbom_schema_analysis.json](result/field/sbom_schema_analysis.json): Consolidated top-level schema summary for all SBOM JSON files. For each file, it lists every top-level key with:
  - `type`: Python type name (`dict`, `list`, `str`, etc.).
  - `sub_keys`: when the value is a dict, its immediate keys.
  - `item_count` and optional `item_example_keys`: when the value is a list (first item inspected if it is a dict).
  - `sample_value`: short sample for primitive values.

## How This Is Produced

- Source script: `field_extractor.py` scans every `.json` under `SBOM_json` and writes the merged schema view to this directory.

## Re-run

From the project root (virtual environment active):

```bash
python field_extractor.py
```
