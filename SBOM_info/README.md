# SBOM_info

This directory stores reference SBOM artifacts that prime the semantic field analyzer before it processes new SBOM results.

## Purpose

- Provide Upstage AI with contextual SBOM samples and metadata to improve semantic field analysis quality.
- Supply a compact knowledge base that a vector DB can index to answer SBOM-related queries.
- Serve as a staging area for SBOM outputs from multiple generation tools (CycloneDX, SPDX, etc.).

## Typical Contents

- SBOM JSON documents exported from diverse generators.
- Tool-specific notes or mappings that clarify field meanings across formats.
- Minimal metadata to aid vector indexing (e.g., tool name, version, schema flavor).

## Usage

1. Place new SBOM files here; keep filenames descriptive (tool, target, format).
2. Rebuild or refresh the vector DB index after adding or updating files.
3. Run the semantic field analysis; it will leverage this directory as prior context for better precision.

## Maintenance

- Prefer original, unmodified SBOM files for traceability; store any annotations separately if needed.
- Remove obsolete or duplicate artifacts to keep the index focused.
- Document unusual fields or vendor extensions so the analyzer can normalize them.
