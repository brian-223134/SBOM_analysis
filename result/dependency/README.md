## Dependency Graph Output

- [result/dependency/sbom_dependency_graph.html](result/dependency/sbom_dependency_graph.html): Interactive PyVis network built from a selected SBOM JSON. Nodes are components (root highlighted and enlarged), edges represent dependency links. Pan/zoom and hover tooltips are available in the browser.

## How This Is Produced

- Source script: `dependency_visualize.py` (uses `pyvis`).
- It prompts you to pick a JSON under `SBOM_json`, loads `metadata.component` as the root node, adds all `components` as nodes, and wires edges from `dependencies[].ref` to each `dependsOn` entry.
- Layout: ForceAtlas2 tuning to reduce overlap; root in orange, dependencies in blue, directed edges in gray.

## Re-run

From the project root (with the virtual environment active):

```bash
python dependency_visualize.py
```

Then open the generated HTML in a browser.
