# The Separ paper

`main.tex` is the paper about Separ **v2.4** (tag `v2.4`): a host-based, pre-execution command
mediation layer and behavioural monitor for Linux. About seven pages plus a one-column appendix.

Every number in the paper is a macro from `numbers.tex`, and every chart is a PDF in `figures/`.
Both are generated from the committed evaluation data, so a later version or a pilot only needs new
data and:

```bash
make -C documentation numbers figures pdf overleaf-zip   # or: make -C documentation all
```

| File | What it is | Made by |
|---|---|---|
| `main.tex` | the manuscript (two-column, natbib/plainnat) | by hand; no typed numbers |
| `numbers.tex` | one `\newcommand` per number: counts, percentages, Wilson 95 % intervals, thresholds, seed, version, the control tables | `scripts/paper_numbers.py` (tested by `tests/test_paper_numbers.py`) |
| `figures/fig_*.pdf` | the charts (and PNG copies in `docs/img/`) | `make_figures.py` |
| `references.bib` | the bibliography; entries with `note = {TODO verify}` must be checked before submission | by hand |
| `separ-paper-overleaf.zip` | `main.tex`, `numbers.tex`, `references.bib` and the charts, for Overleaf | `make overleaf-zip` |
| `diagrams.tex`, `diagrams/` | the older level-by-level diagram book (not part of the paper) | by hand |

Inputs of the generators: `docs/evaluation/v2.4-seed-335384967.jsonl` (the variants),
`docs/evaluation/lab-reference-run-v2.4.json` (the Attack Lab, from `scripts/lab_reference_run.py`),
the golden catalog in `tests/golden/`, the privacy audit (`refmon.audit`, run by the script),
`docs/variant-seeds.md` and the default policy. Facts about commands, files and identifiers are in
`docs/it-facts.md`.

`\todo{...}` in the text marks a fact the repository does not hold (for example a measured Falco
baseline); the build prints it in red.
