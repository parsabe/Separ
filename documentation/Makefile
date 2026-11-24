# Build the Separ paper (two-column LaTeX), its numbers and charts, the diagram book, or an Overleaf zip.
# Every number in main.tex comes from numbers.tex (scripts/paper_numbers.py) and every chart from
# figures/ (make_figures.py); both are generated from the committed data in docs/evaluation/.
# The charts need the paper extra: pip install -e ".[paper]" in the repository root.

PY    ?= ../.venv/bin/python
MAIN  ?= main

.PHONY: pdf numbers figures all diagrams overleaf-zip clean

pdf:
	latexmk -pdf -interaction=nonstopmode -halt-on-error $(MAIN).tex

numbers:
	$(PY) ../scripts/paper_numbers.py

figures:
	$(PY) make_figures.py

all: numbers figures pdf overleaf-zip

diagrams:
	latexmk -pdf -interaction=nonstopmode -halt-on-error diagrams.tex

overleaf-zip:
	rm -f separ-paper-overleaf.zip refmon-paper-overleaf.zip
	zip -q -r separ-paper-overleaf.zip $(MAIN).tex numbers.tex references.bib figures/fig_*.pdf diagrams/styles.tex diagrams/separ-flow.tex

clean:
	latexmk -C $(MAIN).tex diagrams.tex
	rm -f separ-paper-overleaf.zip
