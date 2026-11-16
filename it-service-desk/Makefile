LATEX ?= pdflatex
MAIN  ?= guide

.PHONY: pdf clean

pdf:
	$(LATEX) -interaction=nonstopmode -halt-on-error $(MAIN).tex
	$(LATEX) -interaction=nonstopmode -halt-on-error $(MAIN).tex

clean:
	rm -f $(MAIN).aux $(MAIN).log $(MAIN).out $(MAIN).toc $(MAIN).pdf
