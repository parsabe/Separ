# Build the English and German IT security guides (needs latexmk and a TeX Live with babel-german).
GUIDES := guide guide-de

.PHONY: all clean

all: $(GUIDES:=.pdf)

%.pdf: %.tex style.tex
	latexmk -pdf -interaction=nonstopmode -halt-on-error $<

clean:
	latexmk -c $(GUIDES:=.tex)
