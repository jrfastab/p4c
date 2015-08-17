.PHONY: all clean
# Find Menhir.
MENHIR := menhir

TARGETS		:= targets/match targets/bpf

MENHIRFLAGS     := --infer

OCAMLBUILD      := ocamlbuild -use-ocamlfind -use-menhir -menhir "$(MENHIR) $(MENHIRFLAGS)" -Is "$(TARGETS)"

MAIN            := p4c

all:
	$(OCAMLBUILD) -cflags -g $(MAIN).native

clean:
	rm -f *~
	$(OCAMLBUILD) -clean
