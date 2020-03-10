
all: run

node_modules:
	npm install

.PHONY: install
install: node_modules

.PHONY: run-javashit
run-javashit: node_modules bins
	npx r2r db/extras

.PHONY: run
run: bins
	r2r db/extras/r2db

bins:
	git clone https://github.com/radareorg/radare2-testbins --depth 1 bins
