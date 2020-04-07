
all: run

.PHONY: run
run: bins
	r2r -L db/extras/r2db

bins:
	git clone https://github.com/radareorg/radare2-testbins --depth 1 bins
