wat := $(wildcard *.wat)

all: $(wat)
	for w in *.wat; do \
		wat2wasm $$w >`basename $$w .wat`.wasm; \
	done
	for w in *.wasm; do \
		wasmtime compile $$w; \
	done
	for w in *.cwasm; do \
		objdump -d -M intel $$w >`basename $$w .cwasm`.asm; \
	done

gen:
	for i in `seq -f '%02g' 1 99`; do \
		cat wat.tmpl |perl -pe "s/%param%/join(' ', ('i64') x (0+'$$i'))/e; s/%get%/join(qq|\\n    |, (map { qq|local.get \$$_| } (0..(0+'$$i'-1))))/e; s/%drop%/join(qq|\\n    |, ("drop") x (0+'$$i'))/e" >$$i.wat; \
	done

clean:
	rm -f *.wat *.wasm *.cwasm *.asm

.PHONY: all gen clean