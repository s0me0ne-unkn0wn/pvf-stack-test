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
		cat wat.tmpl |perl -pe "\
			s/%param%/join(' ', ('i64') x (0+'$$i'))/e; \
			s/%const%/join(qq|\\n    |, (map { qq|i64.const \$$_| } (0..(0+'$$i'-1))))/e; \
			s/%get%/join(qq|\\n    |, (map { qq|local.get \$$_| } (0..(0+'$$i'-1))))/e; \
			s/%set%/join(qq|\\n    |, (map { qq|local.set \$$_| } (0..(0+'$$i'-1))))/e; \
			s/%drop%/join(qq|\\n    |, ('drop') x (0+'$$i'))/e; \
			s/%add%/join(qq|\\n    |, (map { qq|i64.add| } (0..(0+'$$i'-1))))/e; \
			s/%calladd%/join(qq|\\n    |, (map { (qq|local.get \$$_|, qq|call 1|, qq|i64.add|) } (0..(0+'$$i'-1))))/e; \
			s/%getcall%/join(qq|\\n    |, (map { (qq|local.get \$$_|, qq|call 1|) } (0..(0+'$$i'-1))))/e; \
			s/%constand%/join(qq|\\n      |, (map { (qq|i32.const -\$$_|, qq|i32.const \$$_|, qq|i32.store|) } (1..(0+'$$i'))))/e; \
		" >$$i.wat; \
	done

clean:
	rm -f *.wat *.wasm *.cwasm *.asm

.PHONY: all gen clean
