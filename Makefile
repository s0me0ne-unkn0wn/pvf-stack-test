all: test.log dist.dat

dist.dat: test.log
	cat test.log |awk '{print $$6,$$8}' |sort |uniq -c |sort -nr |perl -pe 's/^\s+//' >dist.dat

test.log: target/release/pvf-stack-test
	target/release/pvf-stack-test >test.log

target/release/pvf-stack-test: src/main.rs Cargo.toml
	cargo build -r

clean:
	rm -f out* test.log dist.dat

disasm:
	for f in *.cwasm; do objdump -d -M intel $$f >`basename $$f .cwasm`.asm; done
	for f in *.wasm; do wasm2wat $$f -o `basename $$f .wasm`.wat; done

calc: dist.dat
	cat dist.dat |awk '{ v=$$3/$$2; s+=v; if(v>m){m=v; cs=$$2; fr=$$3} } END { print "MAXIMUM", m, "(", cs, ",", fr " )"; print "AVERAGE", s/NR }'
# cat dist.dat |awk '{ v=$$3/$$2; c[NR]=v; s+=v; if(v>m){m=v; cs=$$2; fr=$$3} } END { print "MAXIMUM", m, "(", cs, ",", fr " )"; print "AVERAGE", s/NR; print "MEDIAN ", (NR%2 ? c[(NR+1)/2] : (c[NR/2]+c[(NR/2)+1])/2) }'

plot: dist.dat
	gnuplot -p -e 'set term qt size 1024,768; set xrange [0:1000]; set yrange [0:8000]; set grid; plot "dist.dat" using 2:3:(sqrt($$1)) with circles'

.PHONY: all clean disasm calc plot

