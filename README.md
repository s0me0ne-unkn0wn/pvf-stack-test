# pvf-stack-test

Compares logical stack cost estimation made by [wasm-instrument](https://github.com/paritytech/wasm-instrument) to the real stack frame size.

Do NOT use debug build to run tests, it is incredibly slow. Always build release binary.

## Usage
```
USAGE:
    pvf-stack-test [OPTIONS]

OPTIONS:
    -b, --batch-size <BATCH_SIZE>      Batch size [default: 100]
    -h, --help                         Print help information
    -n, --num-batches <NUM_BATCHES>    Number of batches [default: 160]
    -s, --seed <SEED>                  Reproduce a case for single seed, output
                                       out.<seed>.{wasm|cwasm}
    -t, --single-thread                Run in a single thread
    -v, --save                         Save every .wasm and .cwasm (slow)
    -V, --version                      Print version information
```

## Shortcuts

* `make` : Generates `test.log` and `dist.dat` in standard conditions (16000 samples)
* `make disasm` : Produces `.wat` and `.asm` for output files (generated with `--save` or `--seed`)
* `make clean` : Removes output files (generated with `--save` or `--seed`), compiled binaries and disassembly results
* `make plot` : Plots current `dist.dat` with `gnuplot`
* `make calc` : Calculates maximum real_stack_size/estimation ratio in the current `dist.dat` as well as average ratio

## Experiments

See [here](https://github.com/s0me0ne-unkn0wn/pvf-stack-test/tree/main/exp)
