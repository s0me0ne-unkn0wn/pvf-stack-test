# Experiments

Experiments reside here. Run `make gen && make` in a subdirectory to get artifacts generated, compiled and disassembled.

* `01-empty-func` : Empty functions with increasing number of arguments
* `02-load-args` : Functions with increading number of arguments that load all the arguments on stack and then drop them
* `03-load-args-and-call` : Like previous one, but instead of dropping calls another function which is empty
* `04-locals` : Empty functions with increasing number of locals
* `05-used-locals` : Functions that are using locals in a non-polymorphic way
* `06-used-nondeterm-locals` : Functions are processing locals with another function (effectively rendering locals' values polymorphic/non-deterministic)
* `07-used-nondeterm-locals-stack` : The same as previous, but values are collected on-stack rather that being used in chain
* `08-const-loop` : Process and store constants into memory in a recurrant loop
