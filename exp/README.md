# Experiments

Experiments reside here. Run `make gen && make` in a subdirectory to get artifacts generated, compiled and disassembled.

* `01-empty-func` : Empty functions with increasing number of arguments
* `02-load-args` : Functions with increading number of arguments that load all the arguments on stack and then drop them
* `03-load-args-and-call` : Like previous one, but instead of dropping calls another function which is empty
* `04-locals` : Empty functions with increasing number of locals
