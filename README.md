## About

The drops are base Linux XDP use to proactive defense TCP-SYN flood.

when SYN package count greater than RX_SYN_LIMIT, accept 10  drops 30 package.


## Build dependencies

### Compiling requires having installed:

clang >= version 3.4.0

llvm >= version 3.7.1

Note that LLVM's tool 'llc' must support target 'bpf', list version and supported targets with command: llc --version


## Manually compiling LLVM with 'bpf' support

Since version 3.7.0, LLVM adds a proper LLVM backend target for the BPF bytecode architecture.

By default llvm will build all non-experimental backends including bpf. To generate a smaller llc binary one can use:

```
-DLLVM_TARGETS_TO_BUILD="BPF"
```

Quick sniplet for manually compiling LLVM and clang (build dependencies are cmake and gcc-c++):

```shell
$ git clone http://llvm.org/git/llvm.git
$ cd llvm/tools
$ git clone --depth 1 http://llvm.org/git/clang.git
$ cd ..; mkdir build; cd build
$ cmake .. -DLLVM_TARGETS_TO_BUILD="BPF;X86"
$ make -j $(getconf _NPROCESSORS_ONLN)
```

