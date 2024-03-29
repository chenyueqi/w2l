### First Things First
This repo is the code repo for CCS 2020 paper "[A Systematic Study of Elastic Objects in Kernel Exploitation](http://www.personal.psu.edu/yxc431/publications/ELOISE.pdf)"

### Organization
code - LLVM implementation of static analysis  
defense - Hardend kernel using the isolation mechanism described in the paper  
inputs - Programs that can manipulate elastic objects in FreeBSD, Linux, and XNU   
kernels - The IR code of FreeBSD, Linux 5.5.3 (tiny, defconfig), and xnu-4906.241.1 (xnudeps)  
scripts - Scripts that help building this repo  
vm - Scripts to setup virtual Machine for kernel fuzzing and exploitation  
human-study - PoCs and environments for vulnerabilities used in human study  

### Build
Please check `scripts/build_essential.sh` for the setup of the environment.

Please see [this patch](https://github.com/Markakd/LLVM-O0-BitcodeWriter) to build a clang that will generate a complete set of O0 bitcode for Linux kernel.

### Notes
The method of identifying the elastic objects and the design of the hardening technique described in the paper and implemented in this code repo are in the proccess of applying for a patent.

### Contact
Please email to ychen@ist.psu.edu if you have questions.
