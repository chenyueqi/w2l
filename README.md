### First Things First
This repo is the code repo for CCS 2020 paper "[A Systematic Study of Elastic Objects in Kernel Exploitation](http://www.personal.psu.edu/yxc431/publications/ELOISE.pdf)"

### Organization
/code - LLVM implementation of static analysis
/inputs - Programs that can manipulate elastic objects in the Linux kernel and XNU 
/scripts - Scripts that help building this repo
/vm - Virtual Machine for kernel fuzzing and exploitation
/kernels - The IR code of FreeBSD, Linux 5.5.3 (ting, defconfig), and xnu-4906.241.1 (xnudeps)
/human-study - PoCs and environments for vulnerabilities used in human study
/defense - Hardend kernel using the isolation mechanism described in the paper

### Notes
The method of identifying the elastic objects and design of the hardening technique described in the paper and implemented in this code are in the proccess of applying for a patent.
