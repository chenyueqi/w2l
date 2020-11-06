#!/usr/bin/python
## This script generates kernel LLVM bitcode by using command in the format of
## "make CC=clang ./kernel/umh.ll"
## Run this script in PATH_TO_KERNEL_SRC/
## Output: bitcode files 
##         ./PATH_TO_KERNEL_SRC/ll_errout
from __future__ import print_function
from os import listdir
from os.path import isfile, isdir, join, splitext, exists
import sys
import subprocess
import multiprocessing
from  multiprocessing import Pool

sys.stdout.write("Using %s threads...\n"%multiprocessing.cpu_count())
path_list = []

ll_errout = open("./ll_errout", 'w')

def build_ll(objfilepath):
    global ll_errout
    print(objfilepath)
    targetobjfile = splitext(objfilepath)[0]+".ll"
    if (exists(targetobjfile)):
        print("file exists")
        return

    cmd = ['make', 'CC=clang-9', 'KBUILD_CFLAGS=-O0 -Xclang -disable-O0-optnone', targetobjfile]
    subprocess.call(cmd, stderr=ll_errout)

    # remove redundant mem use
    cmd2 = 'opt-9 --dse --mem2reg ' + targetobjfile + ' -o ' + splitext(objfilepath)[0]+'.bc'
    subprocess.call(cmd2.split(' '))

def pre_process(kernel_path):
    global path_list

    dirs = [d for d in listdir(kernel_path) if isdir(join(kernel_path, d))]
    for i in range(len(dirs)):
        pre_process(join(kernel_path, dirs[i]))
    files = [f for f in listdir(kernel_path) if isfile(join(kernel_path, f))]
    for i in range(len(files)):
        if (splitext(join(kernel_path, files[i]))[-1][1:] == "o"):
            #print(join(kernel_path, files[i]))
            path_list.append(join(kernel_path, files[i]))

def process():
    print("%s Objs\n"%len(path_list))
    p = Pool(multiprocessing.cpu_count())
    p.map(build_ll, path_list)


if __name__ == '__main__':
    pre_process("./")
    process()
    sys.exit(0)
