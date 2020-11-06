# setup

1. Download LLVM
2. Move FlexiblePatcher to $(LLVM_SRC)/clang/examples
3. add subdirectory to CMakeLists.txt
```bash
echo "add_subdirectory(FlexiblePatcher)" >> CMakeLists.txt
```
4. Compile LLVM and clang

# How to use
#### Write a wrap
```bash
cat << EOF > clang-wrapper
#/bin/sh
$(LLVM_SRC)/build/bin/clang -Xclang -load -Xclang FlexiblePatcher.so -Xclang -add-plugin -Xclang -flexible-patcher-plugin $@
/usr/bin/clang $@
EOF
```

#### Patch kernel
```bash
make CC="clang-wrapper" allyesconfig
make CC="clang-wrapper" -j$(nproc)
```