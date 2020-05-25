add_llvm_library(FlexiblePatcher MODULE FlexiblePatcher.cpp PLUGIN_TOOL clang)

if(LLVM_ENABLE_PLUGINS AND (WIN32 OR CYGWIN))
  target_link_libraries(FlexiblePatcher PRIVATE
    clangAST
    clangBasic
    clangFrontend
    LLVMSupport
    )
endif()
