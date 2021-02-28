

list(APPEND SOURCES_RANDOMX
    ${CMAKE_SOURCE_DIR}/xmrstak/backend/cpu/crypto/randomx/allocator.cpp
    ${CMAKE_SOURCE_DIR}/xmrstak/backend/cpu/crypto/randomx/argon2_core.c
    ${CMAKE_SOURCE_DIR}/xmrstak/backend/cpu/crypto/randomx/argon2_ref.c
    ${CMAKE_SOURCE_DIR}/xmrstak/backend/cpu/crypto/randomx/blake2_generator.cpp
    ${CMAKE_SOURCE_DIR}/xmrstak/backend/cpu/crypto/randomx/blake2/blake2b.c
    ${CMAKE_SOURCE_DIR}/xmrstak/backend/cpu/crypto/randomx/virtual_memory.cpp
)

if(CMAKE_C_COMPILER_ID MATCHES MSVC)
    enable_language(ASM_MASM)
    list(APPEND SOURCES_RANDOMX
         ${CMAKE_SOURCE_DIR}/xmrstak/backend/cpu/crypto/randomx/jit_compiler_x86_static.asm
         ${CMAKE_SOURCE_DIR}/xmrstak/backend/cpu/crypto/common/VirtualMemory_win.cpp
        )
elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
    list(APPEND SOURCES_RANDOMX
         ${CMAKE_SOURCE_DIR}/xmrstak/backend/cpu/crypto/randomx/jit_compiler_x86_static.S
         ${CMAKE_SOURCE_DIR}/xmrstak/backend/cpu/crypto/common/VirtualMemory_unix.cpp
        )
    # cheat because cmake and ccache hate each other
    set_property(SOURCE ${CMAKE_SOURCE_DIR}/xmrstak/backend/cpu/crypto/randomx/jit_compiler_x86_static.S PROPERTY LANGUAGE C)
endif()

add_library(xmr-stak-randomx
    STATIC
    ${SOURCES_RANDOMX}
)
set_property(TARGET xmr-stak-randomx PROPERTY POSITION_INDEPENDENT_CODE ON)