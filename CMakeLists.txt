cmake_minimum_required(VERSION 3.12)

set(PICO_BOARD pico_w)

# Pull in SDK (must be before project)
include(pico_sdk_import.cmake)

include(pico_extras_import_optional.cmake)

project(pico_examples C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

if (PICO_SDK_VERSION_STRING VERSION_LESS "1.3.0")
    message(FATAL_ERROR "Raspberry Pi Pico SDK version 1.3.0 (or later) required. Your version is ${PICO_SDK_VERSION_STRING}")
endif()

# Initialize the SDK
pico_sdk_init()

add_compile_options(-Wall
        -Wno-format          # int != int32_t as far as the compiler is concerned because gcc has int32_t as long int
        -Wno-unused-function # we have some for the docs that aren't called
        )
if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-Wno-maybe-uninitialized)
endif()

add_executable(main
        main.cpp
        Buggy.cpp
        wifi.cpp
        PwmIn.cpp
        QuadMusic.cpp
        )

        pico_generate_pio_header(main ${CMAKE_CURRENT_LIST_DIR}/PwmIn.pio )

        target_include_directories(
                main PRIVATE ${CMAKE_CURRENT_LIST_DIR})

                include(lwip_import.cmake) # lwip config files
                SET(FREERTOS_CONFIG_FILE_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/configs/FreeRTOS-Kernel" CACHE STRING "Local Config")
                include_directories("${FREERTOS_CONFIG_FILE_DIRECTORY}") # FreeRTOS config files

# pull in common dependencies
target_link_libraries(  main 
                        pico_stdlib 
                        hardware_pwm 
                        FreeRTOS-Kernel-Heap4 
                        FREERTOS_PORT 
                        pico_cyw43_arch_lwip_threadsafe_background 
                        LWIP_PORT
                        hardware_rtc
                        hardware_pio
                        hardware_adc )

include(FreeRTOS_Kernel_import.cmake)

# create map/bin/hex/uf2 file etc.
pico_add_extra_outputs(main)
