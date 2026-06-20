cmake_minimum_required(VERSION 3.16)

set(BOOTLOADER_EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/bootloader_components")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp_puf_s3)
