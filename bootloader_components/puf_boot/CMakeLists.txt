idf_component_register(
    SRCS "puf_boot.c"
    INCLUDE_DIRS "."
)

target_link_libraries(${COMPONENT_LIB} INTERFACE "-T ${CMAKE_CURRENT_SOURCE_DIR}/puf_boot.ld")
