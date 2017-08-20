project(iceserver)

aux_source_directory(. SRC_LIST)

add_executable(${PROJECT_NAME} ${SRC_LIST})

target_link_libraries(${PROJECT_NAME} pjnath pjlib-util pj
                                        uuid pthread m rt)
