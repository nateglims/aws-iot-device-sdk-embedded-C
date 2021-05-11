# Macro utility to clone a library and source-related submodules.
macro( clone_path path )
    # Attempt to clone submodules.
    if( ${BUILD_CLONE_SUBMODULES} )
        find_package( Git REQUIRED )
        execute_process( COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive ${ARGV1} -- ${path}
                         WORKING_DIRECTORY ${ROOT_DIR}
                         RESULT_VARIABLE LIB_CLONE_RESULT )
        if( NOT ${LIB_CLONE_RESULT} STREQUAL "0" )
            message( FATAL_ERROR "Failed to clone submodules." )
        endif()
    endif()
endmacro()

# Add build configuration for all 3rd party modules.
add_subdirectory(${3RDPARTY_DIR})
