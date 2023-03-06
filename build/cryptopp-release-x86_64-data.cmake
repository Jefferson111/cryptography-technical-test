########### AGGREGATED COMPONENTS AND DEPENDENCIES FOR THE MULTI CONFIG #####################
#############################################################################################

list(APPEND cryptopp_COMPONENT_NAMES cryptopp::cryptopp)
list(REMOVE_DUPLICATES cryptopp_COMPONENT_NAMES)
set(cryptopp_FIND_DEPENDENCY_NAMES "")

########### VARIABLES #######################################################################
#############################################################################################
set(cryptopp_PACKAGE_FOLDER_RELEASE "/home/user/.conan2/p/cryptc55d07cd30140/p")
set(cryptopp_BUILD_MODULES_PATHS_RELEASE )


set(cryptopp_INCLUDE_DIRS_RELEASE "${cryptopp_PACKAGE_FOLDER_RELEASE}/include")
set(cryptopp_RES_DIRS_RELEASE )
set(cryptopp_DEFINITIONS_RELEASE )
set(cryptopp_SHARED_LINK_FLAGS_RELEASE )
set(cryptopp_EXE_LINK_FLAGS_RELEASE )
set(cryptopp_OBJECTS_RELEASE )
set(cryptopp_COMPILE_DEFINITIONS_RELEASE )
set(cryptopp_COMPILE_OPTIONS_C_RELEASE )
set(cryptopp_COMPILE_OPTIONS_CXX_RELEASE )
set(cryptopp_LIB_DIRS_RELEASE "${cryptopp_PACKAGE_FOLDER_RELEASE}/lib")
set(cryptopp_BIN_DIRS_RELEASE )
set(cryptopp_LIBRARY_TYPE_RELEASE STATIC)
set(cryptopp_IS_HOST_WINDOWS_RELEASE 0)
set(cryptopp_LIBS_RELEASE cryptopp)
set(cryptopp_SYSTEM_LIBS_RELEASE pthread m)
set(cryptopp_FRAMEWORK_DIRS_RELEASE )
set(cryptopp_FRAMEWORKS_RELEASE )
set(cryptopp_BUILD_DIRS_RELEASE )
set(cryptopp_NO_SONAME_MODE_RELEASE FALSE)


# COMPOUND VARIABLES
set(cryptopp_COMPILE_OPTIONS_RELEASE
    "$<$<COMPILE_LANGUAGE:CXX>:${cryptopp_COMPILE_OPTIONS_CXX_RELEASE}>"
    "$<$<COMPILE_LANGUAGE:C>:${cryptopp_COMPILE_OPTIONS_C_RELEASE}>")
set(cryptopp_LINKER_FLAGS_RELEASE
    "$<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,SHARED_LIBRARY>:${cryptopp_SHARED_LINK_FLAGS_RELEASE}>"
    "$<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,MODULE_LIBRARY>:${cryptopp_SHARED_LINK_FLAGS_RELEASE}>"
    "$<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,EXECUTABLE>:${cryptopp_EXE_LINK_FLAGS_RELEASE}>")


set(cryptopp_COMPONENTS_RELEASE cryptopp::cryptopp)
########### COMPONENT cryptopp::cryptopp VARIABLES ############################################

set(cryptopp_cryptopp_cryptopp_INCLUDE_DIRS_RELEASE "${cryptopp_PACKAGE_FOLDER_RELEASE}/include")
set(cryptopp_cryptopp_cryptopp_LIB_DIRS_RELEASE "${cryptopp_PACKAGE_FOLDER_RELEASE}/lib")
set(cryptopp_cryptopp_cryptopp_BIN_DIRS_RELEASE )
set(cryptopp_cryptopp_cryptopp_LIBRARY_TYPE_RELEASE STATIC)
set(cryptopp_cryptopp_cryptopp_IS_HOST_WINDOWS_RELEASE 0)
set(cryptopp_cryptopp_cryptopp_RES_DIRS_RELEASE )
set(cryptopp_cryptopp_cryptopp_DEFINITIONS_RELEASE )
set(cryptopp_cryptopp_cryptopp_OBJECTS_RELEASE )
set(cryptopp_cryptopp_cryptopp_COMPILE_DEFINITIONS_RELEASE )
set(cryptopp_cryptopp_cryptopp_COMPILE_OPTIONS_C_RELEASE "")
set(cryptopp_cryptopp_cryptopp_COMPILE_OPTIONS_CXX_RELEASE "")
set(cryptopp_cryptopp_cryptopp_LIBS_RELEASE cryptopp)
set(cryptopp_cryptopp_cryptopp_SYSTEM_LIBS_RELEASE pthread m)
set(cryptopp_cryptopp_cryptopp_FRAMEWORK_DIRS_RELEASE )
set(cryptopp_cryptopp_cryptopp_FRAMEWORKS_RELEASE )
set(cryptopp_cryptopp_cryptopp_DEPENDENCIES_RELEASE )
set(cryptopp_cryptopp_cryptopp_SHARED_LINK_FLAGS_RELEASE )
set(cryptopp_cryptopp_cryptopp_EXE_LINK_FLAGS_RELEASE )
set(cryptopp_cryptopp_cryptopp_NO_SONAME_MODE_RELEASE FALSE)

# COMPOUND VARIABLES
set(cryptopp_cryptopp_cryptopp_LINKER_FLAGS_RELEASE
        $<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,SHARED_LIBRARY>:${cryptopp_cryptopp_cryptopp_SHARED_LINK_FLAGS_RELEASE}>
        $<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,MODULE_LIBRARY>:${cryptopp_cryptopp_cryptopp_SHARED_LINK_FLAGS_RELEASE}>
        $<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,EXECUTABLE>:${cryptopp_cryptopp_cryptopp_EXE_LINK_FLAGS_RELEASE}>
)
set(cryptopp_cryptopp_cryptopp_COMPILE_OPTIONS_RELEASE
    "$<$<COMPILE_LANGUAGE:CXX>:${cryptopp_cryptopp_cryptopp_COMPILE_OPTIONS_CXX_RELEASE}>"
    "$<$<COMPILE_LANGUAGE:C>:${cryptopp_cryptopp_cryptopp_COMPILE_OPTIONS_C_RELEASE}>")