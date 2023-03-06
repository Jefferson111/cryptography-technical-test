set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED true)

include(CTest)
enable_testing()

add_executable(client client.cpp)
target_link_libraries(client PUBLIC ${CONAN_LIBS})
target_include_directories(client PUBLIC "${PROJECT_BINARY_DIR}") 

add_executable(server server.cpp)
target_link_libraries(server PUBLIC ${CONAN_LIBS})
target_include_directories(server PUBLIC "${PROJECT_BINARY_DIR}")  
                            
set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
