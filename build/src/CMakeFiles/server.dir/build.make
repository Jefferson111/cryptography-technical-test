# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/user/Desktop/Documents/technical-test

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/user/Desktop/Documents/technical-test/build

# Include any dependencies generated for this target.
include src/CMakeFiles/server.dir/depend.make

# Include the progress variables for this target.
include src/CMakeFiles/server.dir/progress.make

# Include the compile flags for this target's objects.
include src/CMakeFiles/server.dir/flags.make

src/CMakeFiles/server.dir/server.cpp.o: src/CMakeFiles/server.dir/flags.make
src/CMakeFiles/server.dir/server.cpp.o: ../src/server.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/user/Desktop/Documents/technical-test/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object src/CMakeFiles/server.dir/server.cpp.o"
	cd /home/user/Desktop/Documents/technical-test/build/src && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/server.dir/server.cpp.o -c /home/user/Desktop/Documents/technical-test/src/server.cpp

src/CMakeFiles/server.dir/server.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/server.dir/server.cpp.i"
	cd /home/user/Desktop/Documents/technical-test/build/src && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/user/Desktop/Documents/technical-test/src/server.cpp > CMakeFiles/server.dir/server.cpp.i

src/CMakeFiles/server.dir/server.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/server.dir/server.cpp.s"
	cd /home/user/Desktop/Documents/technical-test/build/src && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/user/Desktop/Documents/technical-test/src/server.cpp -o CMakeFiles/server.dir/server.cpp.s

# Object files for target server
server_OBJECTS = \
"CMakeFiles/server.dir/server.cpp.o"

# External object files for target server
server_EXTERNAL_OBJECTS =

src/server: src/CMakeFiles/server.dir/server.cpp.o
src/server: src/CMakeFiles/server.dir/build.make
src/server: src/CMakeFiles/server.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/user/Desktop/Documents/technical-test/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable server"
	cd /home/user/Desktop/Documents/technical-test/build/src && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/server.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/CMakeFiles/server.dir/build: src/server

.PHONY : src/CMakeFiles/server.dir/build

src/CMakeFiles/server.dir/clean:
	cd /home/user/Desktop/Documents/technical-test/build/src && $(CMAKE_COMMAND) -P CMakeFiles/server.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/server.dir/clean

src/CMakeFiles/server.dir/depend:
	cd /home/user/Desktop/Documents/technical-test/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/user/Desktop/Documents/technical-test /home/user/Desktop/Documents/technical-test/src /home/user/Desktop/Documents/technical-test/build /home/user/Desktop/Documents/technical-test/build/src /home/user/Desktop/Documents/technical-test/build/src/CMakeFiles/server.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/server.dir/depend
