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

# Utility rule file for ContinuousSubmit.

# Include the progress variables for this target.
include src/CMakeFiles/ContinuousSubmit.dir/progress.make

src/CMakeFiles/ContinuousSubmit:
	cd /home/user/Desktop/Documents/technical-test/build/src && /usr/bin/ctest -D ContinuousSubmit

ContinuousSubmit: src/CMakeFiles/ContinuousSubmit
ContinuousSubmit: src/CMakeFiles/ContinuousSubmit.dir/build.make

.PHONY : ContinuousSubmit

# Rule to build all files generated by this target.
src/CMakeFiles/ContinuousSubmit.dir/build: ContinuousSubmit

.PHONY : src/CMakeFiles/ContinuousSubmit.dir/build

src/CMakeFiles/ContinuousSubmit.dir/clean:
	cd /home/user/Desktop/Documents/technical-test/build/src && $(CMAKE_COMMAND) -P CMakeFiles/ContinuousSubmit.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/ContinuousSubmit.dir/clean

src/CMakeFiles/ContinuousSubmit.dir/depend:
	cd /home/user/Desktop/Documents/technical-test/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/user/Desktop/Documents/technical-test /home/user/Desktop/Documents/technical-test/src /home/user/Desktop/Documents/technical-test/build /home/user/Desktop/Documents/technical-test/build/src /home/user/Desktop/Documents/technical-test/build/src/CMakeFiles/ContinuousSubmit.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/ContinuousSubmit.dir/depend

