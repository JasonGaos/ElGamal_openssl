# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/jgao76/ecc-openssl

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/jgao76/ecc-openssl/build

# Include any dependencies generated for this target.
include CMakeFiles/test_elgamal.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/test_elgamal.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/test_elgamal.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/test_elgamal.dir/flags.make

CMakeFiles/test_elgamal.dir/test/test_elgamal.cpp.o: CMakeFiles/test_elgamal.dir/flags.make
CMakeFiles/test_elgamal.dir/test/test_elgamal.cpp.o: ../test/test_elgamal.cpp
CMakeFiles/test_elgamal.dir/test/test_elgamal.cpp.o: CMakeFiles/test_elgamal.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/jgao76/ecc-openssl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/test_elgamal.dir/test/test_elgamal.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/test_elgamal.dir/test/test_elgamal.cpp.o -MF CMakeFiles/test_elgamal.dir/test/test_elgamal.cpp.o.d -o CMakeFiles/test_elgamal.dir/test/test_elgamal.cpp.o -c /home/jgao76/ecc-openssl/test/test_elgamal.cpp

CMakeFiles/test_elgamal.dir/test/test_elgamal.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_elgamal.dir/test/test_elgamal.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/jgao76/ecc-openssl/test/test_elgamal.cpp > CMakeFiles/test_elgamal.dir/test/test_elgamal.cpp.i

CMakeFiles/test_elgamal.dir/test/test_elgamal.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_elgamal.dir/test/test_elgamal.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/jgao76/ecc-openssl/test/test_elgamal.cpp -o CMakeFiles/test_elgamal.dir/test/test_elgamal.cpp.s

CMakeFiles/test_elgamal.dir/src/ec_curve.cpp.o: CMakeFiles/test_elgamal.dir/flags.make
CMakeFiles/test_elgamal.dir/src/ec_curve.cpp.o: ../src/ec_curve.cpp
CMakeFiles/test_elgamal.dir/src/ec_curve.cpp.o: CMakeFiles/test_elgamal.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/jgao76/ecc-openssl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/test_elgamal.dir/src/ec_curve.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/test_elgamal.dir/src/ec_curve.cpp.o -MF CMakeFiles/test_elgamal.dir/src/ec_curve.cpp.o.d -o CMakeFiles/test_elgamal.dir/src/ec_curve.cpp.o -c /home/jgao76/ecc-openssl/src/ec_curve.cpp

CMakeFiles/test_elgamal.dir/src/ec_curve.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_elgamal.dir/src/ec_curve.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/jgao76/ecc-openssl/src/ec_curve.cpp > CMakeFiles/test_elgamal.dir/src/ec_curve.cpp.i

CMakeFiles/test_elgamal.dir/src/ec_curve.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_elgamal.dir/src/ec_curve.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/jgao76/ecc-openssl/src/ec_curve.cpp -o CMakeFiles/test_elgamal.dir/src/ec_curve.cpp.s

CMakeFiles/test_elgamal.dir/src/ec_elgamal.cpp.o: CMakeFiles/test_elgamal.dir/flags.make
CMakeFiles/test_elgamal.dir/src/ec_elgamal.cpp.o: ../src/ec_elgamal.cpp
CMakeFiles/test_elgamal.dir/src/ec_elgamal.cpp.o: CMakeFiles/test_elgamal.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/jgao76/ecc-openssl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/test_elgamal.dir/src/ec_elgamal.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/test_elgamal.dir/src/ec_elgamal.cpp.o -MF CMakeFiles/test_elgamal.dir/src/ec_elgamal.cpp.o.d -o CMakeFiles/test_elgamal.dir/src/ec_elgamal.cpp.o -c /home/jgao76/ecc-openssl/src/ec_elgamal.cpp

CMakeFiles/test_elgamal.dir/src/ec_elgamal.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_elgamal.dir/src/ec_elgamal.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/jgao76/ecc-openssl/src/ec_elgamal.cpp > CMakeFiles/test_elgamal.dir/src/ec_elgamal.cpp.i

CMakeFiles/test_elgamal.dir/src/ec_elgamal.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_elgamal.dir/src/ec_elgamal.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/jgao76/ecc-openssl/src/ec_elgamal.cpp -o CMakeFiles/test_elgamal.dir/src/ec_elgamal.cpp.s

# Object files for target test_elgamal
test_elgamal_OBJECTS = \
"CMakeFiles/test_elgamal.dir/test/test_elgamal.cpp.o" \
"CMakeFiles/test_elgamal.dir/src/ec_curve.cpp.o" \
"CMakeFiles/test_elgamal.dir/src/ec_elgamal.cpp.o"

# External object files for target test_elgamal
test_elgamal_EXTERNAL_OBJECTS =

test_elgamal: CMakeFiles/test_elgamal.dir/test/test_elgamal.cpp.o
test_elgamal: CMakeFiles/test_elgamal.dir/src/ec_curve.cpp.o
test_elgamal: CMakeFiles/test_elgamal.dir/src/ec_elgamal.cpp.o
test_elgamal: CMakeFiles/test_elgamal.dir/build.make
test_elgamal: /usr/lib/x86_64-linux-gnu/libcrypto.so
test_elgamal: CMakeFiles/test_elgamal.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/jgao76/ecc-openssl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking CXX executable test_elgamal"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_elgamal.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/test_elgamal.dir/build: test_elgamal
.PHONY : CMakeFiles/test_elgamal.dir/build

CMakeFiles/test_elgamal.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/test_elgamal.dir/cmake_clean.cmake
.PHONY : CMakeFiles/test_elgamal.dir/clean

CMakeFiles/test_elgamal.dir/depend:
	cd /home/jgao76/ecc-openssl/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/jgao76/ecc-openssl /home/jgao76/ecc-openssl /home/jgao76/ecc-openssl/build /home/jgao76/ecc-openssl/build /home/jgao76/ecc-openssl/build/CMakeFiles/test_elgamal.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/test_elgamal.dir/depend

