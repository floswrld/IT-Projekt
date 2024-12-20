# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "/Users/flrnvsc/CLionProjects/IT-Projekt/cmake-build-debug/_deps/pqclean-src")
  file(MAKE_DIRECTORY "/Users/flrnvsc/CLionProjects/IT-Projekt/cmake-build-debug/_deps/pqclean-src")
endif()
file(MAKE_DIRECTORY
  "/Users/flrnvsc/CLionProjects/IT-Projekt/cmake-build-debug/_deps/pqclean-build"
  "/Users/flrnvsc/CLionProjects/IT-Projekt/cmake-build-debug/_deps/pqclean-subbuild/pqclean-populate-prefix"
  "/Users/flrnvsc/CLionProjects/IT-Projekt/cmake-build-debug/_deps/pqclean-subbuild/pqclean-populate-prefix/tmp"
  "/Users/flrnvsc/CLionProjects/IT-Projekt/cmake-build-debug/_deps/pqclean-subbuild/pqclean-populate-prefix/src/pqclean-populate-stamp"
  "/Users/flrnvsc/CLionProjects/IT-Projekt/cmake-build-debug/_deps/pqclean-subbuild/pqclean-populate-prefix/src"
  "/Users/flrnvsc/CLionProjects/IT-Projekt/cmake-build-debug/_deps/pqclean-subbuild/pqclean-populate-prefix/src/pqclean-populate-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/Users/flrnvsc/CLionProjects/IT-Projekt/cmake-build-debug/_deps/pqclean-subbuild/pqclean-populate-prefix/src/pqclean-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/Users/flrnvsc/CLionProjects/IT-Projekt/cmake-build-debug/_deps/pqclean-subbuild/pqclean-populate-prefix/src/pqclean-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()
