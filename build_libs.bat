mkdir libs
mkdir libs\debug
mkdir libs\release

mkdir xxHash\build
cd xxHash\build

cmake ..\cmake_unofficial -DBUILD_SHARED_LIBS=OFF

cmake --build .
copy Debug\xxhash.lib ..\..\libs\debug
copy Debug\xxhash.pdb ..\..\libs\debug

cmake --build . --config Release
copy Release\xxhash.lib ..\..\libs\release