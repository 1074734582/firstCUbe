#!/bin/bash

#: << COMMENTBLOCK
#COMMENTBLOCK

echo "build GMP"
tar jxvf gmp-6.2.1.tar.bz2
cd gmp-6.2.1
./configure
make
#make check
sudo make install
cd ..
rm -r gmp-6.2.1

echo "build GF2X"
tar jxvf gf2x-gf2x-1.2.tar.bz2
cd gf2x-gf2x-1.2
aclocal
libtoolize --force
automake --add-missing
autoconf
autoreconf --install
./configure
make
#make check
sudo make install
cd ..
rm -r gf2x-gf2x-1.2

echo "build NTL"
tar zxvf ntl-11.5.1.tar.gz
cd ntl-11.5.1/src
./configure CXXFLAGS="-fPIC" NTL_GF2X_LIB=on
sudo ldconfig
make
#make check
sudo make install
cd ../..
rm -r ntl-11.5.1
