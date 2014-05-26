#!/bin/sh
echo Detecting...
which sudo && which apt-get && apt-get install build-essential git cmake libjson-c-dev

gitdir="./tmp"
distdir="$(pwd)/dist"
[ -z "$distdir" ] && distdir=./dist

mkdir -p $gitdir $distdir/usr

git clone http://git.openwrt.org/project/libubox.git $gitdir/libubox
git clone git://nbd.name/uci.git $gitdir/uci
git clone https://github.com/sbyx/odhcp6c.git $gitdir/odhcp6c
git clone https://github.com/sbyx/odhcpd.git $gitdir/odhcpd
git clone https://github.com/sbyx/hnetd.git $gitdir/hnetd

(
	cd $gitdir/libubox
	cmake -DCMAKE_INSTALL_PREFIX=$distdir/usr -DBUILD_LUA=off .
	make install
)

(
	cd $gitdir/uci
	mv CMakeLists.txt CMakeLists.txt.in
	echo "include_directories($distdir/usr/include)" > CMakeLists.txt
	echo "link_directories($distdir/usr/lib)" >> CMakeLists.txt
	cat CMakeLists.txt.in >> CMakeLists.txt
	cmake -DCMAKE_INSTALL_PREFIX=$distdir/usr -DBUILD_LUA=off .
	make install VERBOSE=1
)

(
	cd $gitdir/odhcp6c
	cmake -DCMAKE_INSTALL_PREFIX=$distdir/usr .
	make install
)

(
	cd $gitdir/odhcpd
	mv CMakeLists.txt CMakeLists.txt.in
	echo "include_directories($distdir/usr/include)" > CMakeLists.txt
	echo "link_directories($distdir/usr/lib)" >> CMakeLists.txt
	cat CMakeLists.txt.in >> CMakeLists.txt
	cmake -DCMAKE_INSTALL_PREFIX=$distdir/usr .
	make install
)

(
	cd $gitdir/hnetd
	mv CMakeLists.txt CMakeLists.txt.in
	echo "include_directories($distdir/usr/include)" > CMakeLists.txt
	echo "link_directories($distdir/usr/lib)" >> CMakeLists.txt
	cat CMakeLists.txt.in >> CMakeLists.txt
	cmake -DCMAKE_INSTALL_PREFIX=$distdir/usr .
	make install
)
