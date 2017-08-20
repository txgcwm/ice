#!/bin/bash

source param.mk

CURDIR=`pwd`


if [ ! -f ${FILENAME} ]; then
	wget ${DOWNLOADURL}
fi

if [ -d ${DIRNAME} ]; then
    rm -rf ${DIRNAME}
fi

if [ -d ${INSTALLDIR} ]; then
    rm -rf ${INSTALLDIR}
fi

mkdir ${INSTALLDIR}

tar -jxvf ${FILENAME}

# build lib
cd ${DIRNAME}
./configure --prefix=${CURDIR}/${INSTALLDIR} --build=i686-linux --disable-sound --disable-oss --disable-video \
--disable-small-filter --disable-large-filter --disable-speex-aec --disable-g711-codec \
--disable-l16-codec --disable-gsm-codec --disable-g722-codec --disable-g7221-codec \
--disable-speex-codec --disable-ilbc-codec --disable-sdl --disable-ffmpeg --disable-v4l2 \
--disable-openh264 --disable-libwebrtc --disable-libyuv --disable-shared
make dep
make
make install
cd ..

function rename_libs()
{
    cd ${INSTALLDIR}/lib/

    comflag=-i686-pc-linux-gnu

    for file in `ls *.a`; do
        file_new=`echo "$file" | sed 's/'$comflag'//g'`
        mv ${file} ${file_new}
    done

    cd -
}

rename_libs

# copy libs and include
cp -rf ${INSTALLDIR}/lib/ ${CURDIR}/../../prebuild/pjsip
cp -rf ${INSTALLDIR}/include/ ${CURDIR}/../../prebuild/pjsip