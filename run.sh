#!/bin/sh

currdir="$(cd "$(dirname "$0")" && pwd -P)"
cd ${currdir}


if [ "$1" == "tcpdump" ]; then

  echo "starting tcpdump on device"
  adb shell "su -c '/data/local/tmp/tcpdump -n -s 0 -w - | busybox nc -l -p 12345'"

elif [ "$1" == "forward" ]; then

  echo "forwording traffic from device to localhost"
  adb forward tcp:54321 tcp:12345

elif [ "$1" == "android" ]; then

  nc 127.0.0.1 54321 | wireshark -X lua_script:sfs.lua -k -S -i -

else

  Wireshark -X lua_script:sfs.lua

fi
