# MITM-attack

Performed a MITM-attack in the virtual environment.

## Compile correction

    make

## Insert modules into kernel

    insmod correction.ko

## Remove modules from kernel

    rmmod correction


* correction.c for IP & checksum correction
* hack.py conducts ARP Poison
* Makefile compiles the correction.c
* nodeWebsocket.js receives the victim information

<img src="Animation.gif" width="300" height="200" />