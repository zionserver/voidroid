#!/bin/bash
trizen -Q jre || xterm -e "sudo pacman -U --noconfirm /home/android/.fwul/jre-8u131-1-x86_64.pkg.tar.xz"
java -jar /home/android/programs/sadb/S-ADB.jar
