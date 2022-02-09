#!/bin/bash
trizen -Q jre || xterm -e "sudo pacman -U --noconfirm /home/android/.fwul/jre-8u131-1-x86_64.pkg.tar.xz"
JAVA_HOME=/usr/lib/jvm/java-8-jre /home/android/programs/JOdin/JOdin3CASUAL
