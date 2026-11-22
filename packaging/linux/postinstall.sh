#!/bin/sh
# After the package put /usr/bin/aba in place. Setting ABA up is a step of
# its own (it plants baits in the home folder of the person who runs it), so
# this only says how. An install that is already set up keeps its own copy
# of the program and updates it itself (signed releases only).
if [ -e /etc/systemd/system/file-access-monitor.service ]; then
  echo "A Better Antivirus is set up already. It keeps its own copy up to date: sudo aba update"
else
  echo "A Better Antivirus is installed. Set it up with:  sudo aba install"
fi
exit 0
