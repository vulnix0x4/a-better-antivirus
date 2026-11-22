#!/bin/sh
# Before the package goes: when it's being removed (not upgraded), take ABA
# off this machine too, the way `sudo aba uninstall` does (the service, every
# bait, the firewall rules, the frozen and cut-off groups). Alert history is
# kept in /var/lib/file-access-monitor; `aba uninstall --purge` before
# removing the package deletes that too.
#   deb: $1 is "remove" or "upgrade"; rpm: $1 is 0 when the last copy goes.
case "${1:-}" in
  remove|0)
    if [ -e /etc/systemd/system/file-access-monitor.service ]; then
      for aba in /usr/local/lib/file-access-monitor/aba /usr/bin/aba; do
        if [ -x "$aba" ]; then
          "$aba" uninstall --yes </dev/null || echo "A Better Antivirus couldn't remove itself completely: run 'sudo $aba uninstall' to retry." >&2
          break
        fi
      done
    fi
    ;;
esac
exit 0
