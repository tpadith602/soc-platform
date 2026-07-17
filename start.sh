#!/bin/bash
sudo systemctl start soc-platform.service
sleep 3
sudo systemctl status soc-platform.service --no-pager
echo "🌐 Dashboard started — see journal for host:port and API key:"
echo "   sudo journalctl -u soc-platform.service -n 30 | grep 'Dashboard\|API key'"
