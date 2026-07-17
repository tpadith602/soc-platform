#!/bin/bash
echo "========================================="
echo "  SOC PLATFORM STATUS"
echo "========================================="
sudo systemctl status soc-platform.service --no-pager
echo ""
echo "💾 Database:"
sqlite3 ~/soc-platform/storage/soc_enriched_matrix.db "SELECT COUNT(*) as total FROM alerts;"
echo ""
echo "📋 Recent Alerts:"
sqlite3 ~/soc-platform/storage/soc_enriched_matrix.db "SELECT datetime(timestamp) as time, source_ip, attack_type, severity, status FROM alerts ORDER BY timestamp DESC LIMIT 5;"
