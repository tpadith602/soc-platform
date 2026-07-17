#!/usr/bin/env python3
"""
Clear All Alerts from SOC Database
"""

import sqlite3
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.settings import DB_PATH

def clear_alerts():
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM alerts")
        count = cursor.fetchone()[0]
        print(f"📊 Found {count} alerts")

        if count > 0:
            confirm = input(f"⚠️ Delete all {count} alerts? (yes/no): ")
            if confirm.lower() != 'yes':
                print("❌ Cancelled")
                conn.close()
                return

        cursor.execute("DELETE FROM alerts")
        cursor.execute("VACUUM")
        conn.commit()

        cursor.execute("SELECT COUNT(*) FROM alerts")
        new_count = cursor.fetchone()[0]
        conn.close()

        print(f"✅ Deleted {count} alerts")
        print(f"📊 Remaining: {new_count}")

    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == '__main__':
    clear_alerts()
