import sqlite3

#connecting to the SQLite database (or creating it if it doesn't exist)
conn = sqlite3.connect('security_dashboard.db')

#creating a cursor object using the cursor() method
c = conn.cursor()

# ساخت جدول برای ذخیره آی‌پی‌های بلاک‌شده
c.execute('''
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL,
        reason TEXT,
        datetime TEXT,
        duration INTEGER,
        notes TEXT
    )
''')

# ذخیره تغییرات و بستن اتصال
conn.commit()
conn.close()

print("Database and table created successfully.")
