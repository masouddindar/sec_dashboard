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



# اتصال به دیتابیس
conn = sqlite3.connect('security_dashboard.db')
cursor = conn.cursor()

# ساخت جدول users
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fullname TEXT NOT NULL,
    personnel_number TEXT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    extension TEXT,
    unit TEXT,
    created_at TEXT NOT NULL
)
''')

# ذخیره تغییرات و بستن اتصال
conn.commit()
conn.close()
