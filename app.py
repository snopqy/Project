"""
How to run:
1) python app.py
2) First run auto-creates fitness.sqlite with sample data.
   Login with: username `admin`, password `admin123`
"""

import os
import shutil
import sqlite3
import hashlib
import secrets
import csv
import random
import calendar as pycal
from datetime import datetime, timedelta, date
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from contextlib import contextmanager
from PIL import Image, ImageTk  # Required for reliable image loading

import sys # Added sys for PyInstaller support (ใช้สำหรับจัดการ System Path)

# ==========================================
# 1. การตั้งค่าและฟังก์ชันช่วย (Configuration & Utilities)
# ส่วนนี้สำหรับจัดการ Path ของไฟล์และ Database เพื่อให้รองรับการรันแบบ .exe
# ==========================================
def get_resource_path(relative_path):
    """ 
    ฟังก์ชันช่วยหาที่อยู่ไฟล์ (Resource Path) 
    - ถ้ารันแบบปกติ จะหาจากโฟลเดอร์ปัจจุบัน
    - ถ้ารันแบบ .exe (PyInstaller) จะหาจากโฟลเดอร์ชั่วคราว (_MEIPASS)
    """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def get_db_path():
    """ Get database path. In exe, store next to executable. """
    if getattr(sys, 'frozen', False):
        # Running as compiled exe
        base_path = os.path.dirname(sys.executable)
    else:
        # Running as script
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, "fitness.sqlite")

DB_PATH = get_db_path()
PAGE_SIZE_DEFAULT = 20

# ==========================================
# เครื่องมือช่วย (Utilities)
# ==========================================
class Debouncer:
    """
    คลาสสำหรับหน่วงเวลาการทำงาน (Debounce)
    - ใช้สำหรับช่องค้นหา (Search Box)
    - เพื่อป้องกันไม่ให้โปรแกรมค้นหาทันทีที่พิมพ์ทุกตัวอักษร (ซึ่งจะทำให้โปรแกรมค้าง)
    - หลักการคือ: รอให้หยุดพิมพ์สักพัก (delay_ms) แล้วค่อยทำงาน
    """
    def __init__(self, widget, delay_ms=400):
        self.widget = widget
        self.delay = delay_ms
        self._after_id = None
    def call(self, func):
        if self._after_id:
            self.widget.after_cancel(self._after_id)
        self._after_id = self.widget.after(self.delay, func)

def copy_selected_tree_rows_to_clipboard(tree: ttk.Treeview):
    """
    ฟังก์ชันสำหรับคัดลอกข้อมูลจากตาราง (Treeview) ไปยัง Clipboard
    """
    sels = tree.selection()
    if not sels:
        return
    rows = []
    for s in sels:
        rows.append("\t".join(map(str, tree.item(s, "values"))))
    text = "\n".join(rows)
    tree.clipboard_clear()
    tree.clipboard_append(text)

# ==========================================
# ธีมและการตกแต่ง (Styles)
# ==========================================
PALETTE = dict(
    ACCENT="#3B82F6",    # สีหลัก (น้ำเงิน)
    BG="#F7F8FA",        # สีพื้นหลัง (ขาวเทา)
    INK="#111827",       # สีตัวอักษร (ดำเกือบสนิท)
    MUTED="#6B7280",     # สีตัวอักษรจาง (เทา)
    BORDER="#E5E7EB",    # สีเส้นขอบ
    ROW_A="#FFFFFF",     # สีพื้นหลังแถว A
    ROW_B="#F9FAFB",     # สีพื้นหลังแถว B
    EXPIRED_BG="#FFF1F2",# สีพื้นหลังสำหรับรายการที่หมดอายุ (แดงอ่อน)
    TODAY_BG="#FEFCE8",  # สีพื้นหลังสำหรับรายการวันนี้ (เหลืองอ่อน)
)

def setup_styles(root: tk.Tk):
    """
    ตั้งค่าธีมและสไตล์ของ Widget ต่างๆ
    """
    P = PALETTE
    style = ttk.Style(root)
    # พยายามใช้ธีมที่ดูดีที่สุดที่มีในระบบ
    for th in ("vista", "clam", "xpnative"):
        if th in style.theme_names():
            style.theme_use(th)
            break
    try:
        root.configure(bg=P["BG"])
    except:
        pass
    
    # กำหนดค่าเริ่มต้นให้กับ Widget ต่างๆ
    style.configure(".", font=("Segoe UI", 10), foreground=P["INK"], background=P["BG"])
    style.configure("TFrame", background=P["BG"])
    style.configure("TLabel", background=P["BG"], foreground=P["INK"])
    style.configure("Muted.TLabel", background=P["BG"], foreground=P["MUTED"])
    style.configure("TEntry", padding=6)
    style.configure("TCombobox", padding=4)
    
    # Card Style (White background, for Login Card)
    style.configure("Card.TFrame", background="#FFFFFF", relief="solid", borderwidth=1)
    style.configure("Card.TLabel", background="#FFFFFF", foreground=P["INK"])
    
    # ปุ่มหลัก (Primary Button)
    style.configure("Primary.TButton", padding=(12,8),  background=P["ACCENT"])
    style.map("Primary.TButton", background=[("active", "#2563EB")])
    
    # ปุ่มรอง (Secondary Button)
    style.configure("Secondary.TButton", padding=(10,6))
    style.map("Secondary.TButton", background=[("active", "#F3F4F6")])
    
    # ปุ่มเครื่องมือ (Tool Button)
    style.configure("Tool.TButton", padding=(8, 4), font=("Segoe UI", 9))
    style.map("Tool.TButton", background=[("active", "#EFF6FF")])
    
    # ปุ่มปฏิทิน (Modern Style)
    style.configure("Calendar.TButton", padding=5, width=4, relief="flat", font=("Segoe UI", 9), background="#FFFFFF")
    style.map("Calendar.TButton", background=[("active", "#F3F4F6")]) # Hover effect
    
    style.configure("CalendarSelected.TButton", padding=5, width=4, relief="flat", font=("Segoe UI", 9, "bold"), background=P["ACCENT"], foreground="#FFFFFF")
    style.map("CalendarSelected.TButton", background=[("active", "#2563EB")], foreground=[("active", "#FFFFFF")])
    
    style.configure("CalendarToday.TButton", padding=5, width=4, relief="flat", font=("Segoe UI", 9, "bold"), foreground=P["ACCENT"], background="#FFFFFF")
    style.map("CalendarToday.TButton", background=[("active", "#EFF6FF")])

    # Navigation Buttons (Minimal)
    style.configure("CalNav.TButton", padding=2, relief="flat", font=("Segoe UI", 10), background="#FFFFFF", width=3)
    style.map("CalNav.TButton", background=[("active", "#F3F4F6")])
    
    # ตาราง (Treeview)
    style.configure("Treeview",
        rowheight=28, bordercolor=P["BORDER"], lightcolor=P["BORDER"], darkcolor=P["BORDER"],
        background=P["ROW_A"], fieldbackground=P["ROW_A"], foreground=P["INK"])
    style.configure("Treeview.Heading", font=("Segoe UI Semibold", 10), padding=6, background=P["ROW_B"])
    return P

# ==========================================
# ฐานข้อมูล (Database)
# ==========================================
@contextmanager
def get_db_connection():
    """
    Context Manager สำหรับเชื่อมต่อฐานข้อมูล SQLite
    - ทำหน้าที่เปิดการเชื่อมต่อ (connect)
    - และปิดการเชื่อมต่อ (close) ให้อัตโนมัติเมื่อทำงานเสร็จ
    - ช่วยป้องกันปัญหา Database Locked หรือลืมปิด Connection
    """
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON") # เปิดใช้งาน Foreign Key Constraint
    try:
        yield conn
    finally:
        conn.close()

def _ensure_column(conn, table, col_name, col_def):
    """ตรวจสอบและเพิ่มคอลัมน์ในตารางถ้ายังไม่มี"""
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    cols = [r[1] for r in cur.fetchall()]
    if col_name not in cols:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def}")
    conn.commit()

def ensure_sequence(cur: sqlite3.Cursor, name: str):
    """ตรวจสอบว่ามีลำดับเลข (Sequence) ชื่อนี้อยู่หรือไม่ ถ้าไม่มีให้สร้างใหม่"""
    cur.execute("INSERT OR IGNORE INTO sequences(name, last_value) VALUES (?, 0)", (name,))

def next_sequence(cur: sqlite3.Cursor, name: str) -> int:
    """ดึงเลขลำดับถัดไป"""
    ensure_sequence(cur, name)
    cur.execute("UPDATE sequences SET last_value = last_value + 1 WHERE name = ?", (name,))
    cur.execute("SELECT last_value FROM sequences WHERE name = ?", (name,))
    return cur.fetchone()[0]

def hash_password(password: str, salt: str) -> str:
    """เข้ารหัสรหัสผ่านด้วย SHA256"""
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()

def create_user(cur: sqlite3.Cursor, username: str, password: str):
    """สร้างผู้ใช้งานใหม่"""
    salt = secrets.token_hex(16)
    cur.execute("INSERT INTO users(username, password_hash, salt) VALUES (?, ?, ?)",
                (username, hash_password(password, salt), salt))

def verify_user(username: str, password: str) -> bool:
    """ตรวจสอบชื่อผู้ใช้และรหัสผ่าน"""
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
    if not row: return False
    ph, salt = row
    return ph == hash_password(password, salt)



def init_db():
    """
    ฟังก์ชันเริ่มต้นฐานข้อมูล (Initialize Database)
    - ทำงานเมื่อเปิดโปรแกรมครั้งแรก
    - สร้างตาราง (Tables) ที่จำเป็นทั้งหมดถ้ายังไม่มี
    - สร้างข้อมูลตัวอย่าง (Dummy Data) เช่น Admin User, Trainers, Residents
    """
    with get_db_connection() as conn:
        cur = conn.cursor()
        # สร้างตารางต่างๆ
        cur.execute("""CREATE TABLE IF NOT EXISTS sequences (name TEXT PRIMARY KEY, last_value INTEGER NOT NULL)""")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )""")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS trainers (
                id INTEGER PRIMARY KEY AUTOINCREMENT, 
                name TEXT NOT NULL, 
                phone TEXT,
                specialty TEXT,
                level TEXT
            )""")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS rooms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_number TEXT UNIQUE NOT NULL,
                building TEXT,
                floor INTEGER,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )""")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS residents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                resident_no INTEGER UNIQUE NOT NULL,
                name TEXT NOT NULL,
                room TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                trainer_id INTEGER,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                deleted_at TEXT,
                contract_start TEXT,
                contract_days INTEGER,
                membership_type_id INTEGER,
                FOREIGN KEY (trainer_id) REFERENCES trainers(id)
            )""")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS checkins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                resident_id INTEGER NOT NULL,
                checkin_time TEXT NOT NULL,
                FOREIGN KEY (resident_id) REFERENCES residents(id)
            )""")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS membership_types (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                duration_days INTEGER NOT NULL,
                price REAL
            )""")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS contract_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                resident_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                old_days INTEGER,
                new_days INTEGER,
                old_start TEXT,
                new_start TEXT,
                logged_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (resident_id) REFERENCES residents(id)
            )""")

        # สร้าง Indexes เพื่อความรวดเร็วในการค้นหา
        cur.execute("CREATE INDEX IF NOT EXISTS idx_residents_name ON residents(name)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_residents_room ON residents(room)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_residents_trainer ON residents(trainer_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_residents_resno ON residents(resident_no)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_residents_deleted ON residents(deleted_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_checkins_resident ON checkins(resident_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_checkins_time ON checkins(checkin_time)")

        # Ensure Columns Exist (Migration)
        _ensure_column(conn, "residents", "contract_start", "TEXT")
        _ensure_column(conn, "residents", "contract_days", "INTEGER")
        _ensure_column(conn, "residents", "membership_type_id", "INTEGER")
        _ensure_column(conn, "trainers", "specialty", "TEXT")
        _ensure_column(conn, "trainers", "level", "TEXT")

        # สร้าง admin user ถ้ายังไม่มี
        cur.execute("SELECT COUNT(1) FROM users")
        if cur.fetchone()[0] == 0:
            create_user(cur, "admin", "admin123")

        # UAT Data Seeding (if empty)
        cur.execute("SELECT COUNT(*) FROM residents")
        if cur.fetchone()[0] == 0:
            print("Seeding UAT Data...")
            
            # Seed Membership Types
            cur.execute("INSERT OR IGNORE INTO membership_types (name, price, duration_days) VALUES ('Monthly', 1500, 30)")
            cur.execute("INSERT OR IGNORE INTO membership_types (name, price, duration_days) VALUES ('Yearly', 15000, 365)")
            cur.execute("SELECT id FROM membership_types")
            mem_type_ids = [row[0] for row in cur.fetchall()]

            # Seed Trainers
            trainers = [
                ("Coach Bank", "081-111-1111", "Bodybuilding", "Senior"),
                ("Coach May", "081-222-2222", "Yoga", "Master"),
                ("Coach John", "081-333-3333", "Crossfit", "Junior"),
                ("Coach Sarah", "081-444-4444", "Pilates", "Senior"),
                ("Coach Mike", "081-555-5555", "Boxing", "Master"),
                ("Coach Alice", "081-666-6666", "Zumba", "Junior"),
                ("Coach Tom", "081-777-7777", "Weight Loss", "Senior"),
                ("Coach Jane", "081-888-8888", "Rehab", "Master")
            ]
            for t in trainers:
                cur.execute("INSERT INTO trainers (name, phone, specialty, level) VALUES (?, ?, ?, ?)", t)
            cur.execute("SELECT id FROM trainers"); trainer_ids = [row[0] for row in cur.fetchall()]

            # Seed Rooms (A-H, Floors 1-8)
            buildings = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H']
            room_ids = []
            for b in buildings:
                for f in range(1, 9):
                    for r in range(1, 11): # 10 rooms per floor
                        room_num = f"{b}{f}{r:02d}"
                        cur.execute("INSERT OR IGNORE INTO rooms (room_number, building, floor) VALUES (?, ?, ?)", (room_num, b, f))
                        room_ids.append(room_num)
            
            # Seed Residents
            first_names = ["James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda", "William", "Elizabeth", "David", "Barbara", "Richard", "Susan", "Joseph", "Jessica", "Thomas", "Sarah", "Charles", "Karen"]
            last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin"]
            
            resident_ids = []
            for i in range(200): # 200 Residents
                fname = random.choice(first_names); lname = random.choice(last_names)
                name = f"{fname} {lname}"
                room = random.choice(room_ids)
                start_date = datetime.now() - timedelta(days=random.randint(0, 365))
                mem_id = random.choice(mem_type_ids) if mem_type_ids else None
                tid = random.choice(trainer_ids) if random.random() < 0.3 and trainer_ids else None
                resident_no = 1000 + i
                
                cur.execute("""
                    INSERT INTO residents (resident_no, name, room, contract_start, contract_days, active, membership_type_id, trainer_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (resident_no, name, room, start_date.strftime("%Y-%m-%d"), 365, 1, mem_id, tid))
                resident_ids.append(cur.lastrowid)
                
            # Seed Check-ins
            for _ in range(3000):
                rid = random.choice(resident_ids)
                ci_date = datetime.now() - timedelta(days=random.randint(0, 60), hours=random.randint(0, 23), minutes=random.randint(0, 59))
                cur.execute("INSERT INTO checkins (resident_id, checkin_time) VALUES (?, ?)", (rid, ci_date.strftime("%Y-%m-%d %H:%M:%S")))
            
            # Seed Contract Logs (Simulate history)
            for rid in resident_ids:
                # Initial contract log
                cur.execute("SELECT contract_start, contract_days FROM residents WHERE id=?", (rid,))
                row = cur.fetchone()
                if row:
                    start, days = row
                    cur.execute("""
                        INSERT INTO contract_logs (resident_id, action, old_days, new_days, old_start, new_start, logged_at)
                        VALUES (?, 'NEW', 0, ?, NULL, ?, ?)
                    """, (rid, days, start, start))

            print("UAT Data Seeding Complete!")




        
        conn.commit()

# ==========================================
# ส่วนแสดงผลหลัก (Main Application)
# ==========================================
class App(tk.Tk):
    """
    คลาสหลักของโปรแกรม (Main Application Window)
    - สืบทอดมาจาก tk.Tk (หน้าต่างหลัก)
    - ทำหน้าที่จัดการหน้าจอต่างๆ (Frames) และสลับหน้าจอไปมา
    """
    def __init__(self):
        super().__init__()
        self.title("Fitness Check-ins | Condo Admin")
        self.geometry("1300x800")
        self.minsize(1100, 650)
        
        # Set App Icon
        try:
            icon_path = get_resource_path("assets/icon.png")
            icon_img = ImageTk.PhotoImage(file=icon_path)
            self.iconphoto(False, icon_img)
        except Exception as e:
            print(f"Error loading icon: {e}")

        self.palette = setup_styles(self)  
        self.center_on_screen()

        self._frames = {}
        container = ttk.Frame(self)
        container.pack(fill=tk.BOTH, expand=True)

        # สร้าง Menu Bar
        self._build_menubar()

        # สร้างหน้าจอต่างๆ (Login, Landing)
        for F in (LoginFrame, LandingFrame):
            frame = F(parent=container, controller=self)
            self._frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)
        self.show_frame("LoginFrame")

    def _build_menubar(self):
        """สร้างเมนูด้านบน"""
        self.menubar = tk.Menu(self)
        
        # เมนู File
        filem = tk.Menu(self.menubar, tearoff=0)
        filem.add_command(label="Dashboard", command=self.open_dashboard)
        filem.add_separator()
        filem.add_command(label="Exit", command=self.destroy)
        self.menubar.add_cascade(label="File", menu=filem)
        
        # เมนู Manage (จัดการข้อมูล)
        managem = tk.Menu(self.menubar, tearoff=0)
        managem.add_command(label="Residents (ลูกบ้าน)", command=self.open_residents)
        managem.add_command(label="Trainers (เทรนเนอร์)", command=self.open_trainers)
        managem.add_command(label="Rooms (ห้อง)", command=self.open_rooms)
        self.menubar.add_cascade(label="Manage", menu=managem)

        # เมนู Reports
        self.menubar.add_command(label="Reports", command=self.open_reports)

        # เริ่มต้นยังไม่แสดงเมนู (จะแสดงเมื่อ Login ผ่าน)
        self.config(menu=tk.Menu(self))
        
    def open_dashboard(self):
        Dashboard(self)
        
    def open_residents(self):
        ResidentsDialog(self)

    def open_trainers(self):
        TrainersDialog(self)

    def open_rooms(self):
        RoomsDialog(self)

    def open_reports(self):
        ReportsDialog(self)

    # Backup/Restore/Settings methods removed as requested

    def center_on_screen(self):
        """จัดหน้าต่างให้อยู่กึ่งกลางหน้าจอ"""
        self.update_idletasks()
        w = self.winfo_width() or 1300
        h = self.winfo_height() or 800
        sw = self.winfo_screenwidth(); sh = self.winfo_screenheight()
        x = max((sw - w) // 2, 0); y = max((sh - h) // 2, 0)
        self.geometry(f"{w}x{h}+{x}+{y}")

    def show_frame(self, name: str):
        """สลับหน้าจอ"""
        frame = self._frames[name]
        frame.tkraise()
        
        # จัดการการแสดงผลเมนู
        if name == "LoginFrame":
            self.center_on_screen()
            self.config(menu=tk.Menu(self)) # ซ่อนเมนู
        elif name == "LandingFrame":
            self.config(menu=self.menubar) # แสดงเมนู
            
        if hasattr(frame, "on_show"):
            frame.on_show()

class LoginFrame(ttk.Frame):
    """
    หน้าจอเข้าสู่ระบบ (Login Screen)
    - แสดงภาพพื้นหลังเต็มจอ
    - มีการ์ด Login ตรงกลาง
    - ตรวจสอบ Username/Password ผ่านฟังก์ชัน verify_user
    """
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        # 1. Background Image (Full Screen)
        self.bg_lbl = tk.Label(self, bg="#F7F8FA")
        self.bg_lbl.place(x=0, y=0, relwidth=1, relheight=1)
        
        try:
            # Load and Resize Image to cover typical screen size
            bg_path = get_resource_path("assets/login_bg.png")
            pil_img = Image.open(bg_path)
            # Resize to a large enough size to cover the window (e.g., 1366x768 or larger)
            # We can also dynamically resize, but for simplicity, let's scale it up.
            pil_img = pil_img.resize((1400, 900), Image.Resampling.LANCZOS)
            self.bg_img = ImageTk.PhotoImage(pil_img)
            self.bg_lbl.config(image=self.bg_img)
        except Exception as e:
            print(f"Error loading background: {e}")

        # 2. Login Card (Centered)
        card = ttk.Frame(self, style="Card.TFrame", padding=40)
        card.place(relx=0.5, rely=0.5, anchor="center")
        
        # Title & Subtitle
        ttk.Label(card, text="Condo Fitness", font=("Segoe UI", 28, "bold"), style="Card.TLabel").pack(pady=(0, 5))
        ttk.Label(card, text="Admin Portal", font=("Segoe UI", 16), foreground="#6B7280", style="Card.TLabel").pack(pady=(0, 30))
        
        # Username
        ttk.Label(card, text="Username", font=("Segoe UI", 10, "bold"), style="Card.TLabel").pack(anchor="w", pady=(0,5))
        self.user_ent = ttk.Entry(card, width=35, font=("Segoe UI", 11))
        self.user_ent.pack(fill=tk.X, pady=(0, 15))
        
        # Password
        ttk.Label(card, text="Password", font=("Segoe UI", 10, "bold"), style="Card.TLabel").pack(anchor="w", pady=(0,5))
        self.pass_ent = ttk.Entry(card, width=35, font=("Segoe UI", 11), show="•")
        self.pass_ent.pack(fill=tk.X, pady=(0, 25))
        self.pass_ent.bind("<Return>", lambda e: self._login())
        
        # Login Button
        login_btn = ttk.Button(card, text="Sign In", style="Primary.TButton", command=self._login)
        login_btn.pack(fill=tk.X, ipady=8)

        self.user_ent.focus_set()

    def _login(self):
        u = self.user_ent.get().strip()
        p = self.pass_ent.get()
        if not u or not p:
            messagebox.showwarning("Required", "Please enter username and password"); return
        if verify_user(u, p):
            self.controller.show_frame("LandingFrame")
            self.user_ent.delete(0, tk.END); self.pass_ent.delete(0, tk.END)
        else:
            messagebox.showerror("Invalid", "Incorrect username or password")

class LandingFrame(ttk.Frame):
    """
    หน้าจอหลักแบบ Kiosk (Landing Screen)
    - เป็นหน้าจอที่เปิดค้างไว้สำหรับให้ลูกบ้าน Check-in
    - แสดงนาฬิกาดิจิทัลขนาดใหญ่
    - มีช่องกรอกรหัสลูกบ้าน/เลขห้อง ที่รองรับการกด Enter
    - แสดงตารางประวัติการเข้าใช้งานล่าสุด (Recent Activity)
    """
    def __init__(self, parent, controller: App):
        super().__init__(parent); self.controller = controller
        self.search_q = ""
        self._build_ui()

    def _build_ui(self):
        # 1. Background Image
        self.bg_lbl = tk.Label(self, bg="#F7F8FA")
        self.bg_lbl.place(x=0, y=0, relwidth=1, relheight=1)
        
        try:
            bg_path = get_resource_path("assets/landing_bg.png")
            pil_img = Image.open(bg_path)
            pil_img = pil_img.resize((1400, 900), Image.Resampling.LANCZOS)
            self.bg_img = ImageTk.PhotoImage(pil_img)
            self.bg_lbl.config(image=self.bg_img)
        except Exception as e:
            print(f"Error loading landing bg: {e}")

        # 2. Top Container (Clock + Input) - Centered Card
        top_card = ttk.Frame(self, style="Card.TFrame", padding=30)
        top_card.pack(pady=(40, 20))
        
        # Clock
        self.clock_lbl = ttk.Label(top_card, text="", font=("Segoe UI Light", 48), style="Card.TLabel")
        self.clock_lbl.pack(pady=(0, 20))
        self._update_clock()

        # Input
        ttk.Label(top_card, text="Enter Resident No. / Room:", font=("Segoe UI", 14), style="Card.TLabel").pack(pady=(0, 10))
        
        self.res_ent = ttk.Entry(top_card, font=("Segoe UI", 24), width=15, justify="center")
        self.res_ent.pack(ipady=10)
        self.res_ent.bind("<Return>", self._on_enter)
        
        ttk.Label(top_card, text="(Press Enter to Check-in)", style="Muted.TLabel", background="#FFFFFF").pack(pady=(5,0))
        
        # Status Label
        self.status_lbl = ttk.Label(top_card, text="", font=("Segoe UI", 12), foreground="green", style="Card.TLabel")
        self.status_lbl.pack(pady=(10,0))

        # ส่วนแสดงรายการล่าสุด
        list_frame = ttk.Frame(self)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=20)
        
        # Header Row (Title + Search + Delete)
        hdr = ttk.Frame(list_frame)
        hdr.pack(fill=tk.X, pady=(0,10))
        
        ttk.Label(hdr, text="Recent Activity", font=("Segoe UI Semibold", 12)).pack(side=tk.LEFT)
        
        # Search & Actions
        actions = ttk.Frame(hdr)
        actions.pack(side=tk.RIGHT)
        
        # Search Bar Redesign
        ttk.Label(actions, text="Search:").pack(side=tk.LEFT, padx=(0,5))
        self.search_ent = ttk.Entry(actions, width=25)
        self.search_ent.pack(side=tk.LEFT, padx=(0,5))
        self.search_ent.bind("<Return>", lambda e: self.do_search())
        
        ttk.Button(actions, text="Search", style="Tool.TButton", command=self.do_search).pack(side=tk.LEFT, padx=(0,5))
        ttk.Button(actions, text="Clear", style="Tool.TButton", command=self.clear_search).pack(side=tk.LEFT, padx=(0,15))
        
        # Delete Button (Distinct)
        ttk.Button(actions, text="Delete Selected", style="Tool.TButton", command=self.delete_checkin).pack(side=tk.LEFT)

        # Container for Treeview + Scrollbar
        tree_frame = ttk.Frame(list_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("time", "resno", "name", "room", "id")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=8)
        self.tree.heading("time", text="Time")
        self.tree.heading("resno", text="No.")
        self.tree.heading("name", text="Name")
        self.tree.heading("room", text="Room")
        self.tree.heading("id", text="ID")
        
        self.tree.column("time", width=150, anchor=tk.CENTER)
        self.tree.column("resno", width=80, anchor=tk.CENTER)
        self.tree.column("name", width=250, anchor=tk.W)
        self.tree.column("room", width=100, anchor=tk.CENTER)
        self.tree.column("id", width=0, stretch=False) # Hidden ID
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscroll=vsb.set)
        
        # ตั้งค่าสีแถว
        self.tree.tag_configure("odd", background=self.controller.palette["ROW_A"])
        self.tree.tag_configure("even", background=self.controller.palette["ROW_B"])
        self.tree.tag_configure("today", background="#d4edda") # Highlight color (light green)

        # Count Label
        self.count_lbl = ttk.Label(list_frame, text="Total: 0", style="Muted.TLabel")
        self.count_lbl.pack(anchor="e", pady=(5,0))

    def _update_clock(self):
        """อัปเดตเวลาบนหน้าจอทุก 1 วินาที"""
        now = datetime.now().strftime("%H:%M:%S")
        self.clock_lbl.config(text=now)
        self.after(1000, self._update_clock)

    def _on_enter(self, event):
        """ทำงานเมื่อกด Enter ที่ช่องกรอกรหัส"""
        val = self.res_ent.get().strip()
        if not val: return
        
        # Allow alphanumeric for Room search
        self._checkin(val)
        self.res_ent.delete(0, tk.END)

    def _checkin(self, query):
        """
        ฟังก์ชันบันทึกการ Check-in
        - รับค่า query (เลขห้อง หรือ รหัสลูกบ้าน)
        - ค้นหาใน Database ว่ามีลูกบ้านคนนี้ไหม และ Active อยู่ไหม
        - ถ้ามี -> บันทึกลงตาราง checkins และแสดงข้อความสีเขียว
        - ถ้าไม่มี -> แสดง Error
        """
        with get_db_connection() as conn:
            cur = conn.cursor()
            # ค้นหาลูกบ้าน (Resident No OR Room)
            cur.execute("SELECT id, name, room, active FROM residents WHERE (resident_no = ? OR room = ?) AND deleted_at IS NULL", (query, query))
            rows = cur.fetchall()
            
            if not rows:
                messagebox.showerror("Not Found", f"Resident '{query}' not found.")
                return
            
            if len(rows) > 1:
                # กรณีเจอหลายคน (เช่น ห้องเดียวกันมีหลายคน) - ให้เลือกคนแรก หรือแจ้งเตือน
                # For now, pick the first active one, or just the first one.
                # Let's prioritize active ones.
                rows.sort(key=lambda x: x[3], reverse=True)
                
            row = rows[0]
            rid, name, room, active = row
            
            if not active:
                messagebox.showwarning("Inactive", f"Resident {name} ({room}) is inactive/expired.")
                return

            # บันทึก
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cur.execute("INSERT INTO checkins(resident_id, checkin_time) VALUES (?,?)", (rid, now))
            conn.commit()
            
            # UX Improvement: Non-blocking feedback (แจ้งเตือนแบบไม่ขัดจังหวะ)
            self.status_lbl.config(text=f"✔ Check-in: {name} ({room})", foreground="green")
            self.after(3000, lambda: self.status_lbl.config(text="")) # Clear after 3s
            
            self.refresh()
            self.res_ent.focus_set() # Auto-focus (โฟกัสกลับไปที่ช่องกรอกทันที)

    def refresh(self):
        """โหลดรายการล่าสุดมาแสดง"""
        with get_db_connection() as conn:
            cur = conn.cursor()
            
            sql = """
                SELECT c.id, c.checkin_time, r.resident_no, r.name, r.room
                FROM checkins c
                JOIN residents r ON r.id = c.resident_id
                WHERE 1=1
            """
            params = []
            if self.search_q:
                sql += " AND (r.name LIKE ? OR r.room LIKE ? OR r.resident_no LIKE ?)"
                like = f"%{self.search_q}%"
                params.extend([like, like, like])
            
            sql += " ORDER BY c.checkin_time DESC LIMIT 20"
            
            cur.execute(sql, params)
            rows = cur.fetchall()
            
        for i in self.tree.get_children():
            self.tree.delete(i)
            
        today_str = datetime.now().strftime("%Y-%m-%d")
        for idx, r in enumerate(rows):
            # r = (id, time, resno, name, room)
            cid = r[0]
            t_str = r[1].split(".")[0]
            
            tag = "even" if idx % 2 else "odd"
            if r[1].startswith(today_str):
                tag = "today"
                
            self.tree.insert("", tk.END, values=(t_str, f"{r[2]:04d}", r[3], r[4], cid), tags=(tag,))
            
        self.count_lbl.config(text=f"Total shown: {len(rows)}")

    def do_search(self):
        self.search_q = self.search_ent.get().strip()
        self.refresh()

    def clear_search(self):
        self.search_ent.delete(0, tk.END)
        self.search_q = ""
        self.refresh()

    def delete_checkin(self):
        sel = self.tree.selection()
        if not sel: return
        if not messagebox.askyesno("Confirm", "Delete selected check-in record?"): return
        
        cid = self.tree.item(sel[0], "values")[4] # Hidden ID column
        with get_db_connection() as conn:
            conn.execute("DELETE FROM checkins WHERE id=?", (cid,))
            conn.commit()
        self.refresh()

    def on_show(self):
        """ทำงานเมื่อหน้าจอนี้ถูกแสดง"""
        self.res_ent.delete(0, tk.END)
        self.res_ent.focus_set()
        self.refresh()

class DatePicker(tk.Toplevel):
    """
    หน้าต่างเลือกวันที่ (Date Picker Dialog) - Modern Version
    """
    def __init__(self, parent, target_entry: ttk.Entry):
        super().__init__(parent); self.withdraw()
        self.title("Select Date"); self.resizable(False, False)
        self.target = target_entry
        self.today = date.today()
        self.year = self.today.year; self.month = self.today.month
        self.sel_date = None
        
        try:
            curr = datetime.strptime(target_entry.get(), "%Y-%m-%d").date()
            self.year = curr.year; self.month = curr.month; self.sel_date = curr
        except: pass

        self.configure(bg="#FFFFFF")
        self._build_ui()
        
        # Position near mouse or center
        try:
            x = parent.winfo_pointerx() - 10; y = parent.winfo_pointery() + 10
            self.geometry(f"+{x}+{y}")
        except: self.center_on_parent()
        
        self.deiconify(); self.transient(parent); self.grab_set()

    def _build_ui(self):
        main = ttk.Frame(self, padding=15, style="Card.TFrame")
        main.pack(fill=tk.BOTH, expand=True)

        # Header (Month/Year Navigation) - Clean & Minimal
        hdr = ttk.Frame(main, style="Card.TFrame")
        hdr.pack(fill=tk.X, pady=(0, 15))
        
        # Left Controls
        left_box = ttk.Frame(hdr, style="Card.TFrame")
        left_box.pack(side=tk.LEFT)
        ttk.Button(left_box, text="«", style="CalNav.TButton", command=lambda: self.change_year(-1)).pack(side=tk.LEFT)
        ttk.Button(left_box, text="‹", style="CalNav.TButton", command=lambda: self.change_month(-1)).pack(side=tk.LEFT)
        
        # Title (Month Year)
        self.lbl = ttk.Label(hdr, text=f"{pycal.month_name[self.month]} {self.year}", font=("Segoe UI", 12, "bold"), anchor="center", style="Card.TLabel")
        self.lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Right Controls
        right_box = ttk.Frame(hdr, style="Card.TFrame")
        right_box.pack(side=tk.RIGHT)
        ttk.Button(right_box, text="›", style="CalNav.TButton", command=lambda: self.change_month(1)).pack(side=tk.LEFT)
        ttk.Button(right_box, text="»", style="CalNav.TButton", command=lambda: self.change_year(1)).pack(side=tk.LEFT)

        # Days Grid
        self.grid_frame = ttk.Frame(main, style="Card.TFrame")
        self.grid_frame.pack()
        self._render_month()
        
        # Footer (Today Button) - Minimal Link Style
        ftr = ttk.Frame(main, style="Card.TFrame")
        ftr.pack(fill=tk.X, pady=(15, 0))
        
        # Using a Label that looks like a link or a subtle button
        today_btn = ttk.Button(ftr, text="Jump to Today", style="CalNav.TButton", width=15, command=self.go_today)
        today_btn.pack()

    def _render_month(self):
        for w in self.grid_frame.winfo_children(): w.destroy()
        days = ["Mo","Tu","We","Th","Fr","Sa","Su"]
        
        # Header Row
        for i, d in enumerate(days):
            ttk.Label(self.grid_frame, text=d, width=5, anchor="center", foreground="#9CA3AF", background="#FFFFFF", font=("Segoe UI", 9)).grid(row=0, column=i, pady=(0,8))
        
        cal = pycal.Calendar(firstweekday=0)
        row = 1
        for week in cal.monthdayscalendar(self.year, self.month):
            for col, day in enumerate(week):
                if day == 0:
                    ttk.Label(self.grid_frame, text="", width=5, background="#FFFFFF").grid(row=row, column=col)
                else:
                    style = "Calendar.TButton"
                    if self.sel_date and day == self.sel_date.day and self.month == self.sel_date.month and self.year == self.sel_date.year:
                        style = "CalendarSelected.TButton"
                    elif day == self.today.day and self.month == self.today.month and self.year == self.today.year:
                        style = "CalendarToday.TButton"
                    
                    btn = ttk.Button(self.grid_frame, text=str(day), style=style, command=lambda d=day: self.pick(d))
                    btn.grid(row=row, column=col, padx=2, pady=2) # More spacing
            row += 1

    def change_month(self, delta):
        self.month += delta
        if self.month < 1: self.month = 12; self.year -= 1
        elif self.month > 12: self.month = 1; self.year += 1
        self.lbl.config(text=f"{pycal.month_name[self.month]} {self.year}"); self._render_month()

    def change_year(self, delta):
        self.year += delta
        self.lbl.config(text=f"{pycal.month_name[self.month]} {self.year}"); self._render_month()

    def go_today(self):
        self.year = self.today.year; self.month = self.today.month
        self.lbl.config(text=f"{pycal.month_name[self.month]} {self.year}"); self._render_month()

    def pick(self, day): 
        d = date(self.year, self.month, day)
        self.target.delete(0, tk.END); self.target.insert(0, d.strftime("%Y-%m-%d")); self.destroy()

# -------------------------
# Residents + Membership + History
# -------------------------
def log_contract_change(resident_id, action, old_days, new_days, old_start, new_start):
    """บันทึกประวัติการแก้ไขสัญญา"""
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("""INSERT INTO contract_logs(resident_id, action, old_days, new_days, old_start, new_start)
                       VALUES (?,?,?,?,?,?)""",
                    (resident_id, action, old_days, new_days, old_start, new_start))
        conn.commit()

class ResidentsDialog(tk.Toplevel):
    """
    หน้าต่างจัดการข้อมูลลูกบ้าน (Manage Residents)
    """
    def __init__(self, parent):
        super().__init__(parent); self.parent = parent
        self.title("Manage Residents"); self.geometry("1300x700"); self.resizable(True, True)
        self.page = 1; self.search_q = ""; self.active_only = tk.IntVar(value=0)
        self.page_size = PAGE_SIZE_DEFAULT
        self.sort_col = "resident_no"; self.sort_desc = False # Default sort
        self.deb = Debouncer(self, 400)
        self._build_ui(); self.refresh(); self.transient(parent); self.grab_set()

    def _build_ui(self):
        # Container
        top_container = ttk.Frame(self)
        top_container.pack(fill=tk.X, padx=20, pady=(20,10))
        
        # แถวที่ 1: ค้นหา (Search)
        row1 = ttk.Frame(top_container)
        row1.pack(fill=tk.X, pady=(0, 8))
        
        ttk.Label(row1, text="Search").pack(side=tk.LEFT)
        self.q_ent = ttk.Entry(row1, width=28)
        self.q_ent.pack(side=tk.LEFT, padx=(6,8))
        self.q_ent.bind("<KeyRelease>", lambda e: self.deb.call(self.do_search))
        
        ttk.Button(row1, text="Find", style="Secondary.TButton", command=self.do_search).pack(side=tk.LEFT)
        ttk.Button(row1, text="Clear", style="Tool.TButton", command=self.clear_search).pack(side=tk.LEFT, padx=(6,0))
        ttk.Checkbutton(row1, text="Active only", variable=self.active_only, command=self.refresh).pack(side=tk.LEFT, padx=(12,0))

        # แถวที่ 2: ปุ่มคำสั่ง (Actions)
        row2 = ttk.Frame(top_container)
        row2.pack(fill=tk.X)
        
        # เครื่องมือ (ซ้าย)
        tools_frame = ttk.Frame(row2)
        tools_frame.pack(side=tk.LEFT)
        
        ttk.Button(tools_frame, text="Export CSV", style="Tool.TButton", command=self.export_csv).pack(side=tk.LEFT, padx=(0,6))
        # Import CSV removed as requested
        # History button removed as requested
        # History button removed as requested
        ttk.Button(tools_frame, text="Membership Types", style="Tool.TButton", command=self.manage_membership).pack(side=tk.LEFT)
        
        # จัดการข้อมูล (ขวา)
        crud_frame = ttk.Frame(row2)
        crud_frame.pack(side=tk.RIGHT)
        
        ttk.Button(crud_frame, text="Renew Contract", style="Tool.TButton", command=self.renew_contract).pack(side=tk.LEFT, padx=(0,6))
        ttk.Button(crud_frame, text="Add", style="Primary.TButton", command=self.add_resident).pack(side=tk.LEFT, padx=(0,6))
        ttk.Button(crud_frame, text="Edit", style="Secondary.TButton", command=self.edit_resident).pack(side=tk.LEFT, padx=(0,6))
        ttk.Button(crud_frame, text="Delete", style="Tool.TButton", command=self.delete_resident).pack(side=tk.LEFT)

        # ตารางแสดงข้อมูล
        frame = ttk.Frame(self); frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0,20))
        cols = ("id","resno","name","room","trainer","active","membership","contract_start","contract_days","days_left")
        self.tree = ttk.Treeview(frame, columns=cols, show="headings")
        headers = [
            ("id",60),("resno",70),("name",220),("room",90),("trainer",160),
            ("active",70),("membership",150),("contract_start",120),("contract_days",110),("days_left",90)
        ]
        for c,w in headers:
            self.tree.heading(c, text=c.replace("_"," ").title(), command=lambda _c=c: self.tree_sort_column(_c))
            anchor = tk.CENTER if c in ("id","resno","active","contract_days","days_left") else tk.W
            self.tree.column(c, width=w, anchor=anchor)

        self.tree.tag_configure("odd",  background=self.parent.palette["ROW_A"])
        self.tree.tag_configure("even", background=self.parent.palette["ROW_B"])
        self.tree.tag_configure("expired", background=self.parent.palette["EXPIRED_BG"]) # Red (Expired)
        self.tree.tag_configure("expiring", background="#FFEDD5") # Orange (Expiring Soon < 7 days)

        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew"); vsb.grid(row=0, column=1, sticky="ns")
        frame.rowconfigure(0, weight=1); frame.columnconfigure(0, weight=1)

        # ปุ่มเปลี่ยนหน้า (Pagination) - Swap Next/Prev
        pager = ttk.Frame(self); pager.pack(fill=tk.X, padx=20, pady=(0,20))
        self.info_lbl = ttk.Label(pager, text="", style="Muted.TLabel"); self.info_lbl.pack(side=tk.LEFT)
        
        # Next ขวา, Prev ซ้าย (ตามคำขอ)
        ttk.Button(pager, text="Next", style="Tool.TButton", command=self.next_page).pack(side=tk.RIGHT)
        ttk.Button(pager, text="Prev", style="Tool.TButton", command=self.prev_page).pack(side=tk.RIGHT, padx=(0,6))

        self.bind("<Control-n>", lambda e: self.add_resident())
        self.tree.bind("<Double-1>", lambda e: self.edit_resident())
        self.tree.bind_all("<Control-c>", lambda e: copy_selected_tree_rows_to_clipboard(self.tree))
        self.bind_all("<Delete>", lambda e: self.delete_resident())

    def do_search(self):
        self.search_q = self.q_ent.get().strip(); self.page = 1; self.refresh()

    def clear_search(self):
        self.q_ent.delete(0, tk.END); self.search_q = ""; self.page = 1; self.refresh()

    def tree_sort_column(self, col):
        """เรียงลำดับข้อมูลตามคอลัมน์ที่คลิก"""
        if self.sort_col == col:
            self.sort_desc = not self.sort_desc
        else:
            self.sort_col = col
            self.sort_desc = False
        self.refresh()

    def refresh(self):
        """โหลดข้อมูลลูกบ้านมาแสดงในตาราง"""
        offset = (self.page - 1) * self.page_size
        with get_db_connection() as conn:
            cur = conn.cursor()
            
            # สร้าง Query
            base_sql = """
                SELECT r.id, r.resident_no, r.name, r.room, t.name, r.active, 
                       m.name, r.contract_start, r.contract_days
                FROM residents r
                LEFT JOIN trainers t ON t.id = r.trainer_id
                LEFT JOIN membership_types m ON m.id = r.membership_type_id
                WHERE 1=1
            """
            params = []
            if self.active_only.get():
                # Filter active AND not expired (end_date > tomorrow)
                # Matches Python logic: (end_dt - now).days > 0
                base_sql += """ AND r.active = 1 AND (
                    r.contract_start IS NULL OR r.contract_start = '' OR 
                    r.contract_days IS NULL OR r.contract_days = '' OR 
                    date(r.contract_start, '+' || r.contract_days || ' days') > date('now', 'localtime', '+1 day')
                )"""
            
            if self.search_q:
                base_sql += " AND (r.name LIKE ? OR r.room LIKE ?)"
                like = f"%{self.search_q}%"; params += [like, like]

            # นับจำนวนทั้งหมด
            count_sql = f"SELECT COUNT(*) FROM ({base_sql})"
            cur.execute(count_sql, params); total = cur.fetchone()[0]

            # ดึงข้อมูลตามหน้า (Sorting Logic)
            sort_map = {
                "resno": "r.resident_no", "name": "r.name", "room": "r.room",
                "contract_days": "r.contract_days", "contract_start": "r.contract_start",
                "days_left": "r.contract_start" # Sort by start date approximates days left sort
            }
            order_by = sort_map.get(self.sort_col, "r.resident_no")
            direction = "DESC" if self.sort_desc else "ASC"
            
            sql = base_sql + f" ORDER BY {order_by} {direction} LIMIT ? OFFSET ?"
            params += [self.page_size, offset]
            cur.execute(sql, params); rows = cur.fetchall()

        # แสดงผล
        for i in self.tree.get_children(): self.tree.delete(i)
        
        for idx, r in enumerate(rows):
            rid, rno, name, room, tname, active, mname, c_start, c_days = r
            
            # คำนวณวันคงเหลือ
            days_left = "-"
            is_expired = False
            if active and c_start and c_days:
                try:
                    start_dt = datetime.strptime(c_start, "%Y-%m-%d")
                    end_dt = start_dt + timedelta(days=c_days)
                    left = (end_dt - datetime.now()).days
                    days_left = str(max(0, left))
                    if left <= 0: # Changed from < 0 to <= 0
                        is_expired = True
                        active = 0 # Treat as inactive for display
                except: pass

            tag = "expired" if is_expired else ("even" if idx % 2 else "odd")
            
            # UX: Highlight expiring soon (< 7 days)
            if not is_expired and days_left != "-" and int(days_left) <= 7:
                tag = "expiring"
                
            vals = (rid, f"{rno:04d}", name, room, tname or "-", "Yes" if active else "No",
                    mname or "-", c_start or "-", c_days or "-", days_left)
            self.tree.insert("", tk.END, values=vals, tags=(tag,))

        # อัปเดตสถานะหน้า
        self.total_pages = (total + self.page_size - 1) // self.page_size or 1
        self.info_lbl.config(text=f"Page {self.page}/{self.total_pages} (Total {total})")

    def prev_page(self):
        if self.page > 1: self.page -= 1; self.refresh()
    
    def next_page(self):
        if self.page < self.total_pages: self.page += 1; self.refresh()

    def add_resident(self): ResidentForm(self, None)
    def edit_resident(self):
        sel = self.tree.selection()
        if not sel: return
        rid = self.tree.item(sel[0], "values")[0]
        ResidentForm(self, rid)

    def delete_resident(self):
        """ลบลูกบ้านถาวร (Hard Delete)"""
        sel = self.tree.selection()
        if not sel: return
        if not messagebox.askyesno("Confirm", "Permanently delete selected resident(s)?\nThis cannot be undone."): return
        
        with get_db_connection() as conn:
            cur = conn.cursor()
            for s in sel:
                rid = self.tree.item(s, "values")[0]
                # Check for dependencies if needed, or cascade delete
                cur.execute("DELETE FROM checkins WHERE resident_id = ?", (rid,))
                cur.execute("DELETE FROM contract_logs WHERE resident_id = ?", (rid,))
                cur.execute("DELETE FROM residents WHERE id = ?", (rid,))
            conn.commit()
        self.refresh()

    def renew_contract(self):
        """ต่อสัญญา"""
        sel = self.tree.selection()
        if not sel: return
        rid = self.tree.item(sel[0], "values")[0]
        
        # ถามจำนวนวันที่จะต่อ
        dlg = tk.Toplevel(self); dlg.title("Renew Contract"); dlg.geometry("300x150")
        ttk.Label(dlg, text="Add days:").pack(pady=10)
        ent = ttk.Entry(dlg); ent.pack()
        ent.insert(0, "30")
        
        def save():
            try:
                days = int(ent.get())
            except: return
            
            with get_db_connection() as conn:
                cur = conn.cursor()
                # ดึงข้อมูลเดิม
                cur.execute("SELECT contract_days, contract_start FROM residents WHERE id=?", (rid,))
                row = cur.fetchone()
                old_days = row[0] or 0
                old_start = row[1] or datetime.now().strftime("%Y-%m-%d")
                
                new_days = old_days + days
                
                cur.execute("UPDATE residents SET contract_days=?, active=1 WHERE id=?", (new_days, rid))
                
                # บันทึก Log
                cur.execute("""INSERT INTO contract_logs(resident_id, action, old_days, new_days, old_start, new_start)
                               VALUES (?,?,?,?,?,?)""",
                            (rid, "RENEW", old_days, new_days, old_start, old_start))
                conn.commit()
            self.refresh(); dlg.destroy()
            
        ttk.Button(dlg, text="Save", command=save).pack(pady=10)

    def export_csv(self):
        """ส่งออกข้อมูลเป็น CSV"""
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not path: return
        try:
            with get_db_connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT * FROM residents")
                rows = cur.fetchall()
                cols = [d[0] for d in cur.description]
            
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(cols)
                writer.writerows(rows)
            messagebox.showinfo("Export", "Done.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def import_csv(self):
        """นำเข้าข้อมูลจาก CSV"""
        path = filedialog.askopenfilename(filetypes=[("CSV","*.csv")])
        if not path: return
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                data = list(reader)
            
            with get_db_connection() as conn:
                cur = conn.cursor()
                for row in data:
                    # ตัวอย่างการ import แบบง่าย (ควรมีการตรวจสอบข้อมูลก่อน)
                    cur.execute("""
                        INSERT INTO residents(resident_no, name, room, active, trainer_id)
                        VALUES (?,?,?,?,?)
                    """, (row.get("resident_no"), row.get("name"), row.get("room"), 1, None))
                conn.commit()
            self.refresh(); messagebox.showinfo("Import", f"Imported {len(data)} rows.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def open_history(self):
        """ดูประวัติการแก้ไขสัญญา"""
        sel = self.tree.selection()
        if not sel: return
        rid = self.tree.item(sel[0], "values")[0]
        HistoryDialog(self, rid)

    def manage_membership(self):
        MembershipDialog(self)

class ResidentForm(tk.Toplevel):
    """
    ฟอร์มเพิ่ม/แก้ไขข้อมูลลูกบ้าน
    """
    def __init__(self, parent, resident_id=None):
        super().__init__(parent); self.parent = parent; self.rid = resident_id
        self.title("Resident Form"); self.geometry("500x550"); self.resizable(False, False)
        self._build_ui(); self._load_data()
        self.transient(parent); self.grab_set()

    def _build_ui(self):
        f = ttk.Frame(self, padding=20); f.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(f, text="Name *").grid(row=0, column=0, sticky="w", pady=5)
        self.name_ent = ttk.Entry(f, width=40); self.name_ent.grid(row=1, column=0, columnspan=2, sticky="ew")
        
        ttk.Label(f, text="Room *").grid(row=2, column=0, sticky="w", pady=5)
        # Change to Combobox for Autocomplete
        self.room_var = tk.StringVar()
        self.room_ent = ttk.Combobox(f, textvariable=self.room_var, width=20)
        self.room_ent.grid(row=3, column=0, sticky="w")
        self.room_ent.bind("<KeyRelease>", self._filter_rooms)
        
        ttk.Label(f, text="Trainer").grid(row=4, column=0, sticky="w", pady=5)
        self.trainer_var = tk.StringVar()
        self.trainer_cb = ttk.Combobox(f, textvariable=self.trainer_var, state="readonly")
        self.trainer_cb.grid(row=5, column=0, sticky="ew")
        
        ttk.Label(f, text="Membership Type").grid(row=6, column=0, sticky="w", pady=5)
        self.mem_var = tk.StringVar()
        self.mem_cb = ttk.Combobox(f, textvariable=self.mem_var, state="readonly")
        self.mem_cb.grid(row=7, column=0, sticky="ew")
        self.mem_cb.bind("<<ComboboxSelected>>", self._on_mem_change)
        
        ttk.Label(f, text="Contract Start (YYYY-MM-DD)").grid(row=8, column=0, sticky="w", pady=5)
        self.start_ent = ttk.Entry(f, width=20); self.start_ent.grid(row=9, column=0, sticky="w")
        ttk.Button(f, text="📅", style="Tool.TButton", width=3,
                   command=lambda: DatePicker(self, self.start_ent)).grid(row=9, column=1, sticky="w")
        
        ttk.Label(f, text="Duration (Days)").grid(row=10, column=0, sticky="w", pady=5)
        self.days_ent = ttk.Entry(f, width=10); self.days_ent.grid(row=11, column=0, sticky="w")
        
        self.active_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(f, text="Active", variable=self.active_var).grid(row=12, column=0, sticky="w", pady=15)
        
        btns = ttk.Frame(f); btns.grid(row=13, column=0, columnspan=2, sticky="e", pady=20)
        ttk.Button(btns, text="Save", style="Primary.TButton", command=self.save).pack(side=tk.LEFT, padx=5)
        ttk.Button(btns, text="Cancel", style="Secondary.TButton", command=self.destroy).pack(side=tk.LEFT)

        # Load combos
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, name FROM trainers ORDER BY name")
            self.trainers = cur.fetchall()
            self.trainer_cb["values"] = ["- None -"] + [t[1] for t in self.trainers]
            
            cur.execute("SELECT id, name, duration_days FROM membership_types ORDER BY name")
            self.mems = cur.fetchall()
            self.mem_cb["values"] = ["- Custom -"] + [m[1] for m in self.mems]

            # Load Rooms for Autocomplete
            cur.execute("SELECT room_number FROM rooms ORDER BY room_number")
            self.all_rooms = [r[0] for r in cur.fetchall()]
            self.room_ent["values"] = self.all_rooms

    def _filter_rooms(self, event):
        """Filter room list based on user input"""
        val = self.room_var.get().lower()
        if val == "":
            self.room_ent["values"] = self.all_rooms
        else:
            filtered = [r for r in self.all_rooms if val in r.lower()]
            self.room_ent["values"] = filtered
            if filtered:
                self.room_ent.event_generate("<<ComboboxSelected>>") # Optional: Trigger selection logic if needed
                # To show dropdown automatically:
                # self.room_ent.tk.call('ttk::combobox::Post', self.room_ent) 
                # But this can be annoying while typing, so maybe just let user click or press Down

    def _on_mem_change(self, event):
        idx = self.mem_cb.current()
        if idx > 0:
            mid, mname, dur = self.mems[idx-1]
            self.days_ent.delete(0, tk.END); self.days_ent.insert(0, str(dur))
            if not self.start_ent.get():
                self.start_ent.insert(0, datetime.now().strftime("%Y-%m-%d"))

    def _load_data(self):
        if not self.rid: return
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT name, room, trainer_id, active, membership_type_id, contract_start, contract_days FROM residents WHERE id=?", (self.rid,))
            row = cur.fetchone()
            if row:
                self.name_ent.insert(0, row[0])
                self.room_ent.set(row[1]) # Use set() for Combobox
                
                # Set Trainer
                tid = row[2]
                if tid:
                    for i, t in enumerate(self.trainers):
                        if t[0] == tid: self.trainer_cb.current(i+1); break
                else: self.trainer_cb.current(0)
                
                self.active_var.set(bool(row[3]))
                
                # Set Membership
                mid = row[4]
                if mid:
                    for i, m in enumerate(self.mems):
                        if m[0] == mid: self.mem_cb.current(i+1); break
                else: self.mem_cb.current(0)
                
                if row[5]: self.start_ent.insert(0, row[5])
                if row[6]: self.days_ent.insert(0, str(row[6]))

    def save(self):
        name = self.name_ent.get().strip()
        room = self.room_ent.get().strip() # Works for Combobox too
        if not name or not room:
            messagebox.showwarning("Required", "Name and Room are required."); return
        
        tid = None
        if self.trainer_cb.current() > 0:
            tid = self.trainers[self.trainer_cb.current()-1][0]
            
        mid = None
        if self.mem_cb.current() > 0:
            mid = self.mems[self.mem_cb.current()-1][0]
            
        c_start = self.start_ent.get().strip() or None
        c_days = self.days_ent.get().strip() or None
        
        with get_db_connection() as conn:
            cur = conn.cursor()
            if self.rid:
                # Update
                cur.execute("""UPDATE residents SET name=?, room=?, trainer_id=?, active=?, 
                               membership_type_id=?, contract_start=?, contract_days=? WHERE id=?""",
                            (name, room, tid, 1 if self.active_var.get() else 0, mid, c_start, c_days, self.rid))
            else:
                # Insert
                # Fix: Ensure unique resident_no
                while True:
                    rn = next_sequence(cur, "resident_no")
                    cur.execute("SELECT 1 FROM residents WHERE resident_no = ?", (rn,))
                    if not cur.fetchone():
                        break
                        
                cur.execute("""INSERT INTO residents(resident_no, name, room, trainer_id, active, 
                               membership_type_id, contract_start, contract_days) 
                               VALUES (?,?,?,?,?,?,?,?)""",
                            (rn, name, room, tid, 1 if self.active_var.get() else 0, mid, c_start, c_days))
                
                # Get the new resident ID
                rid = cur.lastrowid
                
                # Log the initial contract if provided
                if c_start and c_days:
                    cur.execute("""INSERT INTO contract_logs(resident_id, action, old_days, new_days, old_start, new_start)
                                   VALUES (?,?,?,?,?,?)""",
                                (rid, "NEW", 0, c_days, None, c_start))
            conn.commit()
        self.parent.refresh(); self.destroy()

class TrainersDialog(tk.Toplevel):
    """
    หน้าต่างจัดการข้อมูลเทรนเนอร์ (Manage Trainers)
    """
    def __init__(self, parent):
        super().__init__(parent); self.parent = parent
        self.title("Manage Trainers"); self.geometry("900x600"); self.resizable(False, False)
        self.page = 1; self.page_size = 10
        self.search_q = ""; self.sort_col = "id"; self.sort_desc = False
        self.deb = Debouncer(self, 400)
        self._build_ui(); self.refresh(); self.transient(parent); self.grab_set()

    def _build_ui(self):
        # Top Bar: Search & Actions
        top = ttk.Frame(self); top.pack(fill=tk.X, padx=20, pady=20)
        
        # Search
        ttk.Label(top, text="Search").pack(side=tk.LEFT)
        self.q_ent = ttk.Entry(top, width=20)
        self.q_ent.pack(side=tk.LEFT, padx=(5,5))
        self.q_ent.bind("<KeyRelease>", lambda e: self.deb.call(self.do_search))
        ttk.Button(top, text="Clear", style="Tool.TButton", command=self.clear_search).pack(side=tk.LEFT)

        # Actions
        ttk.Button(top, text="Delete", style="Tool.TButton", command=self.delete).pack(side=tk.RIGHT)
        ttk.Button(top, text="Edit", style="Secondary.TButton", command=self.edit).pack(side=tk.RIGHT, padx=5)
        ttk.Button(top, text="Add Trainer", style="Primary.TButton", command=self.add).pack(side=tk.RIGHT, padx=5)

        # Table
        cols = ("id", "name", "phone", "specialty", "level", "clients")
        self.tree = ttk.Treeview(self, columns=cols, show="headings")
        self.tree.heading("id", text="ID", command=lambda: self.tree_sort_column("id"))
        self.tree.heading("name", text="Name", command=lambda: self.tree_sort_column("name"))
        self.tree.heading("phone", text="Phone")
        self.tree.heading("specialty", text="Specialty")
        self.tree.heading("level", text="Level")
        self.tree.heading("clients", text="Clients")
        
        self.tree.column("id", width=60, anchor=tk.CENTER)
        self.tree.column("name", width=200)
        self.tree.column("phone", width=120)
        self.tree.column("specialty", width=150)
        self.tree.column("level", width=100, anchor=tk.CENTER)
        self.tree.column("clients", width=80, anchor=tk.CENTER)
        
        self.tree.pack(fill=tk.BOTH, expand=True, padx=20)
        
        vsb = ttk.Scrollbar(self.tree, orient=tk.VERTICAL, command=self.tree.yview)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscroll=vsb.set)
        
        self.tree.bind("<Double-1>", lambda e: self.edit())

        # Pagination
        pager = ttk.Frame(self); pager.pack(fill=tk.X, padx=20, pady=(0,20))
        self.info_lbl = ttk.Label(pager, text="", style="Muted.TLabel"); self.info_lbl.pack(side=tk.LEFT)
        ttk.Button(pager, text="Next", style="Tool.TButton", command=self.next_page).pack(side=tk.RIGHT)
        ttk.Button(pager, text="Prev", style="Tool.TButton", command=self.prev_page).pack(side=tk.RIGHT, padx=(0,6))

    def refresh(self):
        offset = (self.page - 1) * self.page_size
        for i in self.tree.get_children(): self.tree.delete(i)
        
        with get_db_connection() as conn:
            cur = conn.cursor()
            
            sql = "SELECT id, name, phone, specialty, level FROM trainers WHERE 1=1"
            params = []
            if self.search_q:
                sql += " AND (name LIKE ? OR specialty LIKE ?)"
                params.extend([f"%{self.search_q}%", f"%{self.search_q}%"])
            
            # Count
            count_sql = f"SELECT COUNT(*) FROM ({sql})"
            cur.execute(count_sql, params); total = cur.fetchone()[0]
            
            # Sort & Limit
            direction = "DESC" if self.sort_desc else "ASC"
            sql += f" ORDER BY {self.sort_col} {direction} LIMIT ? OFFSET ?"
            params.extend([self.page_size, offset])
            
            cur.execute(sql, params)
            rows = cur.fetchall()
            
            for r in rows:
                tid = r[0]
                # Count active clients
                cur.execute("SELECT COUNT(*) FROM residents WHERE trainer_id=? AND active=1", (tid,))
                client_cnt = cur.fetchone()[0]
                
                self.tree.insert("", tk.END, values=(*r, client_cnt))
            
        self.total_pages = (total + self.page_size - 1) // self.page_size or 1
        self.info_lbl.config(text=f"Page {self.page}/{self.total_pages} (Total {total})")

    def do_search(self):
        self.search_q = self.q_ent.get().strip(); self.page = 1; self.refresh()
    def clear_search(self):
        self.q_ent.delete(0, tk.END); self.search_q = ""; self.page = 1; self.refresh()

    def tree_sort_column(self, col):
        if self.sort_col == col: self.sort_desc = not self.sort_desc
        else: self.sort_col = col; self.sort_desc = False
        self.refresh()

    def prev_page(self):
        if self.page > 1: self.page -= 1; self.refresh()
    
    def next_page(self):
        if self.page < self.total_pages: self.page += 1; self.refresh()

    def add(self): TrainerForm(self, None)
    def edit(self):
        sel = self.tree.selection()
        if not sel: return
        tid = self.tree.item(sel[0], "values")[0]
        TrainerForm(self, tid)

    def delete(self):
        sel = self.tree.selection()
        if not sel: return
        if not messagebox.askyesno("Confirm", "Delete selected trainer?"): return
        tid = self.tree.item(sel[0], "values")[0]
        with get_db_connection() as conn:
            cur = conn.cursor()
            # ตรวจสอบว่ามีลูกบ้านผูกอยู่หรือไม่
            cur.execute("SELECT COUNT(1) FROM residents WHERE trainer_id=?", (tid,))
            if cur.fetchone()[0] > 0:
                messagebox.showerror("Error", "Cannot delete: This trainer is assigned to residents."); return
            cur.execute("DELETE FROM trainers WHERE id=?", (tid,))
            conn.commit()
        self.refresh()

class TrainerForm(tk.Toplevel):
    """
    ฟอร์มเพิ่ม/แก้ไขเทรนเนอร์
    """
    def __init__(self, parent, tid=None):
        super().__init__(parent); self.parent = parent; self.tid = tid
        self.title("Trainer Form"); self.geometry("450x450"); self.resizable(False, False)
        self._build_ui(); self._load_data(); self.transient(parent); self.grab_set()

    def _build_ui(self):
        f = ttk.Frame(self, padding=20); f.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(f, text="Name *").grid(row=0, column=0, sticky="w", pady=5)
        self.name_ent = ttk.Entry(f, width=30); self.name_ent.grid(row=1, column=0, sticky="ew")
        
        ttk.Label(f, text="Phone").grid(row=2, column=0, sticky="w", pady=5)
        self.phone_ent = ttk.Entry(f, width=30); self.phone_ent.grid(row=3, column=0, sticky="ew")
        
        ttk.Label(f, text="Specialty").grid(row=4, column=0, sticky="w", pady=5)
        self.spec_ent = ttk.Entry(f, width=30); self.spec_ent.grid(row=5, column=0, sticky="ew")
        
        ttk.Label(f, text="Level").grid(row=6, column=0, sticky="w", pady=5)
        self.level_cb = ttk.Combobox(f, values=["Junior", "Senior", "Master"], state="readonly")
        self.level_cb.grid(row=7, column=0, sticky="ew")
        self.level_cb.current(0)

        btns = ttk.Frame(f); btns.grid(row=8, column=0, pady=30, sticky="e")
        ttk.Button(btns, text="Save", style="Primary.TButton", command=self.save).pack(side=tk.LEFT, padx=5)
        ttk.Button(btns, text="Cancel", style="Secondary.TButton", command=self.destroy).pack(side=tk.LEFT)

    def _load_data(self):
        if not self.tid: return
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT name, phone, specialty, level FROM trainers WHERE id=?", (self.tid,))
            row = cur.fetchone()
            if row:
                self.name_ent.insert(0, row[0])
                if row[1]: self.phone_ent.insert(0, row[1])
                if row[2]: self.spec_ent.insert(0, row[2])
                if row[3] and row[3] in self.level_cb["values"]: self.level_cb.set(row[3])

    def save(self):
        name = self.name_ent.get().strip()
        phone = self.phone_ent.get().strip()
        spec = self.spec_ent.get().strip()
        level = self.level_cb.get()
        
        if not name: messagebox.showwarning("Required", "Name is required."); return
        
        with get_db_connection() as conn:
            cur = conn.cursor()
            if self.tid:
                cur.execute("UPDATE trainers SET name=?, phone=?, specialty=?, level=? WHERE id=?", (name, phone, spec, level, self.tid))
            else:
                cur.execute("INSERT INTO trainers(name, phone, specialty, level) VALUES (?,?,?,?)", (name, phone, spec, level))
            conn.commit()
        self.parent.refresh(); self.destroy()

class MembershipDialog(tk.Toplevel):
    """
    หน้าต่างจัดการประเภทสมาชิก (Membership Types)
    """
    def __init__(self, parent):
        super().__init__(parent); self.parent = parent
        self.title("Membership Types"); self.geometry("700x500"); self.resizable(False, False)
        self.page = 1; self.page_size = 10
        self.search_q = ""; self.sort_col = "id"; self.sort_desc = False
        self.deb = Debouncer(self, 400)
        self._build_ui(); self.refresh(); self.transient(parent); self.grab_set()

    def _build_ui(self):
        # Top Bar: Search & Actions
        top = ttk.Frame(self); top.pack(fill=tk.X, padx=20, pady=20)
        
        # Search
        ttk.Label(top, text="Search").pack(side=tk.LEFT)
        self.q_ent = ttk.Entry(top, width=20)
        self.q_ent.pack(side=tk.LEFT, padx=(5,5))
        self.q_ent.bind("<KeyRelease>", lambda e: self.deb.call(self.do_search))
        ttk.Button(top, text="Clear", style="Tool.TButton", command=self.clear_search).pack(side=tk.LEFT)

        # Actions
        ttk.Button(top, text="Delete", style="Tool.TButton", command=self.delete).pack(side=tk.RIGHT)
        ttk.Button(top, text="Edit", style="Secondary.TButton", command=self.edit).pack(side=tk.RIGHT, padx=5)
        ttk.Button(top, text="Add Type", style="Primary.TButton", command=self.add).pack(side=tk.RIGHT, padx=5)

        # List
        list_frame = ttk.Frame(self)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0,20))

        cols = ("id", "name", "days", "price")
        self.tree = ttk.Treeview(list_frame, columns=cols, show="headings")
        self.tree.heading("id", text="ID", command=lambda: self.tree_sort_column("id"))
        self.tree.column("id", width=50, anchor=tk.CENTER)
        self.tree.heading("name", text="Name", command=lambda: self.tree_sort_column("name"))
        self.tree.column("name", width=200, anchor=tk.W)
        self.tree.heading("days", text="Duration (Days)", command=lambda: self.tree_sort_column("duration_days"))
        self.tree.column("days", width=100, anchor=tk.CENTER)
        self.tree.heading("price", text="Price", command=lambda: self.tree_sort_column("price"))
        self.tree.column("price", width=100, anchor=tk.E)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        vsb = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscroll=vsb.set)
        
        self.tree.bind("<Double-1>", lambda e: self.edit())

        # Pagination
        pager = ttk.Frame(self); pager.pack(fill=tk.X, padx=20, pady=(0,20))
        self.info_lbl = ttk.Label(pager, text="", style="Muted.TLabel"); self.info_lbl.pack(side=tk.LEFT)
        ttk.Button(pager, text="Next", style="Tool.TButton", command=self.next_page).pack(side=tk.RIGHT)
        ttk.Button(pager, text="Prev", style="Tool.TButton", command=self.prev_page).pack(side=tk.RIGHT, padx=(0,6))

    def refresh(self):
        offset = (self.page - 1) * self.page_size
        for i in self.tree.get_children(): self.tree.delete(i)
        
        with get_db_connection() as conn:
            cur = conn.cursor()
            
            # Base SQL
            sql = "SELECT id, name, duration_days, price FROM membership_types WHERE 1=1"
            params = []
            if self.search_q:
                sql += " AND name LIKE ?"
                params.append(f"%{self.search_q}%")
                
            # Count
            count_sql = f"SELECT COUNT(*) FROM ({sql})"
            cur.execute(count_sql, params); total = cur.fetchone()[0]
            
            # Sort & Limit
            direction = "DESC" if self.sort_desc else "ASC"
            sql += f" ORDER BY {self.sort_col} {direction} LIMIT ? OFFSET ?"
            params.extend([self.page_size, offset])
            
            cur.execute(sql, params)
            for r in cur.fetchall():
                self.tree.insert("", tk.END, values=r)
                
        self.total_pages = (total + self.page_size - 1) // self.page_size or 1
        self.info_lbl.config(text=f"Page {self.page}/{self.total_pages} (Total {total})")

    def do_search(self):
        self.search_q = self.q_ent.get().strip(); self.page = 1; self.refresh()

    def clear_search(self):
        self.q_ent.delete(0, tk.END); self.search_q = ""; self.page = 1; self.refresh()

    def tree_sort_column(self, col):
        if self.sort_col == col: self.sort_desc = not self.sort_desc
        else: self.sort_col = col; self.sort_desc = False
        self.refresh()

    def prev_page(self):
        if self.page > 1: self.page -= 1; self.refresh()
    
    def next_page(self):
        if self.page < self.total_pages: self.page += 1; self.refresh()

    def add(self): MembershipForm(self, None)
    def edit(self):
        sel = self.tree.selection()
        if not sel: return
        mid = self.tree.item(sel[0], "values")[0]
        MembershipForm(self, mid)

    def delete(self):
        sel = self.tree.selection()
        if not sel: return
        if not messagebox.askyesno("Confirm", "Delete selected type?"): return
        mid = self.tree.item(sel[0], "values")[0]
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM membership_types WHERE id=?", (mid,))
            conn.commit()
        self.refresh()

class MembershipForm(tk.Toplevel):
    """
    ฟอร์มเพิ่ม/แก้ไขประเภทสมาชิก
    """
    def __init__(self, parent, mid=None):
        super().__init__(parent); self.parent = parent; self.mid = mid
        self.title("Membership Type Form"); self.geometry("400x300"); self.resizable(False, False)
        self._build_ui(); self._load_data(); self.transient(parent); self.grab_set()

    def _build_ui(self):
        f = ttk.Frame(self, padding=20); f.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(f, text="Name *").grid(row=0, column=0, sticky="w", pady=5)
        self.name_ent = ttk.Entry(f, width=30); self.name_ent.grid(row=1, column=0, sticky="ew")
        
        ttk.Label(f, text="Duration (Days) *").grid(row=2, column=0, sticky="w", pady=5)
        self.days_ent = ttk.Entry(f, width=10); self.days_ent.grid(row=3, column=0, sticky="w")
        
        ttk.Label(f, text="Price").grid(row=4, column=0, sticky="w", pady=5)
        self.price_ent = ttk.Entry(f, width=15); self.price_ent.grid(row=5, column=0, sticky="w")
        
        btns = ttk.Frame(f); btns.grid(row=6, column=0, pady=20, sticky="e")
        ttk.Button(btns, text="Save", style="Primary.TButton", command=self.save).pack(side=tk.LEFT, padx=5)
        ttk.Button(btns, text="Cancel", style="Secondary.TButton", command=self.destroy).pack(side=tk.LEFT)

    def _load_data(self):
        if not self.mid: return
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT name, duration_days, price FROM membership_types WHERE id=?", (self.mid,))
            row = cur.fetchone()
            if row:
                self.name_ent.insert(0, row[0])
                self.days_ent.insert(0, str(row[1]))
                if row[2]: self.price_ent.insert(0, str(row[2]))

    def save(self):
        name = self.name_ent.get().strip()
        days_str = self.days_ent.get().strip()
        price_str = self.price_ent.get().strip()
        
        if not name or not days_str:
            messagebox.showwarning("Required", "Name and Duration are required."); return
        try:
            days = int(days_str)
            price = float(price_str) if price_str else 0.0
        except ValueError:
            messagebox.showerror("Invalid", "Duration must be integer, Price must be number."); return
            
        with get_db_connection() as conn:
            cur = conn.cursor()
            if self.mid:
                cur.execute("UPDATE membership_types SET name=?, duration_days=?, price=? WHERE id=?", (name, days, price, self.mid))
            else:
                cur.execute("INSERT INTO membership_types(name, duration_days, price) VALUES (?,?,?)", (name, days, price))
            conn.commit()
        self.parent.refresh(); self.destroy()

class RoomsDialog(tk.Toplevel):
    """
    หน้าต่างจัดการข้อมูลห้องพัก (Manage Rooms)
    """
    def __init__(self, parent):
        super().__init__(parent); self.parent = parent
        self.title("Manage Rooms"); self.geometry("800x600"); self.resizable(False, False)
        self.page = 1; self.page_size = 15
        self.search_q = ""; self.sort_col = "room_number"; self.sort_desc = False
        self.deb = Debouncer(self, 400)
        self._build_ui(); self.refresh(); self.transient(parent); self.grab_set()

    def _build_ui(self):
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tab 1: Rooms List
        self.tab_list = ttk.Frame(self.tabs)
        self.tabs.add(self.tab_list, text="Rooms List")
        self._build_list_tab(self.tab_list)
        
        # Tab 2: Floor Summary
        self.tab_summary = ttk.Frame(self.tabs)
        self.tabs.add(self.tab_summary, text="Floor Summary")
        self._build_summary_tab(self.tab_summary)

    def _build_list_tab(self, parent):
        # Top Bar
        top = ttk.Frame(parent); top.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(top, text="Search").pack(side=tk.LEFT)
        self.q_ent = ttk.Entry(top, width=20)
        self.q_ent.pack(side=tk.LEFT, padx=(5,5))
        self.q_ent.bind("<KeyRelease>", lambda e: self.deb.call(self.do_search))
        ttk.Button(top, text="Clear", style="Tool.TButton", command=self.clear_search).pack(side=tk.LEFT)
        ttk.Button(top, text="Delete", style="Tool.TButton", command=self.delete).pack(side=tk.RIGHT)
        ttk.Button(top, text="Edit", style="Secondary.TButton", command=self.edit).pack(side=tk.RIGHT, padx=5)
        ttk.Button(top, text="Add Room", style="Primary.TButton", command=self.add).pack(side=tk.RIGHT, padx=5)

        # List
        list_frame = ttk.Frame(parent)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))

        cols = ("id", "room", "building", "floor", "residents")
        self.tree = ttk.Treeview(list_frame, columns=cols, show="headings")
        self.tree.heading("id", text="ID", command=lambda: self.tree_sort_column("id"))
        self.tree.column("id", width=50, anchor=tk.CENTER)
        self.tree.heading("room", text="Room No.", command=lambda: self.tree_sort_column("room_number"))
        self.tree.column("room", width=100, anchor=tk.CENTER)
        self.tree.heading("building", text="Building", command=lambda: self.tree_sort_column("building"))
        self.tree.column("building", width=100, anchor=tk.CENTER)
        self.tree.heading("floor", text="Floor", command=lambda: self.tree_sort_column("floor"))
        self.tree.column("floor", width=80, anchor=tk.CENTER)
        self.tree.heading("residents", text="Residents")
        self.tree.column("residents", width=300, anchor=tk.W)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        vsb = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscroll=vsb.set)
        
        self.tree.bind("<Double-1>", lambda e: self.edit())

        # Pagination
        pager = ttk.Frame(parent); pager.pack(fill=tk.X, padx=10, pady=(0,10))
        self.info_lbl = ttk.Label(pager, text="", style="Muted.TLabel"); self.info_lbl.pack(side=tk.LEFT)
        ttk.Button(pager, text="Next", style="Tool.TButton", command=self.next_page).pack(side=tk.RIGHT)
        ttk.Button(pager, text="Prev", style="Tool.TButton", command=self.prev_page).pack(side=tk.RIGHT, padx=(0,6))

    def _build_summary_tab(self, parent):
        # Summary Table (Columns will be dynamic)
        self.sum_tree = ttk.Treeview(parent, show="headings")
        self.sum_tree.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

    def refresh(self):
        offset = (self.page - 1) * self.page_size
        for i in self.tree.get_children(): self.tree.delete(i)
        
        with get_db_connection() as conn:
            cur = conn.cursor()
            
            # Base SQL
            sql = "SELECT id, room_number, building, floor FROM rooms WHERE 1=1"
            params = []
            if self.search_q:
                sql += " AND room_number LIKE ?"
                params.append(f"%{self.search_q}%")
                
            # Count
            count_sql = f"SELECT COUNT(*) FROM ({sql})"
            cur.execute(count_sql, params); total = cur.fetchone()[0]
            
           
            # Sort & Limit
            direction = "DESC" if self.sort_desc else "ASC"
            sql += f" ORDER BY {self.sort_col} {direction} LIMIT ? OFFSET ?"
            params.extend([self.page_size, offset])
            
            cur.execute(sql, params)
            rows = cur.fetchall()
            
            # Update Summary Tab
            for i in self.sum_tree.get_children(): self.sum_tree.delete(i)
            
            # Calculate stats per floor & building (Matrix View)
            # 1. Get all Buildings
            cur.execute("SELECT DISTINCT building FROM rooms ORDER BY building")
            buildings = [r[0] for r in cur.fetchall()]
            
            # 2. Configure Treeview Columns
            cols = ["floor"] + buildings
            self.sum_tree["columns"] = cols
            self.sum_tree.heading("floor", text="Floor")
            self.sum_tree.column("floor", width=80, anchor=tk.CENTER)
            
            for b in buildings:
                self.sum_tree.heading(b, text=f"Bldg {b}")
                self.sum_tree.column(b, width=80, anchor=tk.CENTER)
            
            # 3. Fetch Data
            # Total rooms per floor & building
            cur.execute("SELECT floor, building, COUNT(*) FROM rooms GROUP BY floor, building")
            total_data = {(r[0], r[1]): r[2] for r in cur.fetchall()}
            
            # Occupied rooms per floor & building
            cur.execute("""
                SELECT r.floor, r.building, COUNT(DISTINCT r.room_number) 
                FROM rooms r
                JOIN residents res ON r.room_number = res.room
                WHERE res.active = 1
                GROUP BY r.floor, r.building
            """)
            occupied_data = {(r[0], r[1]): r[2] for r in cur.fetchall()}
            
            # 4. Populate Matrix
            # Floors 1-8
            for f in range(1, 9):
                row_vals = [f]
                for b in buildings:
                    k = (f, b)
                    total_rooms = total_data.get(k, 0)
                    occupied = occupied_data.get(k, 0)
                    val = f"{occupied}/{total_rooms}" if total_rooms > 0 else "-"
                    row_vals.append(val)
                self.sum_tree.insert("", tk.END, values=row_vals)

            # Fetch residents for each room
            for r in rows:
                rid, rno, bldg, flr = r
                cur.execute("SELECT name FROM residents WHERE room=? AND active=1", (rno,))
                res_names = [x[0] for x in cur.fetchall()]
                res_str = ", ".join(res_names) if res_names else "-"
                self.tree.insert("", tk.END, values=(rid, rno, bldg, flr, res_str))
                
        self.total_pages = (total + self.page_size - 1) // self.page_size or 1
        self.info_lbl.config(text=f"Page {self.page}/{self.total_pages} (Total {total})")

    def do_search(self):
        self.search_q = self.q_ent.get().strip(); self.page = 1; self.refresh()

    def clear_search(self):
        self.q_ent.delete(0, tk.END); self.search_q = ""; self.page = 1; self.refresh()

    def tree_sort_column(self, col):
        if self.sort_col == col: self.sort_desc = not self.sort_desc
        else: self.sort_col = col; self.sort_desc = False
        self.refresh()

    def prev_page(self):
        if self.page > 1: self.page -= 1; self.refresh()
    
    def next_page(self):
        if self.page < self.total_pages: self.page += 1; self.refresh()

    def add(self): RoomForm(self, None)
    def edit(self):
        sel = self.tree.selection()
        if not sel: return
        rid = self.tree.item(sel[0], "values")[0]
        RoomForm(self, rid)

    def delete(self):
        sel = self.tree.selection()
        if not sel: return
        if not messagebox.askyesno("Confirm", "Delete selected room?"): return
        rid = self.tree.item(sel[0], "values")[0]
        rno = self.tree.item(sel[0], "values")[1]
        
        with get_db_connection() as conn:
            cur = conn.cursor()
            # Check if residents exist in this room
            cur.execute("SELECT COUNT(1) FROM residents WHERE room=?", (rno,))
            if cur.fetchone()[0] > 0:
                messagebox.showerror("Error", "Cannot delete: Residents are assigned to this room."); return
            
            cur.execute("DELETE FROM rooms WHERE id=?", (rid,))
            conn.commit()
        self.refresh()

class RoomForm(tk.Toplevel):
    """
    ฟอร์มเพิ่ม/แก้ไขห้องพัก
    """
    def __init__(self, parent, rid=None):
        super().__init__(parent); self.parent = parent; self.rid = rid
        self.title("Room Form"); self.geometry("400x300"); self.resizable(False, False)
        self._build_ui(); self._load_data(); self.transient(parent); self.grab_set()

    def _build_ui(self):
        f = ttk.Frame(self, padding=20); f.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(f, text="Room No. *").grid(row=0, column=0, sticky="w", pady=5)
        self.room_ent = ttk.Entry(f, width=20); self.room_ent.grid(row=1, column=0, sticky="w")
        
        ttk.Label(f, text="Building").grid(row=2, column=0, sticky="w", pady=5)
        self.bldg_ent = ttk.Entry(f, width=20); self.bldg_ent.grid(row=3, column=0, sticky="w")
        
        ttk.Label(f, text="Floor").grid(row=4, column=0, sticky="w", pady=5)
        self.floor_ent = ttk.Entry(f, width=10); self.floor_ent.grid(row=5, column=0, sticky="w")
        
        btns = ttk.Frame(f); btns.grid(row=6, column=0, pady=20, sticky="e")
        ttk.Button(btns, text="Save", style="Primary.TButton", command=self.save).pack(side=tk.LEFT, padx=5)
        ttk.Button(btns, text="Cancel", style="Secondary.TButton", command=self.destroy).pack(side=tk.LEFT)

    def _load_data(self):
        if not self.rid: return
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT room_number, building, floor FROM rooms WHERE id=?", (self.rid,))
            row = cur.fetchone()
            if row:
                self.room_ent.insert(0, row[0])
                if row[1]: self.bldg_ent.insert(0, row[1])
                if row[2]: self.floor_ent.insert(0, str(row[2]))

    def save(self):
        rno = self.room_ent.get().strip()
        bldg = self.bldg_ent.get().strip()
        floor = self.floor_ent.get().strip()
        
        if not rno: messagebox.showwarning("Required", "Room Number is required."); return
        
        # Validate Floor (1-8)
        if not floor.isdigit() or not (1 <= int(floor) <= 8):
            messagebox.showwarning("Invalid Input", "Floor must be between 1 and 8."); return
        
        with get_db_connection() as conn:
            cur = conn.cursor()
            
            # Check uniqueness of Room No
            if self.rid:
                cur.execute("SELECT COUNT(1) FROM rooms WHERE room_number=? AND id!=?", (rno, self.rid))
            else:
                cur.execute("SELECT COUNT(1) FROM rooms WHERE room_number=?", (rno,))
            
            if cur.fetchone()[0] > 0:
                messagebox.showerror("Error", f"Room {rno} already exists."); return

            if self.rid:
                cur.execute("UPDATE rooms SET room_number=?, building=?, floor=? WHERE id=?", (rno, bldg, floor, self.rid))
            else:
                cur.execute("INSERT INTO rooms(room_number, building, floor) VALUES (?,?,?)", (rno, bldg, floor))
            conn.commit()
        self.parent.refresh(); self.destroy()

class ReportsDialog(tk.Toplevel):
    """
    หน้าต่างรายงาน (Reports)
    - Tab 1: Room Usage (การใช้งานรายห้อง)
    - Tab 2: Trainer Performance (ผลงานเทรนเนอร์)
    """
    def __init__(self, parent):
        super().__init__(parent); self.parent = parent
        self.title("Reports"); self.geometry("1000x700"); self.resizable(False, False)
        self.sort_col = "room"; self.sort_desc = False
        self.search_q = ""
        self.data_cache = [] # Store loaded data for filtering/sorting
        self._build_ui(); self.transient(parent); self.grab_set()

    def _build_ui(self):
        tabs = ttk.Notebook(self)
        tabs.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.tab_rooms = ttk.Frame(tabs); tabs.add(self.tab_rooms, text="Room Usage")
        self.tab_trainers = ttk.Frame(tabs); tabs.add(self.tab_trainers, text="Trainer Performance")
        
        self._build_room_report(self.tab_rooms)
        self._build_trainer_report(self.tab_trainers)

    def _build_room_report(self, parent):
        # Toolbar
        tbar = ttk.Frame(parent); tbar.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(tbar, text="Search Room:").pack(side=tk.LEFT)
        self.q_ent = ttk.Entry(tbar, width=15)
        self.q_ent.pack(side=tk.LEFT, padx=5)
        self.q_ent.bind("<KeyRelease>", self._on_search)
        
        ttk.Button(tbar, text="Refresh", style="Tool.TButton", command=self._load_rooms).pack(side=tk.LEFT, padx=10)
        
        self.summary_lbl = ttk.Label(tbar, text="", font=("Segoe UI", 10, "bold"), foreground="#2c3e50")
        self.summary_lbl.pack(side=tk.RIGHT)
        
        # Table
        cols = ("room", "total", "month")
        tree = ttk.Treeview(parent, columns=cols, show="headings")
        
        # Bind sorting
        tree.heading("room", text="Room No.", command=lambda: self._sort_by("room"))
        tree.heading("total", text="Total Check-ins", command=lambda: self._sort_by("total"))
        tree.heading("month", text="This Month", command=lambda: self._sort_by("month"))
        
        tree.column("room", width=100, anchor=tk.CENTER)
        tree.column("total", width=150, anchor=tk.CENTER)
        tree.column("month", width=150, anchor=tk.CENTER)
        
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        
        # Scrollbar
        vsb = ttk.Scrollbar(tree, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.room_tree = tree
        self._load_rooms()

    def _build_trainer_report(self, parent):
        # Toolbar
        tbar = ttk.Frame(parent); tbar.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(tbar, text="Refresh", style="Tool.TButton", command=self._load_trainers).pack(side=tk.LEFT)
        
        # Table
        cols = ("name", "clients", "checkins")
        tree = ttk.Treeview(parent, columns=cols, show="headings")
        tree.heading("name", text="Trainer Name")
        tree.heading("clients", text="Active Clients")
        tree.heading("checkins", text="Client Check-ins (Total)")
        
        tree.column("name", width=200)
        tree.column("clients", width=100, anchor=tk.CENTER)
        tree.column("checkins", width=150, anchor=tk.CENTER)
        
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        self.trainer_tree = tree
        self._load_trainers()

    def _load_rooms(self):
        # Optimized Query
        month_str = datetime.now().strftime("%Y-%m")
        
        with get_db_connection() as conn:
            cur = conn.cursor()
            # Left Join Rooms -> Residents -> Checkins
            # Group by Room to get aggregate counts
            sql = f"""
                SELECT 
                    r.room_number,
                    COUNT(c.id) as total_checkins,
                    SUM(CASE WHEN c.checkin_time LIKE '{month_str}%' THEN 1 ELSE 0 END) as month_checkins
                FROM rooms r
                LEFT JOIN residents res ON r.room_number = res.room
                LEFT JOIN checkins c ON res.id = c.resident_id
                GROUP BY r.room_number
                ORDER BY r.room_number
            """
            cur.execute(sql)
            self.data_cache = cur.fetchall() # List of tuples (room, total, month)
            
        self._update_tree()

    def _update_tree(self):
        # Filter and Sort
        filtered = [row for row in self.data_cache if self.search_q.lower() in row[0].lower()]
        
        # Sort
        # Determine index based on col name
        idx = 0
        if self.sort_col == "total": idx = 1
        elif self.sort_col == "month": idx = 2
        
        filtered.sort(key=lambda x: x[idx], reverse=self.sort_desc)
        
        # Clear and Repopulate
        for i in self.room_tree.get_children(): self.room_tree.delete(i)
        
        total_all = 0
        month_all = 0
        
        for row in filtered:
            self.room_tree.insert("", tk.END, values=row)
            total_all += row[1]
            month_all += row[2]
            
        # Update Summary
        self.summary_lbl.config(text=f"Total Check-ins: {total_all} | This Month: {month_all}")

    def _on_search(self, event):
        self.search_q = self.q_ent.get().strip()
        self._update_tree()

    def _sort_by(self, col):
        if self.sort_col == col:
            self.sort_desc = not self.sort_desc
        else:
            self.sort_col = col
            self.sort_desc = True # Default to Descending for numbers usually
            if col == "room": self.sort_desc = False # Ascending for room numbers
            
        self._update_tree()

    def _load_trainers(self):
        for i in self.trainer_tree.get_children(): self.trainer_tree.delete(i)
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, name FROM trainers ORDER BY name")
            trainers = cur.fetchall()
            
            for tid, name in trainers:
                # Active Clients
                cur.execute("SELECT COUNT(*) FROM residents WHERE trainer_id=? AND active=1", (tid,))
                clients = cur.fetchone()[0]
                
                # Client Check-ins (Total)
                cur.execute("""
                    SELECT COUNT(c.id) 
                    FROM checkins c
                    JOIN residents r ON c.resident_id = r.id
                    WHERE r.trainer_id = ?
                """, (tid,))
                checkins = cur.fetchone()[0]
                
                self.trainer_tree.insert("", tk.END, values=(name, clients, checkins))

class Dashboard(tk.Toplevel):
    """
    หน้าจอ Dashboard (Business Intelligence)
    - แสดงภาพรวมข้อมูลในรูปแบบกราฟและตัวเลข
    - คำนวณสถิติจาก Database เช่น ยอดเข้าใช้งานวันนี้, แนวโน้ม 7 วันย้อนหลัง
    """
    def __init__(self, parent):
        super().__init__(parent); self.parent = parent
        self.title("Dashboard"); self.geometry("800x600"); self.resizable(False, False)
        self._build_ui(); self.transient(parent); self.grab_set()

    def _build_ui(self):
        # 1. Summary Cards
        cards_frame = ttk.Frame(self, padding=20)
        cards_frame.pack(fill=tk.X)
        
        stats = self._get_stats()
        
        self._create_card(cards_frame, "Total Residents", stats["total"], 0)
        self._create_card(cards_frame, "Active Residents", stats["active"], 1)
        self._create_card(cards_frame, "Check-ins Today", stats["today"], 2)
        self._create_card(cards_frame, "Check-ins This Month", stats["month"], 3)

        # 2. BI Chart (Canvas) - Last 7 Days Trend
        chart_frame = ttk.Frame(self, padding=20)
        chart_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(chart_frame, text="Check-ins Trend (Last 7 Days)", font=("Segoe UI Semibold", 12)).pack(anchor="w", pady=(0,10))
        
        self.canvas = tk.Canvas(chart_frame, bg="white", height=300)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        
        self._draw_chart(stats["trend"])

    def _create_card(self, parent, title, value, col):
        f = ttk.Frame(parent, borderwidth=1, relief="solid", padding=15)
        f.grid(row=0, column=col, padx=10, sticky="ew")
        parent.columnconfigure(col, weight=1)
        
        ttk.Label(f, text=title, style="Muted.TLabel").pack(anchor="w")
        ttk.Label(f, text=str(value), font=("Segoe UI", 24, "bold"), foreground=self.parent.palette["ACCENT"]).pack(anchor="w")

    def _get_stats(self):
        with get_db_connection() as conn:
            cur = conn.cursor()
            total = cur.execute("SELECT COUNT(*) FROM residents WHERE deleted_at IS NULL").fetchone()[0]
            active = cur.execute("SELECT COUNT(*) FROM residents WHERE active=1 AND deleted_at IS NULL").fetchone()[0]
            
            today_str = datetime.now().strftime("%Y-%m-%d")
            month_str = datetime.now().strftime("%Y-%m")
            
            today_cnt = cur.execute("SELECT COUNT(*) FROM checkins WHERE checkin_time LIKE ?", (f"{today_str}%",)).fetchone()[0]
            month_cnt = cur.execute("SELECT COUNT(*) FROM checkins WHERE checkin_time LIKE ?", (f"{month_str}%",)).fetchone()[0]
            
            # Trend Data (Last 7 Days)
            trend = []
            for i in range(6, -1, -1):
                d = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
                c = cur.execute("SELECT COUNT(*) FROM checkins WHERE checkin_time LIKE ?", (f"{d}%",)).fetchone()[0]
                trend.append((d, c))
                
            return {"total": total, "active": active, "today": today_cnt, "month": month_cnt, "trend": trend}

    def _draw_chart(self, data):
        """วาดกราฟแท่งด้วย Canvas"""
        w = 720; h = 250
        x_start = 50; y_start = 220
        bar_w = 60; gap = 30
        
        # Find max value for scaling
        max_val = max([d[1] for d in data]) if data else 1
        scale = 180 / max_val if max_val > 0 else 1
        
        # Draw Axes
        self.canvas.create_line(x_start, y_start, x_start + (bar_w+gap)*7 + 20, y_start, width=2) # X-axis
        self.canvas.create_line(x_start, y_start, x_start, 20, width=2) # Y-axis
        
        for i, (date_str, count) in enumerate(data):
            x = x_start + 20 + i * (bar_w + gap)
            bar_h = count * scale
            y = y_start - bar_h
            
            # Bar (Blue)
            self.canvas.create_rectangle(x, y, x + bar_w, y_start, fill="#007bff", outline="")
            
            # Value Label (Top of bar)
            self.canvas.create_text(x + bar_w/2, y - 10, text=str(count), font=("Segoe UI", 10, "bold"))
            
            # Date Label (X-axis) - Show only Day/Month (e.g., 29/11)
            d_lbl = date_str.split("-")[2] + "/" + date_str.split("-")[1]
            self.canvas.create_text(x + bar_w/2, y_start + 15, text=d_lbl, font=("Segoe UI", 9))

class HistoryDialog(tk.Toplevel):
    """
    หน้าต่างดูประวัติการแก้ไขสัญญา (Contract History)
    """
    def __init__(self, parent, resident_id):
        super().__init__(parent)
        self.title("Contract History"); self.geometry("700x400")
        self.rid = resident_id
        self._build_ui(); self.transient(parent)

    def _build_ui(self):
        cols = ("time", "action", "old_days", "new_days", "old_start", "new_start")
        tree = ttk.Treeview(self, columns=cols, show="headings")
        tree.heading("time", text="Time")
        tree.heading("action", text="Action")
        tree.heading("old_days", text="Old Days")
        tree.heading("new_days", text="New Days")
        tree.heading("old_start", text="Old Start")
        tree.heading("new_start", text="New Start")
        
        tree.column("time", width=140); tree.column("action", width=80)
        tree.column("old_days", width=70); tree.column("new_days", width=70)
        tree.column("old_start", width=90); tree.column("new_start", width=90)
        
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("""SELECT logged_at, action, old_days, new_days, old_start, new_start 
                           FROM contract_logs WHERE resident_id=? ORDER BY logged_at DESC""", (self.rid,))
            for r in cur.fetchall():
                tree.insert("", tk.END, values=r)

if __name__ == "__main__":
    init_db()
    app = App()
    app.mainloop()
