"""
How to run:
1) `python app.py`
2) First run auto-creates `fitness.sqlite` with sample data.
   Login with: username `admin`, password `admin123`
"""

import os
import sqlite3
import hashlib
import secrets
import calendar as pycal
from datetime import datetime, timedelta, date
import tkinter as tk
from tkinter import ttk, messagebox

DB_PATH = os.path.join(os.path.dirname(__file__), "fitness.sqlite")
PAGE_SIZE = 50

# -------------------------
# Database 
# -------------------------

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    # Sequences table for running numbers
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS sequences (
            name TEXT PRIMARY KEY,
            last_value INTEGER NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS trainers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS residents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            resident_no INTEGER UNIQUE NOT NULL,
            name TEXT NOT NULL,
            room TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            trainer_id INTEGER,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            deleted_at TEXT,
            FOREIGN KEY (trainer_id) REFERENCES trainers(id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS checkins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            resident_id INTEGER NOT NULL,
            checkin_time TEXT NOT NULL,
            FOREIGN KEY (resident_id) REFERENCES residents(id)
        )
        """
    )

    # Helpful indexes for speed
    cur.execute("CREATE INDEX IF NOT EXISTS idx_residents_name ON residents(name)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_residents_room ON residents(room)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_residents_trainer ON residents(trainer_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_residents_resno ON residents(resident_no)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_residents_deleted ON residents(deleted_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_checkins_resident ON checkins(resident_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_checkins_time ON checkins(checkin_time)")

    # Seed admin user if none
    cur.execute("SELECT COUNT(1) FROM users")
    if cur.fetchone()[0] == 0:
        create_user(cur, "admin", "admin123")

    # Seed trainers if none
    cur.execute("SELECT COUNT(1) FROM trainers")
    if cur.fetchone()[0] == 0:
        trainers = [("Coach Bank", "081-234-5678"), ("Coach May", "089-111-2222")]
        cur.executemany("INSERT INTO trainers(name, phone) VALUES (?, ?)", trainers)

    # Seed residents (demo) if none
    cur.execute("SELECT COUNT(1) FROM residents")
    if cur.fetchone()[0] == 0:
        # ensure sequence exists
        ensure_sequence(cur, "resident_no")
        residents = [
            ("Somchai Prasert", "A101", 1, 1),
            ("Suda Wong", "A102", 1, 1),
            ("Anan Chai", "B205", 1, 2),
            ("Nicha R.", "C303", 1, None),
            ("Kittisak T.", "C501", 1, 2),
        ]
        for name, room, active, trainer_id in residents:
            rn = next_sequence(cur, "resident_no")
            cur.execute(
                "INSERT INTO residents(resident_no, name, room, active, trainer_id) VALUES (?,?,?,?,?)",
                (rn, name, room, active, trainer_id),
            )
        # add example check-ins for last 3 days
        cur.execute("SELECT id FROM residents")
        r_ids = [r[0] for r in cur.fetchall()]
        now = datetime.now()
        rows = []
        for rid in r_ids:
            for d in range(3):
                t = (now - timedelta(days=d, hours=rid % 5, minutes=rid % 13)).strftime("%Y-%m-%d %H:%M:%S")
                rows.append((rid, t))
        cur.executemany("INSERT INTO checkins(resident_id, checkin_time) VALUES (?, ?)", rows)

    conn.commit()
    conn.close()


def ensure_sequence(cur: sqlite3.Cursor, name: str):
    cur.execute("INSERT OR IGNORE INTO sequences(name, last_value) VALUES (?, 0)", (name,))


def next_sequence(cur: sqlite3.Cursor, name: str) -> int:
    ensure_sequence(cur, name)
    cur.execute("UPDATE sequences SET last_value = last_value + 1 WHERE name = ?", (name,))
    cur.execute("SELECT last_value FROM sequences WHERE name = ?", (name,))
    return cur.fetchone()[0]


def hash_password(password: str, salt: str) -> str:
    import hashlib
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def create_user(cur: sqlite3.Cursor, username: str, password: str):
    salt = secrets.token_hex(16)
    cur.execute(
        "INSERT INTO users(username, password_hash, salt) VALUES (?, ?, ?)",
        (username, hash_password(password, salt), salt),
    )


def verify_user(username: str, password: str) -> bool:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return False
    ph, salt = row
    return ph == hash_password(password, salt)


# -------------------------
# GUI
# -------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Fitness Check-ins | Condo Admin")
        self.geometry("1120x680")
        self.minsize(1000, 620)
        self.style = ttk.Style(self)
        if "vista" in self.style.theme_names():
            self.style.theme_use("vista")
        self._frames = {}

        container = ttk.Frame(self)
        container.pack(fill=tk.BOTH, expand=True)

        for F in (LoginFrame, LandingFrame):
            frame = F(parent=container, controller=self)
            self._frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)
        self.show_frame("LoginFrame")

    def show_frame(self, name: str):
        frame = self._frames[name]
        frame.tkraise()
        if hasattr(frame, "on_show"):
            frame.on_show()


class LoginFrame(ttk.Frame):
    def __init__(self, parent, controller: App):
        super().__init__(parent)
        self.controller = controller

        # Center container
        wrapper = ttk.Frame(self)
        wrapper.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        title = ttk.Label(wrapper, text="Condo Fitness | Admin Login", font=("Segoe UI", 18, "bold"))
        subtitle = ttk.Label(wrapper, text="Sign in to manage resident check-ins")
        user_lbl = ttk.Label(wrapper, text="Username")
        self.user_ent = ttk.Entry(wrapper, width=28)
        pass_lbl = ttk.Label(wrapper, text="Password")
        self.pass_ent = ttk.Entry(wrapper, show="*", width=28)
        self.pass_ent.bind("<Return>", lambda e: self._login())

        login_btn = ttk.Button(wrapper, text="Sign in", command=self._login)

        title.grid(row=0, column=0, columnspan=2, pady=(0, 2), sticky="w")
        subtitle.grid(row=1, column=0, columnspan=2, pady=(0, 14), sticky="w")
        user_lbl.grid(row=2, column=0, sticky="w")
        self.user_ent.grid(row=3, column=0, columnspan=2, pady=(0, 10))
        pass_lbl.grid(row=4, column=0, sticky="w")
        self.pass_ent.grid(row=5, column=0, columnspan=2, pady=(0, 12))
        login_btn.grid(row=6, column=0, columnspan=2, sticky="ew")

        self.user_ent.focus_set()

    def _login(self):
        u = self.user_ent.get().strip()
        p = self.pass_ent.get()
        if not u or not p:
            messagebox.showwarning("Required", "Please enter username and password")
            return
        if verify_user(u, p):
            self.controller.show_frame("LandingFrame")
            self.user_ent.delete(0, tk.END)
            self.pass_ent.delete(0, tk.END)
        else:
            messagebox.showerror("Invalid", "Incorrect username or password")


class LandingFrame(ttk.Frame):
    def __init__(self, parent, controller: App):
        super().__init__(parent)
        self.controller = controller
        self._build_ui()

    def _build_ui(self):
        topbar = ttk.Frame(self)
        topbar.pack(fill=tk.X, padx=12, pady=8)

        title = ttk.Label(topbar, text="Fitness Check-ins", font=("Segoe UI", 16, "bold"))
        title.pack(side=tk.LEFT)

        logout_btn = ttk.Button(topbar, text="Log out", command=lambda: self.controller.show_frame("LoginFrame"))
        logout_btn.pack(side=tk.RIGHT, padx=(0, 8))

        manage_tr_btn = ttk.Button(topbar, text="Manage Trainers", command=self.open_trainers)
        manage_tr_btn.pack(side=tk.RIGHT, padx=(0, 8))

        manage_btn = ttk.Button(topbar, text="Manage Residents", command=self.open_residents)
        manage_btn.pack(side=tk.RIGHT, padx=(0, 8))

        # Filters
        filt = ttk.Frame(topbar)
        filt.pack(side=tk.RIGHT)

        ttk.Label(filt, text="Trainer").grid(row=0, column=0, padx=(0,4))
        self.trainer_var = tk.StringVar()
        self.trainer_cb = ttk.Combobox(filt, textvariable=self.trainer_var, state="readonly", width=18)
        self.trainer_cb.grid(row=0, column=1)
        self._load_trainer_filter()

        ttk.Label(filt, text="From").grid(row=0, column=2, padx=(8,4))
        self.from_ent = ttk.Entry(filt, width=12)
        self.from_ent.grid(row=0, column=3)
        ttk.Button(filt, text="📅", width=3, command=lambda: self.pick_date(self.from_ent)).grid(row=0, column=4)

        ttk.Label(filt, text="To").grid(row=0, column=5, padx=(8,4))
        self.to_ent = ttk.Entry(filt, width=12)
        self.to_ent.grid(row=0, column=6)
        ttk.Button(filt, text="📅", width=3, command=lambda: self.pick_date(self.to_ent)).grid(row=0, column=7)

        ttk.Label(filt, text="Search").grid(row=0, column=8, padx=(8,4))
        self.search_ent = ttk.Entry(filt, width=18)
        self.search_ent.grid(row=0, column=9)

        refresh_btn = ttk.Button(filt, text="Refresh", command=self.refresh)
        refresh_btn.grid(row=0, column=10, padx=(8,0))

        add_btn = ttk.Button(filt, text="Add check-in", command=self.add_checkin_dialog)
        add_btn.grid(row=0, column=11, padx=(8,0))

        # Table
        table_frame = ttk.Frame(self)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0,12))

        columns = ("time", "resno", "name", "room", "trainer")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        self.tree.heading("time", text="Check-in Time")
        self.tree.heading("resno", text="No")
        self.tree.heading("name", text="Resident")
        self.tree.heading("room", text="Room")
        self.tree.heading("trainer", text="Trainer")
        self.tree.column("time", width=200, anchor=tk.W)
        self.tree.column("resno", width=60, anchor=tk.CENTER)
        self.tree.column("name", width=240, anchor=tk.W)
        self.tree.column("room", width=80, anchor=tk.CENTER)
        self.tree.column("trainer", width=160, anchor=tk.W)

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        # Status bar
        self.status = ttk.Label(self, text="", anchor=tk.W)
        self.status.pack(fill=tk.X, padx=12, pady=(0,10))

    def _load_trainer_filter(self):
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, name FROM trainers ORDER BY name")
        items = ["All trainers"] + [f"{i}:{n}" for i,n in cur.fetchall()]
        conn.close()
        self.trainer_cb["values"] = items
        self.trainer_cb.set("All trainers")

    def on_show(self):
        self.refresh()

    # ---- Date logic
    def _parse_dates(self):
        dfrom = self.from_ent.get().strip()
        dto = self.to_ent.get().strip()
        start, end = None, None
        try:
            if dfrom:
                start = datetime.strptime(dfrom, "%Y-%m-%d")
            if dto:
                end = datetime.strptime(dto, "%Y-%m-%d") + timedelta(days=1)
        except ValueError:
            messagebox.showerror("Invalid date", "Use format YYYY-MM-DD for From/To or leave empty")
            return None, None
        return start, end

    def refresh(self):
        start, end = self._parse_dates()
        q = self.search_ent.get().strip()
        trainer_val = self.trainer_var.get()
        trainer_id = None
        if trainer_val and trainer_val != "All trainers":
            trainer_id = int(trainer_val.split(":",1)[0])

        conn = get_conn()
        cur = conn.cursor()

        base_sql = (
            """
            SELECT c.checkin_time, r.resident_no, r.name, r.room, COALESCE(t.name, '') AS trainer
            FROM checkins c
            JOIN residents r ON r.id = c.resident_id
            LEFT JOIN trainers t ON t.id = r.trainer_id
            WHERE r.deleted_at IS NULL
            {time_clause}
            {trainer_clause}
            {search_clause}
            ORDER BY c.checkin_time DESC
            """
        )
        params = []

        # time clause
        time_clause = ""
        if start and end:
            time_clause = "AND c.checkin_time >= ? AND c.checkin_time < ?"
            params += [start.strftime("%Y-%m-%d %H:%M:%S"), end.strftime("%Y-%m-%d %H:%M:%S")]
        elif start and not end:
            time_clause = "AND c.checkin_time >= ? AND c.checkin_time < ?"
            now_plus = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
            params += [start.strftime("%Y-%m-%d %H:%M:%S"), now_plus]
        elif end and not start:
            time_clause = "AND c.checkin_time < ?"
            params += [end.strftime("%Y-%m-%d %H:%M:%S")]

        trainer_clause = ""
        if trainer_id is not None:
            trainer_clause = "AND r.trainer_id = ?"
            params.append(trainer_id)

        search_clause = ""
        if q:
            search_clause = "AND (r.name LIKE ? OR r.room LIKE ? OR t.name LIKE ?)"
            like = f"%{q}%"
            params += [like, like, like]

        sql = base_sql.format(time_clause=time_clause, trainer_clause=trainer_clause, search_clause=search_clause)
        cur.execute(sql, params)
        rows = cur.fetchall()
        conn.close()

        for i in self.tree.get_children():
            self.tree.delete(i)
        for t, resno, n, room, trainer in rows:
            self.tree.insert("", tk.END, values=(t, f"{resno:04d}", n, room, trainer))
        self.status.config(text=f"{len(rows)} records")

    def pick_date(self, target_entry: ttk.Entry):
        DatePicker(self, target_entry)

    def add_checkin_dialog(self):
        # pick from active, non-deleted
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, resident_no, name, room FROM residents WHERE active = 1 AND deleted_at IS NULL ORDER BY resident_no"
        )
        residents = cur.fetchall()
        conn.close()
        if not residents:
            messagebox.showinfo("No residents", "Please add residents in the database first (using Manage Residents).")
            return

        dlg = tk.Toplevel(self)
        dlg.title("Add check-in")
        dlg.transient(self)
        dlg.grab_set()
        dlg.geometry("520x240")

        ttk.Label(dlg, text="Select resident:").pack(anchor="w", padx=12, pady=(12,4))
        cb_var = tk.StringVar()
        cb = ttk.Combobox(dlg, textvariable=cb_var, state="readonly", width=60)
        cb_items = [f"{rid}:{resno:04d} - {name} ({room})" for rid, resno, name, room in residents]
        cb["values"] = cb_items
        cb.current(0)
        cb.pack(fill=tk.X, padx=12)

        def do_add():
            sel = cb_var.get()
            if not sel:
                return
            rid = int(sel.split(":", 1)[0])
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("INSERT INTO checkins(resident_id, checkin_time) VALUES (?, ?)", (rid, now))
            conn.commit()
            conn.close()
            self.refresh()
            messagebox.showinfo("Added", "Check-in recorded.")
            dlg.destroy()

        btns = ttk.Frame(dlg)
        btns.pack(fill=tk.X, padx=12, pady=12)
        ttk.Button(btns, text="Save", command=do_add).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Cancel", command=dlg.destroy).pack(side=tk.RIGHT, padx=(0,8))

    def open_residents(self):
        ResidentsDialog(self)

    def open_trainers(self):
        TrainersDialog(self)


class DatePicker(tk.Toplevel):
    """Lightweight calendar picker (no external packages)."""
    def __init__(self, parent, target_entry: ttk.Entry):
        super().__init__(parent)
        self.title("Pick a date")
        self.resizable(False, False)
        self.target = target_entry
        self.today = date.today()
        self.year = self.today.year
        self.month = self.today.month
        self._build_ui()
        self.transient(parent)
        self.grab_set()

    def _build_ui(self):
        ctrl = ttk.Frame(self)
        ctrl.pack(fill=tk.X, padx=8, pady=8)
        self.lbl = ttk.Label(ctrl, text=f"{pycal.month_name[self.month]} {self.year}")
        self.lbl.pack(side=tk.LEFT)
        ttk.Button(ctrl, text="◀", width=3, command=self.prev_month).pack(side=tk.RIGHT)
        ttk.Button(ctrl, text="▶", width=3, command=self.next_month).pack(side=tk.RIGHT)

        self.grid_frame = ttk.Frame(self)
        self.grid_frame.pack(padx=8, pady=(0,8))
        self._render_month()

    def _render_month(self):
        for w in self.grid_frame.winfo_children():
            w.destroy()
        for i, wd in enumerate(["Mo","Tu","We","Th","Fr","Sa","Su"]):
            ttk.Label(self.grid_frame, text=wd, width=3, anchor="center").grid(row=0, column=i)
        cal = pycal.Calendar(firstweekday=0)
        row = 1
        for week in cal.monthdayscalendar(self.year, self.month):
            for col, day in enumerate(week):
                if day == 0:
                    ttk.Label(self.grid_frame, text=" ", width=3).grid(row=row, column=col)
                else:
                    b = ttk.Button(self.grid_frame, text=str(day), width=3, command=lambda d=day: self.pick(d))
                    b.grid(row=row, column=col)
            row += 1

    def prev_month(self):
        if self.month == 1:
            self.month = 12
            self.year -= 1
        else:
            self.month -= 1
        self.lbl.config(text=f"{pycal.month_name[self.month]} {self.year}")
        self._render_month()

    def next_month(self):
        if self.month == 12:
            self.month = 1
            self.year += 1
        else:
            self.month += 1
        self.lbl.config(text=f"{pycal.month_name[self.month]} {self.year}")
        self._render_month()

    def pick(self, day):
        d = date(self.year, self.month, day)
        self.target.delete(0, tk.END)
        self.target.insert(0, d.strftime("%Y-%m-%d"))
        self.destroy()


class ResidentsDialog(tk.Toplevel):
    def __init__(self, parent: LandingFrame):
        super().__init__(parent)
        self.parent = parent
        self.title("Manage Residents")
        self.geometry("820x600")
        self.resizable(True, True)
        self.page = 1
        self.search_q = ""
        self._build_ui()
        self.refresh()
        self.transient(parent)
        self.grab_set()

    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=12, pady=8)

        ttk.Label(top, text="Search").pack(side=tk.LEFT)
        self.q_ent = ttk.Entry(top, width=28)
        self.q_ent.pack(side=tk.LEFT, padx=(6,8))
        ttk.Button(top, text="Find", command=self.do_search).pack(side=tk.LEFT)
        ttk.Button(top, text="Clear", command=self.clear_search).pack(side=tk.LEFT, padx=(6,0))

        ttk.Button(top, text="Add", command=self.add_resident).pack(side=tk.RIGHT)
        ttk.Button(top, text="Edit", command=self.edit_resident).pack(side=tk.RIGHT, padx=(0,6))
        ttk.Button(top, text="Soft Delete", command=self.soft_delete_resident).pack(side=tk.RIGHT, padx=(0,6))

        frame = ttk.Frame(self)
        frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0,12))

        cols = ("id", "resno", "name", "room", "trainer", "active", "deleted")
        self.tree = ttk.Treeview(frame, columns=cols, show="headings")
        headers = [("id",60),("resno",70),("name",240),("room",90),("trainer",180),("active",70),("deleted",100)]
        for c,w in headers:
            self.tree.heading(c, text=c.capitalize())
            anchor = tk.CENTER if c in ("id","resno","active","deleted") else tk.W
            self.tree.column(c, width=w, anchor=anchor)

        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        # pager
        pager = ttk.Frame(self)
        pager.pack(fill=tk.X, padx=12, pady=(0,12))
        self.info_lbl = ttk.Label(pager, text="")
        self.info_lbl.pack(side=tk.LEFT)
        ttk.Button(pager, text="Prev", command=self.prev_page).pack(side=tk.RIGHT)
        ttk.Button(pager, text="Next", command=self.next_page).pack(side=tk.RIGHT, padx=(0,6))

    def do_search(self):
        self.search_q = self.q_ent.get().strip()
        self.page = 1
        self.refresh()

    def clear_search(self):
        self.q_ent.delete(0, tk.END)
        self.search_q = ""
        self.page = 1
        self.refresh()

    def _count_total(self):
        conn = get_conn()
        cur = conn.cursor()
        if self.search_q:
            like = f"%{self.search_q}%"
            cur.execute(
                "SELECT COUNT(*) FROM residents r LEFT JOIN trainers t ON t.id=r.trainer_id WHERE (r.name LIKE ? OR r.room LIKE ? OR t.name LIKE ?)",
                (like, like, like),
            )
        else:
            cur.execute("SELECT COUNT(*) FROM residents")
        total = cur.fetchone()[0]
        conn.close()
        return total

    def refresh(self):
        total = self._count_total()
        offset = (self.page - 1) * PAGE_SIZE
        conn = get_conn()
        cur = conn.cursor()
        if self.search_q:
            like = f"%{self.search_q}%"
            cur.execute(
                """
                SELECT r.id, r.resident_no, r.name, r.room, COALESCE(t.name,''), r.active, r.deleted_at
                FROM residents r
                LEFT JOIN trainers t ON t.id = r.trainer_id
                WHERE (r.name LIKE ? OR r.room LIKE ? OR t.name LIKE ?)
                ORDER BY r.deleted_at IS NULL DESC, r.resident_no
                LIMIT ? OFFSET ?
                """,
                (like, like, like, PAGE_SIZE, offset),
            )
        else:
            cur.execute(
                """
                SELECT r.id, r.resident_no, r.name, r.room, COALESCE(t.name,''), r.active, r.deleted_at
                FROM residents r
                LEFT JOIN trainers t ON t.id = r.trainer_id
                ORDER BY r.deleted_at IS NULL DESC, r.resident_no
                LIMIT ? OFFSET ?
                """,
                (PAGE_SIZE, offset),
            )
        rows = cur.fetchall()
        conn.close()

        for i in self.tree.get_children():
            self.tree.delete(i)
        for r in rows:
            rid, resno, name, room, trainer, active, deleted_at = r
            self.tree.insert("", tk.END, values=(rid, f"{resno:04d}", name, room, trainer, "Yes" if active else "No", "-" if not deleted_at else deleted_at))

        max_page = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        self.info_lbl.config(text=f"Total {total} | Page {self.page}/{max_page} | {len(rows)} shown")

    def next_page(self):
        total = self._count_total()
        max_page = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        if self.page < max_page:
            self.page += 1
            self.refresh()

    def prev_page(self):
        if self.page > 1:
            self.page -= 1
            self.refresh()

    def _selected_id(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select", "Please select a resident.")
            return None
        vals = self.tree.item(sel[0], "values")
        return int(vals[0])

    def add_resident(self):
        ResidentForm(self, title="Add Resident", on_save=self._insert)

    def edit_resident(self):
        rid = self._selected_id()
        if not rid:
            return
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT resident_no, name, room, active, trainer_id FROM residents WHERE id = ?", (rid,))
        row = cur.fetchone()
        conn.close()
        if not row:
            messagebox.showerror("Not found", "Resident no longer exists")
            return
        resno, name, room, active, trainer_id = row
        ResidentForm(self, title="Edit Resident", initial={"id": rid, "resident_no": resno, "name": name, "room": room, "active": bool(active), "trainer_id": trainer_id}, on_save=self._update)

    def soft_delete_resident(self):
        rid = self._selected_id()
        if not rid:
            return
        if not messagebox.askyesno("Confirm", "Soft delete this resident? (keeps history, hides from active lists)"):
            return
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("UPDATE residents SET active = 0, deleted_at = datetime('now') WHERE id = ?", (rid,))
        conn.commit()
        conn.close()
        self.refresh()

    # callbacks
    def _insert(self, data):
        conn = get_conn()
        cur = conn.cursor()
        rn = next_sequence(cur, "resident_no")
        cur.execute(
            "INSERT INTO residents(resident_no, name, room, active, trainer_id) VALUES (?, ?, ?, ?, ?)",
            (rn, data["name"], data["room"], 1 if data.get("active", True) else 0, data.get("trainer_id")),
        )
        conn.commit()
        conn.close()
        self.refresh()

    def _update(self, data):
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE residents SET name = ?, room = ?, active = ?, trainer_id = ? WHERE id = ?",
            (data["name"], data["room"], 1 if data.get("active", True) else 0, data.get("trainer_id"), data["id"]),
        )
        conn.commit()
        conn.close()
        self.refresh()


class TrainersDialog(tk.Toplevel):
    def __init__(self, parent: LandingFrame):
        super().__init__(parent)
        self.parent = parent
        self.title("Manage Trainers")
        self.geometry("560x420")
        self.page = 1
        self.search_q = ""
        self._build_ui()
        self.refresh()
        self.transient(parent)
        self.grab_set()

    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=12, pady=8)
        ttk.Label(top, text="Search").pack(side=tk.LEFT)
        self.q_ent = ttk.Entry(top, width=28)
        self.q_ent.pack(side=tk.LEFT, padx=(6,8))
        ttk.Button(top, text="Find", command=self.do_search).pack(side=tk.LEFT)
        ttk.Button(top, text="Clear", command=self.clear_search).pack(side=tk.LEFT, padx=(6,0))
        ttk.Button(top, text="Add", command=self.add_trainer).pack(side=tk.RIGHT)
        ttk.Button(top, text="Edit", command=self.edit_trainer).pack(side=tk.RIGHT, padx=(0,6))
        ttk.Button(top, text="Delete", command=self.delete_trainer).pack(side=tk.RIGHT, padx=(0,6))

        frame = ttk.Frame(self)
        frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0,12))
        cols = ("id","name","phone")
        self.tree = ttk.Treeview(frame, columns=cols, show="headings")
        for c,w in [("id",60),("name",260),("phone",160)]:
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w, anchor=tk.W if c!="id" else tk.CENTER)
        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        pager = ttk.Frame(self)
        pager.pack(fill=tk.X, padx=12, pady=(0,12))
        self.info_lbl = ttk.Label(pager, text="")
        self.info_lbl.pack(side=tk.LEFT)
        ttk.Button(pager, text="Prev", command=self.prev_page).pack(side=tk.RIGHT)
        ttk.Button(pager, text="Next", command=self.next_page).pack(side=tk.RIGHT, padx=(0,6))

    def do_search(self):
        self.search_q = self.q_ent.get().strip()
        self.page = 1
        self.refresh()

    def clear_search(self):
        self.q_ent.delete(0, tk.END)
        self.search_q = ""
        self.page = 1
        self.refresh()

    def _count_total(self):
        conn = get_conn()
        cur = conn.cursor()
        if self.search_q:
            like = f"%{self.search_q}%"
            cur.execute("SELECT COUNT(*) FROM trainers WHERE name LIKE ? OR phone LIKE ?", (like, like))
        else:
            cur.execute("SELECT COUNT(*) FROM trainers")
        total = cur.fetchone()[0]
        conn.close()
        return total

    def refresh(self):
        total = self._count_total()
        offset = (self.page - 1) * PAGE_SIZE
        conn = get_conn()
        cur = conn.cursor()
        if self.search_q:
            like = f"%{self.search_q}%"
            cur.execute(
                "SELECT id, name, phone FROM trainers WHERE name LIKE ? OR phone LIKE ? ORDER BY name LIMIT ? OFFSET ?",
                (like, like, PAGE_SIZE, offset),
            )
        else:
            cur.execute(
                "SELECT id, name, phone FROM trainers ORDER BY name LIMIT ? OFFSET ?",
                (PAGE_SIZE, offset),
            )
        rows = cur.fetchall()
        conn.close()

        for i in self.tree.get_children():
            self.tree.delete(i)
        for r in rows:
            self.tree.insert("", tk.END, values=r)

        max_page = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        self.info_lbl.config(text=f"Total {total} | Page {self.page}/{max_page} | {len(rows)} shown")

    def next_page(self):
        total = self._count_total()
        max_page = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        if self.page < max_page:
            self.page += 1
            self.refresh()

    def prev_page(self):
        if self.page > 1:
            self.page -= 1
            self.refresh()

    def _selected_id(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select", "Please select a trainer.")
            return None
        vals = self.tree.item(sel[0], "values")
        return int(vals[0])

    def add_trainer(self):
        TrainerForm(self, title="Add Trainer", on_save=self._insert)

    def edit_trainer(self):
        tid = self._selected_id()
        if not tid:
            return
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT name, phone FROM trainers WHERE id = ?", (tid,))
        row = cur.fetchone()
        conn.close()
        if not row:
            messagebox.showerror("Not found", "Trainer no longer exists")
            return
        name, phone = row
        TrainerForm(self, title="Edit Trainer", initial={"id": tid, "name": name, "phone": phone}, on_save=self._update)

    def delete_trainer(self):
        tid = self._selected_id()
        if not tid:
            return
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM residents WHERE trainer_id = ? AND deleted_at IS NULL", (tid,))
        used = cur.fetchone()[0]
        if used:
            messagebox.showwarning("In use", "Some residents are linked to this trainer. Please unlink or soft delete residents before deleting trainer.")
            conn.close()
            return
        cur.execute("DELETE FROM trainers WHERE id = ?", (tid,))
        conn.commit()
        conn.close()
        self.refresh()

    # callbacks
    def _insert(self, data):
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("INSERT INTO trainers(name, phone) VALUES (?, ?)", (data["name"], data.get("phone")))
        conn.commit()
        conn.close()
        self.refresh()

    def _update(self, data):
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("UPDATE trainers SET name = ?, phone = ? WHERE id = ?", (data["name"], data.get("phone"), data["id"]))
        conn.commit()
        conn.close()
        self.refresh()


class ResidentForm(tk.Toplevel):
    def __init__(self, parent: ResidentsDialog, title: str, on_save, initial=None):
        super().__init__(parent)
        self.parent = parent
        self.on_save = on_save
        self.initial = initial or {}
        self.title(title)
        self.geometry("460x300")
        self.transient(parent)
        self.grab_set()

        frm = ttk.Frame(self)
        frm.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        ttk.Label(frm, text="Running No.").grid(row=0, column=0, sticky="w")
        self.no_lbl = ttk.Label(frm, text=(f"{self.initial.get('resident_no'):04d}" if self.initial.get('resident_no') else "(auto)"))
        self.no_lbl.grid(row=1, column=0, sticky="w", pady=(0,8))

        ttk.Label(frm, text="Name").grid(row=2, column=0, sticky="w")
        self.name_ent = ttk.Entry(frm, width=36)
        self.name_ent.grid(row=3, column=0, columnspan=2, pady=(0,8))

        ttk.Label(frm, text="Room").grid(row=4, column=0, sticky="w")
        self.room_ent = ttk.Entry(frm, width=16)
        self.room_ent.grid(row=5, column=0, sticky="w", pady=(0,8))

        self.active_var = tk.IntVar(value=1)
        ttk.Checkbutton(frm, text="Active", variable=self.active_var).grid(row=6, column=0, sticky="w", pady=(0,8))

        ttk.Label(frm, text="Trainer").grid(row=7, column=0, sticky="w")
        self.trainer_var = tk.StringVar()
        self.trainer_cb = ttk.Combobox(frm, textvariable=self.trainer_var, state="readonly", width=34)
        trainer_items = self._load_trainers()
        self.trainer_cb["values"] = trainer_items
        self.trainer_cb.grid(row=8, column=0, columnspan=2, sticky="w")

        btns = ttk.Frame(frm)
        btns.grid(row=9, column=0, columnspan=2, sticky="e", pady=(12,0))
        ttk.Button(btns, text="Save", command=self.save).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side=tk.RIGHT, padx=(0,6))

        # preload
        if self.initial:
            self.name_ent.insert(0, self.initial.get("name", ""))
            self.room_ent.insert(0, self.initial.get("room", ""))
            self.active_var.set(1 if self.initial.get("active", True) else 0)
            tid = self.initial.get("trainer_id")
            if tid is None:
                self.trainer_cb.set("None")
            else:
                for item in trainer_items:
                    if item.startswith(f"{tid}:"):
                        self.trainer_cb.set(item)
                        break
        else:
            self.trainer_cb.set("None")

    def _load_trainers(self):
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, name FROM trainers ORDER BY name")
        rows = cur.fetchall()
        conn.close()
        items = ["None"] + [f"{i}:{n}" for i,n in rows]
        return items

    def save(self):
        name = self.name_ent.get().strip()
        room = self.room_ent.get().strip()
        if not name or not room:
            messagebox.showwarning("Required", "Name and Room are required")
            return
        tid_val = self.trainer_var.get()
        trainer_id = None
        if tid_val and tid_val != "None":
            trainer_id = int(tid_val.split(":",1)[0])
        payload = {
            "id": self.initial.get("id"),
            "name": name,
            "room": room,
            "active": bool(self.active_var.get()),
            "trainer_id": trainer_id,
        }
        self.on_save(payload)
        self.destroy()


class TrainerForm(tk.Toplevel):
    def __init__(self, parent: TrainersDialog, title: str, on_save, initial=None):
        super().__init__(parent)
        self.parent = parent
        self.on_save = on_save
        self.initial = initial or {}
        self.title(title)
        self.geometry("360x200")
        self.transient(parent)
        self.grab_set()

        frm = ttk.Frame(self)
        frm.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        ttk.Label(frm, text="Name").grid(row=0, column=0, sticky="w")
        self.name_ent = ttk.Entry(frm, width=32)
        self.name_ent.grid(row=1, column=0, pady=(0,8))

        ttk.Label(frm, text="Phone").grid(row=2, column=0, sticky="w")
        self.phone_ent = ttk.Entry(frm, width=24)
        self.phone_ent.grid(row=3, column=0, pady=(0,8))

        btns = ttk.Frame(frm)
        btns.grid(row=4, column=0, sticky="e")
        ttk.Button(btns, text="Save", command=self.save).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side=tk.RIGHT, padx=(0,6))

        if self.initial:
            self.name_ent.insert(0, self.initial.get("name",""))
            self.phone_ent.insert(0, self.initial.get("phone",""))

    def save(self):
        name = self.name_ent.get().strip()
        phone = self.phone_ent.get().strip() or None
        if not name:
            messagebox.showwarning("Required", "Name is required")
            return
        payload = {"id": self.initial.get("id"), "name": name, "phone": phone}
        self.on_save(payload)
        self.destroy()


if __name__ == "__main__":
    init_db()
    app = App()
    app.mainloop()
