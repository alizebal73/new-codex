import email
import imaplib
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import uuid
from contextlib import closing

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
except ImportError:
    print("Please install cryptography: pip install cryptography")
    sys.exit(1)

try:
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt6.QtGui import QKeySequence, QShortcut
    from PyQt6.QtWidgets import (
        QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
        QFileDialog, QFormLayout, QFrame, QGridLayout, QGroupBox,
        QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit,
        QMessageBox, QPushButton, QTableWidget, QTableWidgetItem,
        QTabWidget, QTextEdit, QToolButton, QVBoxLayout, QWidget,
    )
except ImportError:
    print("❌ PyQt6 نصب نیست. اجرا کنید:\npip install PyQt6")
    sys.exit(1)

try:
    import pyautogui
    pyautogui.FAILSAFE = True
    pyautogui.PAUSE = 0.05
except ImportError:
    print("Warning: pyautogui not found. Auto-typing will be disabled.")
    pyautogui = None

try:
    import pygetwindow as gw
    GW_AVAILABLE = True
except ImportError:
    print("Warning: pygetwindow not found.")
    GW_AVAILABLE = False


STEAM_DEFAULT = r"C:\Program Files (x86)\Steam\steam.exe"
ADMIN_DEFAULT = "12345"
SELECT_DEFAULT = "12345"
HOTKEY_DEFAULT = "Ctrl+Shift+A"

PLATFORMS = {
    "steam": {"name": "Steam", "icon": "🎮", "color": "#171a21", "default_path": r"C:\Program Files (x86)\Steam\steam.exe"},
    "zula": {"name": "Zula", "icon": "🔫", "color": "#ff6b00", "default_path": r"C:\Zula\ZulaLauncher.exe"},
    "riot": {"name": "Riot Games", "icon": "💀", "color": "#ff4655", "default_path": r"C:\Riot Games\Riot Client\RiotClientServices.exe"},
    "epic": {"name": "Epic Games", "icon": "🎯", "color": "#333333", "default_path": r"C:\Program Files (x86)\Epic Games\Launcher\Portal\Binaries\Win32\EpicGamesLauncher.exe"},
}


def bundled_resource_path(rel_path: str) -> str:
    try:
        base = sys._MEIPASS
    except Exception:
        base = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(base, rel_path)


def writable_app_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.abspath(os.path.dirname(sys.executable))
    return os.path.abspath(os.path.dirname(__file__))


APP_DIR = writable_app_dir()
DB_PATH = os.path.join(APP_DIR, "gamenet.db")
KEY_PATH = os.path.join(APP_DIR, "secret.key")


def ensure_bundled_resources():
    try:
        if not os.path.exists(KEY_PATH):
            src = bundled_resource_path("secret.key")
            if os.path.exists(src):
                shutil.copy(src, KEY_PATH)
        if not os.path.exists(DB_PATH):
            src_db = bundled_resource_path("gamenet.db")
            if os.path.exists(src_db):
                shutil.copy(src_db, DB_PATH)
    except Exception:
        pass


def load_fernet() -> Fernet:
    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    if not os.path.exists(KEY_PATH):
        with open(KEY_PATH, "wb") as f:
            f.write(Fernet.generate_key())
    with open(KEY_PATH, "rb") as f:
        return Fernet(f.read())


FERNET = load_fernet()


def encrypt_str(s: str) -> str:
    if not s:
        return ""
    return FERNET.encrypt(s.encode("utf-8")).decode("utf-8")


def decrypt_str(s: str) -> str:
    if not s:
        return ""
    try:
        return FERNET.decrypt(s.encode("utf-8")).decode("utf-8")
    except Exception:
        return ""


def db_connect():
    return sqlite3.connect(DB_PATH, timeout=10)


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with closing(db_connect()) as conn:
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY CHECK (id = 1), steam_path TEXT,
            admin_pass_enc TEXT, select_pass_enc TEXT, hotkey TEXT, show_admin_button INTEGER)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, username TEXT,
            password_enc TEXT, email TEXT, email_password_enc TEXT,
            email_provider TEXT, guard_mode TEXT DEFAULT 'none')""")
        cur.execute("""CREATE TABLE IF NOT EXISTS systems (
            id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT UNIQUE,
            system_name TEXT, account_id INTEGER,
            FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE SET NULL)""")
        cur.execute("SELECT COUNT(*) FROM settings")
        if cur.fetchone()[0] == 0:
            cur.execute("""INSERT INTO settings VALUES (1,?,?,?,?,?)""",
                (STEAM_DEFAULT, encrypt_str(ADMIN_DEFAULT), encrypt_str(SELECT_DEFAULT), HOTKEY_DEFAULT, 1))
        cur.execute("PRAGMA table_info(accounts)")
        cols = {row[1] for row in cur.fetchall()}
        if "guard_mode" not in cols:
            cur.execute("ALTER TABLE accounts ADD COLUMN guard_mode TEXT DEFAULT 'none'")
        conn.commit()


def get_settings():
    with closing(db_connect()) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM settings WHERE id=1")
        row = cur.fetchone()
    return dict(row) if row else {
        "steam_path": STEAM_DEFAULT, "admin_pass_enc": encrypt_str(ADMIN_DEFAULT),
        "select_pass_enc": encrypt_str(SELECT_DEFAULT), "hotkey": HOTKEY_DEFAULT, "show_admin_button": 1}


def update_settings(**kwargs):
    with closing(db_connect()) as conn:
        cur = conn.cursor()
        for k, v in kwargs.items():
            if v is not None:
                cur.execute(f"UPDATE settings SET {k}=? WHERE id=1", (v,))
        conn.commit()


def list_accounts():
    with closing(db_connect()) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM accounts ORDER BY id")
        return [dict(r) for r in cur.fetchall()]


def add_account(name, username, plain_password, email_addr, email_password, provider, guard_mode):
    with closing(db_connect()) as conn:
        cur = conn.cursor()
        cur.execute("""INSERT OR IGNORE INTO accounts 
            (name, username, password_enc, email, email_password_enc, email_provider, guard_mode)
            VALUES (?,?,?,?,?,?,?)""",
            (name, username, encrypt_str(plain_password), email_addr, encrypt_str(email_password), provider, guard_mode))
        cur.execute("""UPDATE accounts SET username=?, password_enc=?, email=?, 
            email_password_enc=?, email_provider=?, guard_mode=? WHERE name=?""",
            (username, encrypt_str(plain_password), email_addr, encrypt_str(email_password), provider, guard_mode, name))
        conn.commit()


def update_account_by_id(acc_id, username, plain_password, name, email_addr, email_password, provider, guard_mode):
    with closing(db_connect()) as conn:
        cur = conn.cursor()
        cur.execute("""UPDATE accounts SET username=?, password_enc=?, name=?, email=?,
            email_password_enc=?, email_provider=?, guard_mode=? WHERE id=?""",
            (username, encrypt_str(plain_password), name, email_addr, encrypt_str(email_password), provider, guard_mode, acc_id))
        conn.commit()


def delete_account_by_id(acc_id):
    with closing(db_connect()) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM accounts WHERE id=?", (acc_id,))
        conn.commit()


def find_account_by_id(acc_id):
    with closing(db_connect()) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM accounts WHERE id=?", (acc_id,))
        row = cur.fetchone()
    return dict(row) if row else None


def list_systems():
    with closing(db_connect()) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM systems ORDER BY id")
        return [dict(r) for r in cur.fetchall()]


def add_or_update_system(mac, system_name, account_id):
    mac = mac.strip().upper()
    with closing(db_connect()) as conn:
        cur = conn.cursor()
        cur.execute("INSERT OR IGNORE INTO systems (mac, system_name, account_id) VALUES (?,?,?)", (mac, system_name, account_id))
        cur.execute("UPDATE systems SET system_name=?, account_id=? WHERE mac=?", (system_name, account_id, mac))
        conn.commit()


def update_system_account(system_id, account_id):
    with closing(db_connect()) as conn:
        cur = conn.cursor()
        cur.execute("UPDATE systems SET account_id=? WHERE id=?", (account_id, system_id))
        conn.commit()


def delete_system_by_id(sys_id):
    with closing(db_connect()) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM systems WHERE id=?", (sys_id,))
        conn.commit()


def find_system_by_mac(mac):
    with closing(db_connect()) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM systems WHERE mac=?", (mac.strip().upper(),))
        row = cur.fetchone()
    return dict(row) if row else None


def get_mac_address():
    node = uuid.getnode()
    return ":".join(f"{(node >> ele) & 0xFF:02X}" for ele in range(40, -1, -8))


def get_steam_guard_code_from_email_detailed(email_user, email_pass, provider, last_time=0):
    code, mail = None, None
    try:
        server = {"Gmail": "imap.gmail.com", "Outlook": "imap.outlook.com"}.get(provider, "imap.gmail.com")
        mail = imaplib.IMAP4_SSL(server)
        mail.login(email_user, email_pass)
        mail.select("inbox")
        since_time = time.strftime("%d-%b-%Y", time.gmtime(time.time() - 300))
        result, data = mail.search(None, f'(SUBJECT "Steam" SINCE "{since_time}")')
        if result != "OK":
            return None, []
        for msg_id in reversed(data[0].split()[:20]):
            res, msg_data = mail.fetch(msg_id, "(RFC822)")
            if res != "OK": continue
            msg = email.message_from_bytes(msg_data[0][1])
            date_tuple = email.utils.parsedate_tz(msg["Date"])
            if date_tuple and email.utils.mktime_tz(date_tuple) <= last_time: continue
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode(errors="ignore"); break
            else:
                body = msg.get_payload(decode=True).decode(errors="ignore")
            match = re.search(r"Steam Guard code[^\w]*([A-Z0-9]{5})|Request made from[^\w]*([A-Z0-9]{5})", body, re.I)
            if match: 
                code = match.group(1) or match.group(2)
                if code: break
            fallback = re.search(r"\b([A-Z0-9]{5})\b", body)
            if fallback: 
                code = fallback.group(1)
                if code: break
    except Exception as e:
        print(f"Error getting Steam Guard code: {e}")
        pass
    finally:
        if mail:
            try: 
                mail.close()
                mail.logout()
            except: 
                pass
    return code, []


APP_STYLE = """
QWidget { background-color: #0a0d15; color: #ffffff; font-family: 'Segoe UI', Arial; font-size: 11pt; }
QGroupBox { border: 2px solid #5b61ff; border-radius: 12px; margin-top: 14px; padding: 14px; background-color: #11172a; color: #ffffff; }
QGroupBox::title { subcontrol-origin: margin; left: 14px; color: #39d0ff; font-weight: 800; padding: 0 8px; }
QPushButton { background-color: #5b61ff; color: #ffffff; border: 1px solid #868bff; border-radius: 10px; padding: 10px 20px; font-weight: 700; min-width: 80px; min-height: 35px; }
QPushButton:hover { background-color: #6f75ff; }
QPushButton:pressed { background-color: #4e55df; }
QPushButton:disabled { background-color: #3a3a5a; color: #8888aa; }
QLineEdit, QComboBox, QTextEdit { background-color: #0b1323; color: #ffffff; border: 1px solid #2e3b63; border-radius: 8px; padding: 8px; }
QLineEdit:focus, QComboBox:focus, QTextEdit:focus { border: 1px solid #39d0ff; }
QTableWidget { background-color: #0b1323; color: #ffffff; gridline-color: #1f2b4c; border: 1px solid #2e3b63; border-radius: 8px; }
QTableWidget::item { padding: 5px; }
QHeaderView::section { background-color: #131d34; color: #8ed8ff; padding: 10px; border: none; font-weight: 700; }
QToolButton { background-color: #1d2746; color: #9ad9ff; border: 1px solid #2e3b63; border-radius: 7px; padding: 5px 10px; }
QToolButton:hover { background-color: #25315a; }
QTabWidget::pane { border: 2px solid #2e3b63; border-radius: 8px; background-color: #0a0d15; }
QTabBar::tab { background-color: #131d34; color: #8ed8ff; padding: 10px 20px; border: 1px solid #2e3b63; border-bottom: none; border-top-left-radius: 8px; border-top-right-radius: 8px; margin-right: 2px; min-height: 35px; }
QTabBar::tab:selected { background-color: #5b61ff; color: #ffffff; }
QTabBar::tab:hover:!selected { background-color: #1f2b4c; }
QLabel { color: #ffffff; }
QCheckBox { color: #ffffff; }
QCheckBox::indicator { border: 2px solid #5b61ff; border-radius: 4px; background-color: #0b1323; }
QCheckBox::indicator:checked { background-color: #5b61ff; }
"""


class SteamGuardWorker(QThread):
    code_found = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    def __init__(self, email_user, email_pass, provider):
        super().__init__()
        self.email_user = email_user
        self.email_pass = email_pass
        self.provider = provider
        self.stop_requested = False
    def run(self):
        last_time = time.time() - 120
        for i in range(10):
            if self.stop_requested: break
            code, _ = get_steam_guard_code_from_email_detailed(self.email_user, self.email_pass, self.provider, last_time=last_time)
            if code:
                self.code_found.emit(code); return
            time.sleep(3)
        self.error_occurred.emit("کدی پیدا نشد")
    def stop(self):
        self.stop_requested = True


class AccountDialog(QDialog):
    def __init__(self, parent=None, acc_id=None, name=None, username="", password="", email_addr="", email_password="", provider="Gmail", guard_mode="none"):
        super().__init__(parent)
        self.acc_id = acc_id
        self.setWindowTitle("ویرایش اکانت" if acc_id else "افزودن اکانت")
        self.setMinimumSize(550, 420)
        form = QFormLayout()
        self.name_edit = QLineEdit(name or "")
        self.user_edit = QLineEdit(username)
        self.pass_edit = QLineEdit(password); self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_eye = QToolButton(); self.pass_eye.setText("👁"); self.pass_eye.setCheckable(True)
        self.pass_eye.toggled.connect(lambda c: self.pass_edit.setEchoMode(QLineEdit.EchoMode.Normal if c else QLineEdit.EchoMode.Password))
        self.email_edit = QLineEdit(email_addr)
        self.email_pass_edit = QLineEdit(email_password); self.email_pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.email_pass_eye = QToolButton(); self.email_pass_eye.setText("👁"); self.email_pass_eye.setCheckable(True)
        self.email_pass_eye.toggled.connect(lambda c: self.email_pass_edit.setEchoMode(QLineEdit.EchoMode.Normal if c else QLineEdit.EchoMode.Password))
        self.provider_combo = QComboBox(); self.provider_combo.addItems(["Gmail", "Outlook"]); self.provider_combo.setCurrentText(provider)
        self.guard_mode_combo = QComboBox(); self.guard_mode_combo.addItems(["none", "email", "mobile"]); self.guard_mode_combo.setCurrentText(guard_mode if guard_mode in {"none","email","mobile"} else "none")
        form.addRow("نام داخلی:", self.name_edit)
        form.addRow("نام کاربری:", self.user_edit)
        pr = QHBoxLayout(); pr.addWidget(self.pass_edit); pr.addWidget(self.pass_eye); form.addRow("رمز عبور:", pr)
        form.addRow("ایمیل:", self.email_edit)
        er = QHBoxLayout(); er.addWidget(self.email_pass_edit); er.addWidget(self.email_pass_eye); form.addRow("رمز ایمیل:", er)
        form.addRow("سرویس ایمیل:", self.provider_combo)
        form.addRow("نوع Guard:", self.guard_mode_combo)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._validate); buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(); lay.addLayout(form); lay.addWidget(buttons); self.setLayout(lay)
    def _validate(self):
        if not self.name_edit.text().strip() or not self.user_edit.text().strip():
            QMessageBox.warning(self, "خطا", "نام و نام کاربری الزامی است"); return
        self.accept()
    def get_values(self):
        return (self.name_edit.text().strip(), self.user_edit.text().strip(), self.pass_edit.text(),
                self.email_edit.text().strip(), self.email_pass_edit.text(), self.provider_combo.currentText(), self.guard_mode_combo.currentText())


class SystemDialog(QDialog):
    def __init__(self, parent=None, mac="", system_name="", account_id=None):
        super().__init__(parent)
        self.accounts = list_accounts()
        self.setWindowTitle("مدیریت سیستم")
        self.setMinimumSize(500, 350)
        form = QFormLayout()
        self.mac_edit = QLineEdit(mac)
        self.name_edit = QLineEdit(system_name)
        self.acc_combo = QComboBox(); self.acc_combo.addItem("هیچکدام", None)
        for a in self.accounts: self.acc_combo.addItem(f"{a['name']} (ID:{a['id']})", a["id"])
        if account_id is not None:
            idx = self.acc_combo.findData(account_id)
            if idx >= 0: self.acc_combo.setCurrentIndex(idx)
        form.addRow("MAC:", self.mac_edit); form.addRow("نام سیستم:", self.name_edit); form.addRow("اکانت:", self.acc_combo)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._validate); buttons.rejected.connect(self.reject)
        lay = QVBoxLayout(); lay.addLayout(form); lay.addWidget(buttons); self.setLayout(lay)
    def _validate(self):
        mac = self.mac_edit.text().strip().replace("-","").replace(":","").upper()
        if len(mac) != 12 or not all(c in "0123456789ABCDEF" for c in mac):
            QMessageBox.warning(self, "خطا", "MAC معتبر نیست"); return
        self.accept()
    def get_values(self):
        raw = self.mac_edit.text().strip().upper().replace("-", ":")
        if ":" not in raw and len(raw) == 12: raw = ":".join(raw[i:i+2] for i in range(0,12,2))
        return raw, self.name_edit.text().strip(), self.acc_combo.currentData()


class GameNetApp(QWidget):
    def __init__(self):
        super().__init__()
        init_db()
        self.setStyleSheet(APP_STYLE)
        self.setWindowTitle("GameNet Pro | Multi-Platform")
        self.setGeometry(100, 80, 1000, 700)
        self.setMinimumSize(800, 600)
        self.current_mac = get_mac_address()
        self.current_platform = "steam"
        self.guard_worker = None
        self.build_ui()
        self._setup_shortcut()

    def build_ui(self):
        root = QVBoxLayout(); root.setSpacing(15); root.setContentsMargins(20, 20, 20, 20)
        title = QLabel("<h2 style='color:#7bd7ff'>GameNet Pro Launcher</h2><div style='color:#9fa8ff;font-size:11pt;'>Multi-Platform Esports Control Panel</div>")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter); root.addWidget(title)
        info = find_system_by_mac(self.current_mac)
        nm = info["system_name"] if info else "Unknown"
        root.addWidget(QLabel(f"MAC: {self.current_mac} | سیستم: {nm}"))
        
        # ✅ کارت‌های پلتفرم - بدون دکمه هوم
        grid = QGridLayout(); grid.setSpacing(15)
        row = col = 0
        for pid, inf in PLATFORMS.items():
            card = QPushButton(f"{inf['icon']}<br><b>{inf['name']}</b><br><small>کلیک برای ورود</small>")
            card.setStyleSheet(f"QPushButton{{background:{inf['color']};border:2px solid #5b61ff;border-radius:15px;padding:20px;text-align:center;}}QPushButton:hover{{border-color:#39d0ff;}}")
            card.setMinimumSize(180, 150)
            card.clicked.connect(lambda _, p=pid: self.go_to_platform(p))
            grid.addWidget(card, row, col)
            col += 1
            if col >= 3: col = 0; row += 1
        root.addLayout(grid)
        
        self.admin_btn = QPushButton("تنظیمات ادمین")
        self.admin_btn.clicked.connect(self._admin)
        self.admin_btn.setVisible(get_settings().get("show_admin_button", 1) == 1)
        self.admin_btn.setMinimumHeight(40)
        root.addWidget(self.admin_btn)
        root.addStretch()
        self.setLayout(root)
        
        # لیبل وضعیت
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color:#00ff00;font-weight:bold;")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.insertWidget(3, self.status_label)

    def go_to_platform(self, platform):
        """ورود به صفحه لاگین پلتفرم انتخاب شده"""
        self.current_platform = platform
        self._do_login_flow(platform)

    def _do_login_flow(self, platform):
        """فلو لاگین برای پلتفرم انتخاب شده"""
        info = find_system_by_mac(self.current_mac)
        if not info or not info["account_id"]:
            QMessageBox.warning(self, "خطا", "این سیستم به هیچ اکانتی متصل نیست"); return
        acc = find_account_by_id(info["account_id"])
        if not acc: 
            QMessageBox.warning(self, "خطا", "اکانت مربوطه یافت نشد"); return
        self._close_platform()
        time.sleep(2)
        path = PLATFORMS.get(platform, {}).get("default_path", STEAM_DEFAULT)
        username = acc["username"]
        password = decrypt_str(acc["password_enc"])
        guard_mode = acc.get("guard_mode", "none")
        
        if platform == "steam" and guard_mode == "email":
            self._login_with_guard(path, username, password, acc)
        else:
            if platform == "steam":
                success = self._popen([path, "-login", username, password])
                if success:
                    self.status_label.setText(f"ورود: {acc['name']}")
                else:
                    self.status_label.setText(f"خطا در باز کردن استیم")
            else:
                success = self._popen([path])
                if success:
                    time.sleep(3); self._focus(); time.sleep(1)
                    self._type(username); time.sleep(0.5); pyautogui.press('tab'); time.sleep(0.3)
                    self._type(password); time.sleep(0.5); pyautogui.press('enter')
                    self.status_label.setText(f"ورود: {acc['name']}")
                else:
                    self.status_label.setText(f"خطا در باز کردن {platform}")

    def _login_with_guard(self, path, username, password, acc):
        self._popen([path]); self.status_label.setText("باز کردن استیم..."); time.sleep(5)
        self._focus(); time.sleep(1)
        self.status_label.setText("وارد کردن نام کاربری..."); self._type(username); time.sleep(0.5); pyautogui.press('tab'); time.sleep(0.3)
        self.status_label.setText("وارد کردن رمز..."); self._type(password); time.sleep(0.5); pyautogui.press('enter')
        self.status_label.setText("انتظار برای کد..."); time.sleep(8)
        self._focus(); time.sleep(1)
        epass = decrypt_str(acc["email_password_enc"])
        self.guard_worker = SteamGuardWorker(acc["email"], epass, acc.get("email_provider", "Gmail"))
        self.guard_worker.code_found.connect(self._on_code); self.guard_worker.error_occurred.connect(self._on_err)
        self.guard_worker.start()
        self.status_label.setText("دریافت کد از ایمیل...")

    def _on_code(self, code):
        self.status_label.setText(f"کد: {code} - در حال تایپ..."); QTimer.singleShot(500, lambda: self._type_code(code))
    def _on_err(self, msg):
        self.status_label.setText(f"خطا: {msg}")
        QMessageBox.warning(self, "خطا", msg + "\n\nلطفاً کد را دستی وارد کنید.")
    def _type_code(self, code):
        if not code or not pyautogui: return
        self._focus(); time.sleep(0.5)
        for c in code: pyautogui.press(c); time.sleep(0.1)
        time.sleep(0.3); pyautogui.press('enter')
        self.status_label.setText(f"کد وارد شد: {code}"); QTimer.singleShot(3000, lambda: self.status_label.setText(""))

    def _popen(self, cmd):
        try:
            if sys.platform == "win32":
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = subprocess.SW_HIDE
                process = subprocess.Popen(cmd, startupinfo=si, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            else: 
                process = subprocess.Popen(cmd)
            return process is not None
        except Exception as e:
            print(f"Error starting process: {e}")
            return False

    def _close_platform(self):
        if PSUTIL_AVAILABLE:
            for p in psutil.process_iter(["name"]):
                try:
                    if any(plat in (p.info["name"] or "").lower() for plat in ["steam", "zula", "riot", "epic"]): p.terminate()
                except: pass
        elif sys.platform == "win32": os.system('taskkill /f /im "steam.exe"')

    def _focus(self):
        if GW_AVAILABLE:
            try:
                for w in gw.getWindowsWithTitle("Steam"): w.activate(); time.sleep(0.3); return True
            except: pass
        if pyautogui: time.sleep(0.3); return True
        return False

    def _type(self, txt):
        if not pyautogui: return False
        for c in txt: pyautogui.press(c); time.sleep(0.05)
        return True

    def _setup_shortcut(self):
        hk = get_settings().get("hotkey", HOTKEY_DEFAULT)
        self.shortcut = QShortcut(QKeySequence(hk), self)
        self.shortcut.activated.connect(self._admin)

    def _admin(self):
        settings = get_settings(); pwd = settings["admin_pass_enc"]
        if pwd and decrypt_str(pwd):
            pt, ok = QInputDialog.getText(self, "Admin", "رمز ادمین:", QLineEdit.EchoMode.Password)
            if not ok or pt != decrypt_str(pwd):
                QMessageBox.warning(self, "خطا", "رمز نادرست"); return
        self._show_admin_panel()

    def _show_admin_panel(self):
        dlg = QDialog(self); dlg.setWindowTitle("پنل ادمین"); dlg.setMinimumSize(850, 650)
        tabs = QTabWidget()
        
        # تب تنظیمات
        tab_set = QWidget(); form = QFormLayout()
        self.path_edit = QLineEdit(get_settings().get("steam_path", STEAM_DEFAULT))
        btn_br = QToolButton(); btn_br.setText("..."); btn_br.clicked.connect(self._browse)
        row = QHBoxLayout(); row.addWidget(self.path_edit); row.addWidget(btn_br)
        form.addRow("مسیر استیم:", row)
        self.admin_edit = QLineEdit(); self.sel_edit = QLineEdit()
        self.hk_edit = QLineEdit(get_settings().get("hotkey", HOTKEY_DEFAULT))
        self.show_chk = QCheckBox("نمایش دکمه ادمین"); self.show_chk.setChecked(get_settings().get("show_admin_button", 1) == 1)
        form.addRow("رمز ادمین جدید:", self.admin_edit)
        form.addRow("رمز انتخاب جدید:", self.sel_edit)
        form.addRow("کلید میانبر:", self.hk_edit); form.addRow(self.show_chk)
        btn_save = QPushButton("ذخیره"); btn_save.setMinimumHeight(40); btn_save.clicked.connect(self._save_settings)
        v = QVBoxLayout(); v.addLayout(form); v.addWidget(btn_save); v.addStretch(); tab_set.setLayout(v)
        tabs.addTab(tab_set, "تنظیمات")
        
        # تب اکانت‌ها
        tab_acc = QWidget(); v_acc = QVBoxLayout()
        self.acc_table = QTableWidget(); self.acc_table.setColumnCount(6)
        self.acc_table.setHorizontalHeaderLabels(["ID", "نام", "کاربری", "ایمیل", "Guard", "عملیات"])
        self.acc_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        v_acc.addWidget(self.acc_table)
        btn_add = QPushButton("افزودن اکانت"); btn_add.setMinimumHeight(40); btn_add.clicked.connect(self._add_acc)
        v_acc.addWidget(btn_add); tab_acc.setLayout(v_acc)
        tabs.addTab(tab_acc, "اکانت‌ها")
        
        # تب سیستم‌ها
        tab_sys = QWidget(); v_sys = QVBoxLayout()
        self.sys_table = QTableWidget(); self.sys_table.setColumnCount(6)
        self.sys_table.setHorizontalHeaderLabels(["ID", "MAC", "نام", "اکانت", "تغییر", "عملیات"])
        self.sys_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        v_sys.addWidget(self.sys_table)
        h_btns = QHBoxLayout()
        btn1 = QPushButton("افزودن دستی"); btn1.setMinimumHeight(40); btn1.clicked.connect(lambda: self._add_sys(False))
        btn2 = QPushButton("این سیستم"); btn2.setMinimumHeight(40); btn2.clicked.connect(lambda: self._add_sys(True))
        h_btns.addWidget(btn1); h_btns.addWidget(btn2); v_sys.addLayout(h_btns); tab_sys.setLayout(v_sys)
        tabs.addTab(tab_sys, "سیستم‌ها")
        
        # تب تست ایمیل
        tab_email = QWidget(); v_email = QVBoxLayout()
        self.email_combo = QComboBox(); self.email_result = QTextEdit(); self.email_result.setReadOnly(True)
        btn_test = QPushButton("تست دریافت کد"); btn_test.setMinimumHeight(40); btn_test.clicked.connect(self._test_email)
        v_email.addWidget(QLabel("انتخاب اکانت:")); v_email.addWidget(self.email_combo)
        v_email.addWidget(btn_test); v_email.addWidget(self.email_result); tab_email.setLayout(v_email)
        tabs.addTab(tab_email, "تست ایمیل")
        
        lay = QVBoxLayout(); lay.addWidget(tabs); dlg.setLayout(lay)
        self._refresh_acc_tbl(); self._refresh_email_combo(); dlg.exec()

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "Steam exe", "", "Executable (*.exe);;All Files (*)")
        if path: self.path_edit.setText(path)

    def _save_settings(self):
        update_settings(steam_path=self.path_edit.text().strip() or STEAM_DEFAULT)
        if self.admin_edit.text(): update_settings(admin_pass_enc=encrypt_str(self.admin_edit.text()))
        if self.sel_edit.text(): update_settings(select_pass_enc=encrypt_str(self.sel_edit.text()))
        update_settings(hotkey=self.hk_edit.text().strip() or HOTKEY_DEFAULT)
        update_settings(show_admin_button=1 if self.show_chk.isChecked() else 0)
        QMessageBox.information(self, "موفق", "تنظیمات ذخیره شد")

    def _refresh_acc_tbl(self):
        rows = list_accounts(); self.acc_table.setRowCount(0)
        for i, r in enumerate(rows):
            self.acc_table.insertRow(i)
            self.acc_table.setItem(i, 0, QTableWidgetItem(str(r["id"])))
            self.acc_table.setItem(i, 1, QTableWidgetItem(r["name"]))
            self.acc_table.setItem(i, 2, QTableWidgetItem(r["username"]))
            self.acc_table.setItem(i, 3, QTableWidgetItem(r["email"] or "-"))
            self.acc_table.setItem(i, 4, QTableWidgetItem(r["guard_mode"]))
            be = QToolButton(); be.setText("ویرایش"); be.clicked.connect(lambda _, aid=r["id"]: self._edit_acc(aid))
            bd = QToolButton(); bd.setText("حذف"); bd.clicked.connect(lambda _, aid=r["id"]: self._del_acc(aid))
            ops = QWidget(); h = QHBoxLayout(); h.setContentsMargins(0,0,0,0); h.addWidget(be); h.addWidget(bd); ops.setLayout(h)
            self.acc_table.setCellWidget(i, 5, ops)

    def _refresh_email_combo(self):
        self.email_combo.clear()
        for a in list_accounts(): self.email_combo.addItem(f"{a['name']} ({a['email']})", a["id"])

    def _add_acc(self):
        dlg = AccountDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            add_account(*dlg.get_values()); self._refresh_acc_tbl(); self._refresh_email_combo()

    def _edit_acc(self, aid):
        acc = find_account_by_id(aid)
        if not acc: return
        dlg = AccountDialog(self, acc_id=aid, name=acc["name"], username=acc["username"],
            password=decrypt_str(acc["password_enc"]), email_addr=acc["email"] or "",
            email_password=decrypt_str(acc["email_password_enc"]), provider=acc["email_provider"] or "Gmail",
            guard_mode=acc.get("guard_mode") or "none")
        if dlg.exec() == QDialog.DialogCode.Accepted:
            update_account_by_id(aid, *dlg.get_values()); self._refresh_acc_tbl(); self._refresh_email_combo()

    def _del_acc(self, aid):
        if QMessageBox.question(self, "حذف", "اکانت حذف شود؟") == QMessageBox.StandardButton.Yes:
            delete_account_by_id(aid); self._refresh_acc_tbl(); self._refresh_email_combo()

    def _add_sys(self, quick):
        dlg = SystemDialog(self, mac=get_mac_address() if quick else "")
        if dlg.exec() == QDialog.DialogCode.Accepted:
            add_or_update_system(*dlg.get_values()); self._refresh_sys_tbl()

    def _refresh_sys_tbl(self):
        rows = list_systems(); accs = list_accounts(); self.sys_table.setRowCount(0)
        for i, s in enumerate(rows):
            self.sys_table.insertRow(i)
            self.sys_table.setItem(i, 0, QTableWidgetItem(str(s["id"])))
            self.sys_table.setItem(i, 1, QTableWidgetItem(s["mac"]))
            self.sys_table.setItem(i, 2, QTableWidgetItem(s["system_name"] or "-"))
            a = find_account_by_id(s["account_id"]) if s["account_id"] else None
            self.sys_table.setItem(i, 3, QTableWidgetItem(a["name"] if a else "-"))
            cb = QComboBox(); cb.addItem("-", None)
            for x in accs: cb.addItem(x["name"], x["id"])
            idx = cb.findData(s["account_id"])
            if idx >= 0: cb.setCurrentIndex(idx)
            ap = QPushButton("اعمال"); ap.setMaximumWidth(80); ap.clicked.connect(lambda _, sid=s["id"], c=cb: self._apply_sys(sid, c.currentData()))
            cw = QWidget(); hl = QHBoxLayout(); hl.setContentsMargins(0,0,0,0); hl.addWidget(cb); hl.addWidget(ap); cw.setLayout(hl)
            self.sys_table.setCellWidget(i, 4, cw)
            be = QToolButton(); be.setText("ویرایش"); be.clicked.connect(lambda _, sid=s["id"]: self._edit_sys(sid))
            bd = QToolButton(); bd.setText("حذف"); bd.clicked.connect(lambda _, sid=s["id"]: self._del_sys(sid))
            ops = QWidget(); h = QHBoxLayout(); h.setContentsMargins(0,0,0,0); h.addWidget(be); h.addWidget(bd); ops.setLayout(h)
            self.sys_table.setCellWidget(i, 5, ops)

    def _apply_sys(self, sid, aid): update_system_account(sid, aid); self._refresh_sys_tbl()
    def _edit_sys(self, sid):
        row = next((x for x in list_systems() if x["id"]==sid), None)
        if not row: return
        dlg = SystemDialog(self, mac=row["mac"], system_name=row["system_name"] or "", account_id=row["account_id"])
        if dlg.exec() == QDialog.DialogCode.Accepted:
            nm, sn, aid = dlg.get_values()
            if nm.upper() != row["mac"].upper(): delete_system_by_id(sid)
            add_or_update_system(nm, sn, aid); self._refresh_sys_tbl()
    def _del_sys(self, sid):
        if QMessageBox.question(self, "حذف", "سیستم حذف شود؟") == QMessageBox.StandardButton.Yes:
            delete_system_by_id(sid); self._refresh_sys_tbl()

    def _test_email(self):
        aid = self.email_combo.currentData()
        if not aid: self.email_result.setText("اکانت انتخاب نشده"); return
        acc = find_account_by_id(aid)
        if not acc: self.email_result.setText("اکانت پیدا نشد"); return
        code, _ = get_steam_guard_code_from_email_detailed(acc["email"], decrypt_str(acc["email_password_enc"]), acc["email_provider"], time.time()-120)
        if code: self.email_result.setText(f"کد پیدا شد: {code}")
        else: self.email_result.setText("کدی پیدا نشد")


if __name__ == "__main__":
    ensure_bundled_resources(); init_db()
    app = QApplication(sys.argv); app.setStyle("Fusion")
    win = GameNetApp(); win.show(); sys.exit(app.exec())