import email
import imaplib
import os
import re
import sqlite3
import subprocess
import sys
import time
from contextlib import closing

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

STEAM_DEFAULT = r"C:\Program Files (x86)\Steam\steam.exe"
DB_PATH = "gamenet.db"

APP_STYLE = """
QWidget { background-color: #0a0d15; color: #d8e7ff; font-family: 'Segoe UI'; font-size: 10.5pt; }
QPushButton { background-color: #5b61ff; color: #f6f8ff; border-radius: 10px; padding: 9px 15px; font-weight: 700; }
QPushButton:hover { background-color: #6f75ff; }
QLineEdit, QComboBox { background-color: #0b1323; border: 1px solid #2e3b63; border-radius: 8px; padding: 8px; }
QToolButton { background-color: #1d2746; border-radius: 7px; padding: 4px 8px; }
"""


def db_connect():
    return sqlite3.connect(DB_PATH, timeout=10)


def init_db():
    with closing(db_connect()) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                username TEXT,
                password TEXT,
                email TEXT,
                email_password TEXT,
                email_provider TEXT DEFAULT 'Gmail',
                guard_mode TEXT DEFAULT 'none'
            )
            """
        )
        conn.commit()


def list_accounts():
    with closing(db_connect()) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute("SELECT * FROM accounts ORDER BY id")]


def find_account_by_id(acc_id):
    with closing(db_connect()) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM accounts WHERE id=?", (acc_id,)).fetchone()
        return dict(row) if row else None


def get_steam_guard_code_from_email_detailed(email_user, email_pass, provider, last_time=0):
    report, code, mail = [], None, None
    try:
        server = {"Gmail": "imap.gmail.com", "Outlook": "imap.outlook.com"}.get(provider, "imap.gmail.com")
        mail = imaplib.IMAP4_SSL(server)
        mail.login(email_user, email_pass)
        mail.select("inbox")
        report.append(("اتصال ایمیل", True, server))

        since_time = time.strftime("%d-%b-%Y", time.gmtime(time.time() - 300))
        result, data = mail.search(None, f'(SUBJECT "Steam" SINCE "{since_time}")')
        if result != "OK":
            return None, report + [("جستجو", False, result)]

        for msg_id in reversed(data[0].split()[:30]):
            res, msg_data = mail.fetch(msg_id, "(RFC822)")
            if res != "OK":
                continue

            msg = email.message_from_bytes(msg_data[0][1])
            date_tuple = email.utils.parsedate_tz(msg.get("Date"))
            if date_tuple and email.utils.mktime_tz(date_tuple) <= last_time:
                continue

            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode(errors="ignore")
                        break
            else:
                body = msg.get_payload(decode=True).decode(errors="ignore")

            match = re.search(r"Steam Guard code[^\w]*([A-Z0-9]{5})|Request made from[^\w]*([A-Z0-9]{5})", body, re.I)
            if match:
                code = match.group(1) or match.group(2)
                break

        report.append(("کد", bool(code), code or "پیدا نشد"))
    except Exception as e:
        report.append(("خطا", False, str(e)))
    finally:
        if mail:
            try:
                mail.logout()
            except Exception:
                pass
    return code, report


class AccountQuickDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("انتخاب اکانت")
        layout = QVBoxLayout()
        self.combo = QComboBox()
        for acc in list_accounts():
            self.combo.addItem(f"{acc['name']} | {acc['guard_mode']}", acc["id"])
        layout.addWidget(self.combo)
        btn = QPushButton("ورود")
        btn.clicked.connect(self.accept)
        layout.addWidget(btn)
        self.setLayout(layout)


class GameNetApp(QWidget):
    def __init__(self):
        super().__init__()
        init_db()
        self.setStyleSheet(APP_STYLE)
        self.setWindowTitle("GameNet Pro | Smart Guard")
        self.setGeometry(120, 100, 800, 420)
        self._build_ui()
        self.shortcut = QShortcut(QKeySequence("Ctrl+Shift+A"), self)
        self.shortcut.activated.connect(self.select_account_flow)

    def _build_ui(self):
        v = QVBoxLayout()
        title = QLabel("<h2 style='color:#7bd7ff'>🎮 GameNet Pro Launcher</h2><div>Smart Steam Guard Flow</div>")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        v.addWidget(title)

        row = QHBoxLayout()
        auto_btn = QPushButton("✅ Auto Login")
        auto_btn.clicked.connect(self.select_account_flow)
        open_btn = QPushButton("🚀 Open Steam")
        open_btn.clicked.connect(self.open_steam)
        row.addWidget(auto_btn)
        row.addWidget(open_btn)
        v.addLayout(row)

        self.setLayout(v)

    def _popen(self, cmd):
        try:
            if sys.platform == "win32":
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = subprocess.SW_HIDE
                subprocess.Popen(cmd, startupinfo=si, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            else:
                subprocess.Popen(cmd)
            return True
        except Exception:
            return False

    def _close_steam(self):
        if sys.platform == "win32":
            os.system('taskkill /f /im "steam.exe" >nul 2>nul')
            os.system('taskkill /f /im "steamwebhelper.exe" >nul 2>nul')

    def open_steam(self):
        if not os.path.exists(STEAM_DEFAULT):
            QMessageBox.warning(self, "خطا", "Steam path not found")
            return
        self._popen([STEAM_DEFAULT])

    def select_account_flow(self):
        dlg = AccountQuickDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        acc_id = dlg.combo.currentData()
        acc = find_account_by_id(acc_id)
        if not acc:
            return
        self.auto_login(acc)

    def auto_login(self, acc):
        username = acc["username"]
        password = acc["password"]
        guard_mode = (acc.get("guard_mode") or "none").lower()
        steam_path = STEAM_DEFAULT

        if not os.path.exists(steam_path):
            QMessageBox.warning(self, "خطا", "Steam path not found")
            return

        self._close_steam()
        time.sleep(1)

        if guard_mode == "mobile":
            ok = self._handle_mobile_guard_flow(steam_path, username, password)
            QMessageBox.information(
                self,
                "Mobile Guard",
                "درخواست تایید به گوشی ارسال شد." if ok else "ارسال تایید موبایل ناموفق بود.",
            )
            return

        # none/email: first trigger login so Steam creates challenge
        self._popen([steam_path, "-login", username, password])

        if guard_mode == "email":
            code = self._wait_for_email_code_smart(
                acc.get("email") or "",
                acc.get("email_password") or "",
                acc.get("email_provider") or "Gmail",
                wait_seconds=48,
                poll_interval=4,
            )
            if code:
                self._close_steam()
                time.sleep(1)
                self._popen([steam_path, "-login", username, password, code])
                QMessageBox.information(self, "موفق", f"کد پیدا شد: {code}")
            else:
                QMessageBox.warning(
                    self,
                    "هشدار",
                    "کد ایمیلی دیر رسید یا پیدا نشد؛ پنجره Steam باز می‌ماند تا دستی وارد کنید.",
                )
        else:
            QMessageBox.information(self, "موفق", "لاگین اجرا شد")

    def _handle_mobile_guard_flow(self, steam_path, username, password):
        for _ in range(2):
            if not self._popen([steam_path, "-login", username, password]):
                return False
            time.sleep(2)
            self._popen([steam_path])
            ans = QMessageBox.question(
                self,
                "Steam Guard Mobile",
                "اعلان تایید در گوشی آمد؟\nYes=آمده و تایید می‌کنم | No=تلاش دوباره",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if ans == QMessageBox.StandardButton.Yes:
                return True
            self._close_steam()
            time.sleep(1)
        return False

    def _wait_for_email_code_smart(self, email_addr, email_pass, provider, wait_seconds=48, poll_interval=4):
        if not email_addr or not email_pass:
            return None
        start = time.time()
        last_time = start - 8
        attempts = max(1, int(wait_seconds / poll_interval))
        for _ in range(attempts):
            time.sleep(poll_interval)
            code, _ = get_steam_guard_code_from_email_detailed(email_addr, email_pass, provider, last_time)
            if code:
                return code
        return None


if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = GameNetApp()
    w.show()
    sys.exit(app.exec())
