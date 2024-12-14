import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QPushButton, QLineEdit, QTextEdit, 
                           QLabel, QStackedWidget, QTableWidgetItem,
                           QProgressBar, QMessageBox, QFrame, QGraphicsDropShadowEffect,
                           QComboBox, QCheckBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QPropertyAnimation, QEasingCurve, QSize, QPoint, QTimer, QUrl
from PyQt6.QtGui import QColor, QIcon, QPixmap, QFont, QTextCursor, QPalette, QPainter, QPen
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtCore import QThread, QObject, pyqtSignal
import nmap
import socket
import ssl
import requests
import warnings
import re
from OpenSSL import crypto
import urllib3
import socket
import nmap
import ssl
import requests
import json
import threading
import asyncio
import os
import qasync
from telethon import TelegramClient, events
import logging
from datetime import datetime

class TelegramWorker(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.query = ""
        self.client = None
        self.config = {
            'TELEGRAM': {
                'API_ID': '28644438',
                'API_HASH': '4f221e71281bfee6310125010021d2bd',
                'SESSION_NAME': 'antichrist_MAIN',
                'BOT_USERNAME': '@ysxfetx_bot'
            }
        }

    def set_query(self, query):
        self.query = query

    async def init_client(self):
        api_id = int(self.config['TELEGRAM']['API_ID'])
        api_hash = self.config['TELEGRAM']['API_HASH']
        session_name = self.config['TELEGRAM']['SESSION_NAME']
        self.client = TelegramClient(session_name, api_id, api_hash)
        await self.client.start()

    async def search(self):
        try:
            bot_username = self.config['TELEGRAM']['BOT_USERNAME']
            bot_entity = await self.client.get_entity(bot_username)
            
            response_event = asyncio.Future()
            
            @self.client.on(events.NewMessage(from_users=bot_entity))
            async def handle_response(event):
                if not response_event.done():
                    response_event.set_result(event)

            await self.client.send_message(bot_entity, f'/s {self.query}')
            
            response = await asyncio.wait_for(response_event, timeout=220)

            message_text = response.raw_text
            if "🟢 (BACKUP) 1/1 nodes" in message_text and "🔎 0 result(s)" in message_text:
                return "No results found! Please try again later."

            if response.file:
                file_path = await response.download_media()
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                os.remove(file_path)
                return content
            else:
                return message_text
            
        except Exception as e:
            self.error.emit(str(e))
            return None

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            loop.run_until_complete(self.init_client())
            result = loop.run_until_complete(self.search())
            if result:
                self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            loop.close()

class VulnScanWorker(QThread):
    finished = pyqtSignal()
    result = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, target, settings=None):
        super().__init__()
        self.target = target
        self.settings = settings or {}
        self.is_running = True
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def stop(self):
        self.is_running = False

    def run(self):
        try:
            results = []
            
            if self.settings.get('enable_ports', True):
                self.progress.emit("🔍 Starting port scan...")
                port_results = self._custom_port_scan()
                if not self.is_running:
                    return
                results.append("📡 PORT SCAN RESULTS:")
                results.append(port_results)
            
            if self.settings.get('enable_sqli', True):
                self.progress.emit("🔍 Testing SQL injection vulnerabilities...")
                sql_results = self._test_sql_injection()
                if not self.is_running:
                    return
                results.append("\n🔍 SQL INJECTION TEST RESULTS:")
                results.append(sql_results)
            
            if self.settings.get('enable_ssl', True):
                self.progress.emit("🔍 Checking SSL/TLS security...")
                ssl_results = self._check_ssl_security()
                if not self.is_running:
                    return
                results.append("\n🔒 SSL/TLS SECURITY:")
                results.append(ssl_results)
            
            if self.settings.get('enable_web', True):
                self.progress.emit("🔍 Scanning web vulnerabilities...")
                web_results = self._scan_web_vulnerabilities()
                if not self.is_running:
                    return
                results.append("\n🌐 WEB VULNERABILITIES:")
                results.append(web_results)
            
            self.progress.emit("✅ Scan complete!")
            self.result.emit("\n".join(results))
            
        except Exception as e:
            self.result.emit(f"❌ Scan Error: {str(e)}")
        finally:
            self.finished.emit()

    def _custom_port_scan(self):
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    open_ports.append(f"Port {port}: {service} (OPEN)")
                sock.close()
            except:
                continue
        
        return "\n".join(open_ports) if open_ports else "No open ports found."

    def _test_sql_injection(self):
        try:
            results = []
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                for payload in ["'", "''", "`", "``", ",", '"', '""', '/', '//', '\\', '\\\\', ';',
                                "' or '1'='1", "' OR '1'='1", '" OR "1"="1"',
                                "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
                                "' UNION ALL SELECT @@VERSION,SLEEP(1)--",
                                "admin' --", "admin' #", "admin'/*",
                                "' OR '1'='1' --", "' OR 1=1 --", "' OR 1=1#",
                                "') OR ('1'='1'", "') OR ('1'='1'--",
                                "SLEEP(5)--", "WAITFOR DELAY '0:0:5'--",
                                "1; WAITFOR DELAY '0:0:5'--",
                                "' OR pg_sleep(5)--",
                                "' AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)--"
                                ]:
                    if not self.is_running:
                        return "Scan stopped."

                    for protocol in ['http', 'https']:
                        url = f"{protocol}://{self.target}"
                        try:
                            response = requests.get(f"{url}?id={payload}", 
                                                 verify=False, 
                                                 timeout=5,
                                                 headers={'User-Agent': 'Mozilla/5.0'})
                            
                            error_patterns = [
                                "SQL syntax.*MySQL", "Warning.*mysql_.*",
                                "valid MySQL result", "MySqlClient\.",
                                "PostgreSQL.*ERROR", "Warning.*Pg_.*",
                                "valid PostgreSQL result", "Npgsql\.",
                                "Driver.* SQL[-_ ]*Server", "OLE DB.* SQL Server",
                                "SQL Server.*Driver", "Warning.*mssql_.*",
                                "JET Database Engine", "Access Database Engine",
                                "Oracle.*Driver", "Warning.*oci_.*", "Warning.*ora_.*"
                            ]
                            
                            for pattern in error_patterns:
                                if re.search(pattern, response.text, re.IGNORECASE):
                                    results.append(f"⚠️ Potential SQL injection vulnerability found at {url}?id={payload}")
                                    results.append(f"   Pattern matched: {pattern}")
                                    break
                                    
                        except requests.exceptions.RequestException:
                            continue
                            
            return "\n".join(results) if results else "✅ No obvious SQL injection vulnerabilities found."
            
        except Exception as e:
            return f"❌ Error during SQL injection testing: {str(e)}"

    def _check_ssl_security(self):
        try:
            results = []
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                try:
                    hostname = self.target
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((hostname, 443), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert(binary_form=True)
                            x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
                            
                            results.append(f"📜 Certificate Information:")
                            results.append(f"   Issuer: {dict(x509.get_issuer().get_components())}")
                            results.append(f"   Valid From: {x509.get_notBefore().decode()}")
                            results.append(f"   Valid Until: {x509.get_notAfter().decode()}")
                            results.append(f"   Version: {x509.get_version()}")
                            results.append(f"   Serial Number: {x509.get_serial_number()}")
                            results.append(f"\n🔐 SSL/TLS Details:")
                            results.append(f"   Protocol: {ssock.version()}")
                            results.append(f"   Cipher: {ssock.cipher()[0]}")
                            
                except (socket.gaierror, socket.timeout, ConnectionRefusedError):
                    results.append("❌ Could not establish SSL/TLS connection")
                except ssl.SSLError as e:
                    results.append(f"⚠️ SSL Error: {str(e)}")
                    
            return "\n".join(results)
            
        except Exception as e:
            return f"❌ Error during SSL security check: {str(e)}"

    def _scan_web_vulnerabilities(self):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(f"https://{self.target}", headers=headers, timeout=5, verify=False)
            
            vulnerabilities = []
            security_headers = {
                'X-XSS-Protection': 'Missing XSS Protection Header',
                'X-Frame-Options': 'Missing Clickjacking Protection',
                'X-Content-Type-Options': 'Missing MIME-Sniffing Protection',
                'Content-Security-Policy': 'Missing Content Security Policy',
                'Strict-Transport-Security': 'Missing HSTS Header',
                'X-Permitted-Cross-Domain-Policies': 'Missing Cross-Domain Policy Header',
                'Referrer-Policy': 'Missing Referrer Policy',
                'Permissions-Policy': 'Missing Permissions Policy'
            }
            
            for header, message in security_headers.items():
                if header not in response.headers:
                    vulnerabilities.append(message)
            
            return "\n".join(vulnerabilities) if vulnerabilities else "No immediate web vulnerabilities detected."
            
        except Exception as e:
            return f"Web Vulnerability Scan Error: {str(e)}"

class AntichristGUI(QMainWindow):
    update_vuln_results = pyqtSignal(str, name='update_vuln_results')

    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground) 
        self.dragging = False
        self.offset = None
        self.config = {
            'TELEGRAM': {
                'API_ID': '28644438',
                'API_HASH': '4f221e71281bfee6310125010021d2bd',
                'SESSION_NAME': 'antichrist_MAIN',
                'BOT_USERNAME': '@ysxfetx_bot'
            }
        }
        
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        self.main_layout = QHBoxLayout(self.main_widget)
        self.main_layout.setContentsMargins(1, 1, 1, 1)
        self.main_layout.setSpacing(0)
        self.create_side_menu()
        self.content_container = QWidget()
        self.content_layout = QVBoxLayout(self.content_container)
        self.content_layout.setContentsMargins(20, 20, 20, 20)
        self.content_layout.setSpacing(15)
        self.stacked_widget = QStackedWidget()
        self.content_layout.addWidget(self.stacked_widget)
        self.osint_page = QWidget()
        self.osint_layout = QVBoxLayout(self.osint_page)
        self.init_osint_ui()
        self.stacked_widget.addWidget(self.osint_page)
        self.ddos_page = QWidget()
        self.ddos_layout = QVBoxLayout(self.ddos_page)
        self.init_ddos_ui()
        self.stacked_widget.addWidget(self.ddos_page)
        self.dorking_page = QWidget()
        self.dorking_layout = QVBoxLayout(self.dorking_page)
        self.init_dorking_ui()
        self.stacked_widget.addWidget(self.dorking_page)
        self.vuln_scanner_page = QWidget()
        self.vuln_scanner_layout = QVBoxLayout(self.vuln_scanner_page)
        self.init_vuln_scanner_ui()
        self.stacked_widget.addWidget(self.vuln_scanner_page)
        
        self.main_layout.addWidget(self.content_container)
        
        self.worker = TelegramWorker()
        self.worker.finished.connect(self.handle_search_result)
        self.worker.error.connect(self.handle_error)
        self.worker.progress.connect(self.update_status)
        self.update_vuln_results.connect(self.update_vuln_scan_results)
        
        self._drag_pos = None
        self._window_state = 'normal'

    def create_side_menu(self):
        self.side_menu = QWidget()
        self.side_menu.setFixedWidth(200)
        self.side_menu_expanded = True
        self.side_menu.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QPushButton {
                text-align: left;
                padding: 10px;
                border: none;
                border-radius: 5px;
                margin: 2px 10px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #2d2d2d;
            }
            QPushButton#selected {
                background-color: #363636;
            }
        """)
        
        side_menu_layout = QVBoxLayout(self.side_menu)
        side_menu_layout.setContentsMargins(0, 10, 0, 10)
        side_menu_layout.setSpacing(5)

        title = QLabel("ANTICHRIST")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 20px; font-weight: bold; margin: 20px 0;")
        side_menu_layout.addWidget(title)

        self.osint_btn = QPushButton("OSINT")
        self.osint_btn.setObjectName("selected")
        self.osint_btn.clicked.connect(lambda: self.switch_page(0))
        
        self.ddos_btn = QPushButton("DDoS")
        self.ddos_btn.clicked.connect(lambda: self.switch_page(1))
        
        self.dorking_btn = QPushButton("Dorking")
        self.dorking_btn.clicked.connect(lambda: self.switch_page(2))
        
        self.vuln_scanner_btn = QPushButton("Scanner")
        self.vuln_scanner_btn.clicked.connect(lambda: self.switch_page(3))
        
        side_menu_layout.addWidget(self.osint_btn)
        side_menu_layout.addWidget(self.ddos_btn)
        side_menu_layout.addWidget(self.dorking_btn)
        side_menu_layout.addWidget(self.vuln_scanner_btn)
        side_menu_layout.addStretch()
        
        self.main_layout.addWidget(self.side_menu)

    def switch_page(self, index):
        self.stacked_widget.setCurrentIndex(index)
        
        self.osint_btn.setObjectName("" if index != 0 else "selected")
        self.ddos_btn.setObjectName("" if index != 1 else "selected")
        self.dorking_btn.setObjectName("" if index != 2 else "selected")
        self.vuln_scanner_btn.setObjectName("" if index != 3 else "selected")
        self.osint_btn.style().unpolish(self.osint_btn)
        self.osint_btn.style().polish(self.osint_btn)
        self.ddos_btn.style().unpolish(self.ddos_btn)
        self.ddos_btn.style().polish(self.ddos_btn)
        self.dorking_btn.style().unpolish(self.dorking_btn)
        self.dorking_btn.style().polish(self.dorking_btn)
        self.vuln_scanner_btn.style().unpolish(self.vuln_scanner_btn)
        self.vuln_scanner_btn.style().polish(self.vuln_scanner_btn)

    def init_osint_ui(self):
        self.create_title_bar()
        self.init_ui()
        
    def init_ddos_ui(self):
        self.ddos_stack = QStackedWidget()
        self.ddos_layout.addWidget(self.ddos_stack)
        self.ddos_layout.setContentsMargins(0, 0, 0, 0)
        self.ddos_layout.setSpacing(0)
        selection_page = QWidget()
        selection_layout = QVBoxLayout(selection_page)
        selection_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        button_style = """
            QPushButton {
                background-color: #1e1e1e;
                border: 2px solid #ff3333;
                border-radius: 10px;
                color: white;
                padding: 20px;
                font-size: 18px;
                min-width: 300px;
                margin: 10px;
            }
            QPushButton:hover {
                background-color: #ff3333;
            }
        """
        shadow_hook_btn = QPushButton("ShadowHook - thiasoft.com")
        shadow_hook_btn.setStyleSheet(button_style)
        shadow_hook_btn.clicked.connect(lambda: self.load_stresser("https://thiasoft.com"))

        quez_btn = QPushButton("Quez - quezstresser.ru")
        quez_btn.setStyleSheet(button_style)
        quez_btn.clicked.connect(lambda: self.load_stresser("https://quezstresser.ru"))
        selection_layout.addWidget(shadow_hook_btn)
        selection_layout.addWidget(quez_btn)
        web_page = QWidget()
        web_layout = QVBoxLayout(web_page)
        web_layout.setContentsMargins(0, 0, 0, 0)
        back_container = QWidget()
        back_container.setFixedHeight(40)
        back_container.setStyleSheet("background-color: #1e1e1e;")
        back_layout = QHBoxLayout(back_container)
        back_layout.setContentsMargins(10, 0, 10, 0)
        
        back_btn = QPushButton("← Back")
        back_btn.setFixedWidth(100)
        back_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff3333;
                border: none;
                border-radius: 5px;
                color: white;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #ff4444;
            }
        """)
        back_btn.clicked.connect(lambda: self.ddos_stack.setCurrentIndex(0))
        
        back_layout.addWidget(back_btn)
        back_layout.addStretch()
        self.web_view = QWebEngineView()

        self.red_shader_js = """
        (function() {
            var style = document.createElement('style');
            style.innerHTML = `
                html {
                    filter: saturate(150%) hue-rotate(-20deg) contrast(110%) !important;
                }
                body::before {
                    content: '';
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(255, 0, 0, 0.1);
                    pointer-events: none;
                    z-index: 9999;
                    mix-blend-mode: multiply;
                }
            `;
            document.head.appendChild(style);
        })();
        """
        
        self.web_view.loadFinished.connect(lambda: self.web_view.page().runJavaScript(self.red_shader_js))
        
        web_layout.addWidget(back_container)
        web_layout.addWidget(self.web_view)
        self.ddos_stack.addWidget(selection_page)
        self.ddos_stack.addWidget(web_page)
        self.ddos_stack.setCurrentIndex(0)

    def load_stresser(self, url):
        self.web_view.setUrl(QUrl(url))
        replace_text_js = """
        (function() {
            function replaceText() {
                const targetText = document.evaluate(
                    "//h2[contains(text(), 'Quez-Approved IP Stressers')]",
                    document,
                    null,
                    XPathResult.FIRST_ORDERED_NODE_TYPE,
                    null
                ).singleNodeValue;

                if (targetText) {
                    targetText.textContent = 'ANTICHRIST';
                }

                const paragraphs = document.evaluate(
                    "//p[contains(text(), 'Nearly all IP booters') or contains(text(), 'IPStresser.su') or contains(text(), 'Nightmarestresser.net') or contains(text(), 'Stresse.ru') or contains(text(), 'DarkVR.io') or contains(text(), 'Tresser.io') or contains(text(), 'Stresserst.su')]",
                    document,
                    null,
                    XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,
                    null
                );

                for (let i = 0; i < paragraphs.snapshotLength; i++) {
                    paragraphs.snapshotItem(i).textContent = 'ANTICHRIST';
                }
            }

            // Run initially and set up an observer to handle dynamic content
            replaceText();
            const observer = new MutationObserver(replaceText);
            observer.observe(document.body, { 
                childList: true, 
                subtree: true 
            });
        })();
        """
        
        def inject_js():
            if "quezstresser.ru" in url:
                self.web_view.page().runJavaScript(replace_text_js)
            self.web_view.page().runJavaScript(self.red_shader_js)
        
        self.web_view.loadFinished.connect(inject_js)
        self.ddos_stack.setCurrentIndex(1)

    def init_dorking_ui(self):
        dorking_container = QWidget()
        dorking_main_layout = QVBoxLayout(dorking_container)
        dork_builder = QWidget()
        dork_builder_layout = QVBoxLayout(dork_builder)
        dork_builder_layout.setSpacing(10)
        title_label = QLabel("DORK BUILDER")
        title_label.setStyleSheet("""
            QLabel {
                color: #ff3333;
                font-size: 18px;
                font-weight: bold;
                padding: 5px;
            }
        """)
        dork_builder_layout.addWidget(title_label)
        operators_grid = QWidget()
        operators_layout = QHBoxLayout(operators_grid)
        operators_layout.setSpacing(5)
        
        operators = [
            ("site:", "Site/Domain"),
            ("inurl:", "In URL"),
            ("intitle:", "In Title"),
            ("intext:", "In Text"),
            ("filetype:", "File Type"),
            ("ext:", "Extension")
        ]
        
        for operator, tooltip in operators:
            op_btn = QPushButton(operator)
            op_btn.setToolTip(tooltip)
            op_btn.clicked.connect(lambda x, op=operator: self.add_dork_operator(op))
            op_btn.setStyleSheet("""
                QPushButton {
                    background-color: #2b2b2b;
                    border: 1px solid #ff3333;
                    border-radius: 3px;
                    color: #ff3333;
                    padding: 5px 10px;
                    font-size: 12px;
                }
                QPushButton:hover {
                    background-color: #ff3333;
                    color: white;
                }
            """)
            operators_layout.addWidget(op_btn)
        
        dork_builder_layout.addWidget(operators_grid)

        advanced_grid = QWidget()
        advanced_layout = QHBoxLayout(advanced_grid)
        advanced_layout.setSpacing(5)
        
        advanced_operators = [
            ("AND", "Match all terms"),
            ("OR", "Match any terms"),
            ("-", "Exclude term"),
            ("\"\"", "Exact match"),
            ("( )", "Group terms")
        ]
        
        for operator, tooltip in advanced_operators:
            op_btn = QPushButton(operator)
            op_btn.setToolTip(tooltip)
            op_btn.clicked.connect(lambda x, op=operator: self.add_dork_operator(op))
            op_btn.setStyleSheet("""
                QPushButton {
                    background-color: #2b2b2b;
                    border: 1px solid #404040;
                    border-radius: 3px;
                    color: #808080;
                    padding: 5px 10px;
                    font-size: 12px;
                }
                QPushButton:hover {
                    background-color: #404040;
                    color: white;
                }
            """)
            advanced_layout.addWidget(op_btn)
        
        dork_builder_layout.addWidget(advanced_grid)
        self.dork_input = QTextEdit()
        self.dork_input.setPlaceholderText("Build your dork query here...")
        self.dork_input.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                border: 1px solid #404040;
                border-radius: 5px;
                color: #ff3333;
                padding: 10px;
                font-family: 'Consolas', monospace;
                font-size: 14px;
                min-height: 100px;
            }
        """)
        dork_builder_layout.addWidget(self.dork_input)
        templates_widget = QWidget()
        templates_layout = QVBoxLayout(templates_widget)
        
        templates_label = QLabel("QUICK TEMPLATES")
        templates_label.setStyleSheet("""
            QLabel {
                color: #ff3333;
                font-size: 14px;
                font-weight: bold;
                padding: 5px;
            }
        """)
        templates_layout.addWidget(templates_label)
        
        templates = [
            ("SQL Injection", "intext:\"sql syntax near\" | intext:\"syntax error has occurred\" | intext:\"incorrect syntax near\" | intext:\"unexpected end of SQL command\" | intext:\"Warning: mysql_connect()\" | intext:\"Warning: mysql_query()\" | intext:\"Warning: pg_connect()\""),
            ("Config Files", "ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini | ext:env"),
            ("Login Pages", "inurl:admin | inurl:login | inurl:adminpage | inurl:adminpanel"),
            ("Exposed Databases", "ext:sql | ext:dbf | ext:mdb | ext:db"),
            ("Password Files", "intext:\"password\" ext:txt | ext:csv | ext:log | ext:sql | ext:env")
        ]
        
        for name, dork in templates:
            template_btn = QPushButton(name)
            template_btn.setToolTip(dork)
            template_btn.clicked.connect(lambda x, d=dork: self.load_template(d))
            template_btn.setStyleSheet("""
                QPushButton {
                    background-color: #2b2b2b;
                    border: 1px solid #404040;
                    border-radius: 3px;
                    color: #808080;
                    padding: 5px 10px;
                    font-size: 12px;
                    text-align: left;
                }
                QPushButton:hover {
                    background-color: #404040;
                    color: white;
                }
            """)
            templates_layout.addWidget(template_btn)
        
        dork_builder_layout.addWidget(templates_widget)
        search_controls = QWidget()
        search_layout = QHBoxLayout(search_controls)
        
        engines = ["Google", "Bing", "DuckDuckGo", "Yandex"]
        self.engine_combo = QComboBox()
        self.engine_combo.addItems(engines)
        self.engine_combo.setStyleSheet("""
            QComboBox {
                background-color: #2b2b2b;
                border: 1px solid #404040;
                border-radius: 3px;
                color: white;
                padding: 5px;
                min-width: 100px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #ff3333;
                margin-right: 5px;
            }
        """)
        
        search_button = QPushButton("Search")
        search_button.clicked.connect(self.execute_dork)
        search_button.setStyleSheet("""
            QPushButton {
                background-color: #ff3333;
                border: none;
                border-radius: 3px;
                color: white;
                padding: 8px 20px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #ff4444;
            }
            QPushButton:pressed {
                background-color: #cc2929;
            }
        """)
        
        save_button = QPushButton("Save Dork")
        save_button.clicked.connect(self.save_dork)
        save_button.setStyleSheet("""
            QPushButton {
                background-color: #2b2b2b;
                border: 1px solid #404040;
                border-radius: 3px;
                color: white;
                padding: 8px 20px;
            }
            QPushButton:hover {
                background-color: #404040;
            }
        """)
        
        search_layout.addWidget(self.engine_combo)
        search_layout.addWidget(save_button)
        search_layout.addWidget(search_button)
        dorking_main_layout.addWidget(dork_builder)
        self.dorking_layout.addWidget(dorking_container)
        
    def add_dork_operator(self, operator):
        cursor = self.dork_input.textCursor()
        if operator in ["\"\"", "( )"]:
            cursor.insertText(operator)
            cursor.movePosition(cursor.Left, cursor.MoveAnchor, 1)
        else:
            cursor.insertText(operator + " ")
        self.dork_input.setFocus()
        
    def load_template(self, dork):
        self.dork_input.setText(dork)
        
    def save_dork(self):
        dork = self.dork_input.toPlainText()
        if not dork:
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"saved_dorks_{timestamp}.txt"
        
        try:
            with open(filename, "w") as f:
                f.write(dork)
            QMessageBox.information(self, "Success", f"Dork saved to {filename}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save dork: {str(e)}")
            
    def execute_dork(self):
        dork = self.dork_input.toPlainText()
        if not dork:
            QMessageBox.warning(self, "Warning", "Please enter a dork query")
            return
            
        engine = self.engine_combo.currentText().lower()
        base_urls = {
            "google": "https://www.google.com/search?q=",
            "bing": "https://www.bing.com/search?q=",
            "duckduckgo": "https://duckduckgo.com/?q=",
            "yandex": "https://yandex.com/search/?text="
        }
        
        url = base_urls[engine] + dork.replace(" ", "+")
        QDesktopServices.openUrl(QUrl(url))
        
    def toggle_side_menu(self):
        width = self.side_menu.width()
        new_width = 60 if self.side_menu_expanded else 200
        
        self.animation = QPropertyAnimation(self.side_menu, b"minimumWidth")
        self.animation.setDuration(200)
        self.animation.setStartValue(width)
        self.animation.setEndValue(new_width)
        self.animation.setEasingCurve(QEasingCurve.Type.InOutQuart)
        self.animation.start()
        
        self.side_menu_expanded = not self.side_menu_expanded
        
        # Update button visibility
        if self.side_menu_expanded:
            self.osint_btn.setText("OSINT")
            self.ddos_btn.setText("DDoS")
            self.dorking_btn.setText("Dorking")
            self.vuln_scanner_btn.setText("Scanner")
        else:
            self.osint_btn.setText("O")
            self.ddos_btn.setText("D")
            self.dorking_btn.setText("D")
            self.vuln_scanner_btn.setText("V")
            
    def create_title_bar(self):
        self.title_bar = QWidget()
        self.title_bar.setFixedHeight(35)
        title_bar_layout = QHBoxLayout(self.title_bar)
        title_bar_layout.setContentsMargins(6, 0, 6, 0)
        title_bar_layout.setSpacing(4)
        
        title_label = QLabel("ANTICHRIST-PREMIUM")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("""
            QLabel {
                color: #ffffff;
                font-size: 13px;
                font-weight: bold;
                padding-left: 8px;
            }
        """)
        
        control_buttons = QWidget()
        control_buttons_layout = QHBoxLayout(control_buttons)
        control_buttons_layout.setContentsMargins(0, 0, 0, 0)
        control_buttons_layout.setSpacing(4)
        
        self.min_button = QPushButton()
        self.min_button.setFixedSize(16, 16)
        self.min_button.clicked.connect(self.showMinimized)
        self.min_button.setObjectName("min_button")
        
        self.max_button = QPushButton()
        self.max_button.setFixedSize(16, 16)
        self.max_button.clicked.connect(self.toggle_maximize)
        self.max_button.setObjectName("max_button")
        
        self.close_button = QPushButton()
        self.close_button.setFixedSize(16, 16)
        self.close_button.clicked.connect(self.close)
        self.close_button.setObjectName("close_button")
        
        control_buttons_layout.addWidget(self.min_button)
        control_buttons_layout.addWidget(self.max_button)
        control_buttons_layout.addWidget(self.close_button)
        
        title_bar_layout.addWidget(title_label)
        title_bar_layout.addStretch()
        title_bar_layout.addWidget(control_buttons)
        
        self.title_bar.setStyleSheet("""
            QWidget {
                background: #2b2b2b;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
            }
            QPushButton {
                border: none;
                border-radius: 8px;
                margin: 4px;
            }
            #close_button {
                background: #ff5f57;
            }
            #close_button:hover {
                background: #ff7369;
            }
            #min_button {
                background: #ffbd2e;
            }
            #min_button:hover {
                background: #ffc641;
            }
            #max_button {
                background: #28c940;
            }
            #max_button:hover {
                background: #39d353;
            }
        """)
        
        self.osint_layout.addWidget(self.title_bar)

    def title_bar_mouse_press(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = event.globalPosition().toPoint()
            event.accept()

    def title_bar_mouse_move(self, event):
        if event.buttons() == Qt.MouseButton.LeftButton and self._drag_pos is not None:
            new_pos = event.globalPosition().toPoint()
            delta = new_pos - self._drag_pos
            self.move(self.pos() + delta)
            self._drag_pos = new_pos
            event.accept()

    def title_bar_double_click(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.toggle_maximize()

    def toggle_maximize(self):
        if self._window_state == 'normal':
            self.showMaximized()
            self._window_state = 'maximized'
            self.osint_layout.setContentsMargins(0, 0, 0, 0)
            self.title_bar.setStyleSheet(self.title_bar.styleSheet().replace('border-radius: 8px', 'border-radius: 0'))
        else:
            self.showNormal()
            self._window_state = 'normal'
            self.osint_layout.setContentsMargins(20, 20, 20, 20)
            self.title_bar.setStyleSheet(self.title_bar.styleSheet().replace('border-radius: 0', 'border-radius: 8px'))

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        if self._window_state == 'normal':
            pen = QPen(QColor('#3f3f3f'))
            pen.setWidth(2)
            painter.setPen(pen)
            painter.setBrush(QColor('#2b2b2b'))
            painter.drawRoundedRect(self.rect().adjusted(1, 1, -1, -1), 8, 8)
        else:
            pen = QPen(QColor('#3f3f3f'))
            pen.setWidth(1)
            painter.setPen(pen)
            painter.setBrush(QColor('#2b2b2b'))
            painter.drawRect(self.rect())

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.dragging = True
            self.offset = event.pos()

    def mouseMoveEvent(self, event):
        if self.dragging and self.offset:
            new_pos = event.globalPosition().toPoint() - self.offset
            self.move(new_pos)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.dragging = False
            self.offset = None

    def init_ui(self):
        self.setWindowTitle('ANTICHRIST-PREMIUM')
        self.setStyleSheet("""
            QMainWindow {
                background: transparent;
            }
            QWidget {
                color: white;
            }
            
            /* Scrollbar Styling */
            QScrollBar:vertical {
                border: none;
                background: rgba(40, 40, 40, 0.7);
                width: 10px;
                margin: 0;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical {
                background: rgba(255, 51, 51, 0.5);
                min-height: 30px;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical:hover {
                background: rgba(255, 71, 71, 0.7);
            }
            QScrollBar::handle:vertical:pressed {
                background: rgba(255, 51, 51, 0.8);
            }
            QScrollBar::add-line:vertical {
                height: 0px;
            }
            QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: none;
            }
            
            /* Horizontal Scrollbar */
            QScrollBar:horizontal {
                border: none;
                background: rgba(40, 40, 40, 0.7);
                height: 10px;
                margin: 0;
                border-radius: 5px;
            }
            QScrollBar::handle:horizontal {
                background: rgba(255, 51, 51, 0.5);
                min-width: 30px;
                border-radius: 5px;
            }
            QScrollBar::handle:horizontal:hover {
                background: rgba(255, 71, 71, 0.7);
            }
            QScrollBar::handle:horizontal:pressed {
                background: rgba(255, 51, 51, 0.8);
            }
            QScrollBar::add-line:horizontal {
                width: 0px;
            }
            QScrollBar::sub-line:horizontal {
                width: 0px;
            }
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
                background: none;
            }
            
            QPushButton {
                background: rgba(255, 51, 51, 0.8);
                border: 1px solid rgba(255, 255, 255, 0.1);
                padding: 12px 25px;
                border-radius: 8px;
                color: white;
                font-weight: bold;
                font-size: 13px;
                transition: all 0.3s ease;
            }
            QPushButton:hover {
                background: rgba(255, 71, 71, 0.9);
                border: 1px solid rgba(255, 255, 255, 0.2);
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(255, 51, 51, 0.3);
            }
            QPushButton:pressed {
                background: rgba(235, 31, 31, 0.8);
                transform: translateY(1px);
                box-shadow: 0 2px 5px rgba(255, 51, 51, 0.2);
            }
            QLineEdit {
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                padding: 10px 15px;
                color: white;
                font-size: 14px;
            }
            QLineEdit:hover {
                background: rgba(255, 255, 255, 0.08);
                border: 1px solid rgba(255, 255, 255, 0.2);
            }
            QLineEdit:focus {
                background: rgba(255, 255, 255, 0.1);
                border: 1px solid rgba(255, 51, 51, 0.4);
                box-shadow: 0 0 10px rgba(255, 51, 51, 0.2);
            }
            QTextEdit {
                background: rgba(30, 30, 30, 0.7);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 15px;
                color: white;
                font-size: 13px;
            }
            QTextEdit:hover {
                background: rgba(35, 35, 35, 0.75);
                border: 1px solid rgba(255, 255, 255, 0.15);
            }
            QProgressBar {
                background: rgba(255, 255, 255, 0.1);
                border: none;
                border-radius: 7px;
                height: 14px;
                text-align: center;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(255, 51, 51, 0.8),
                    stop:1 rgba(255, 102, 102, 0.8));
                border-radius: 7px;
            }
        """)
        
        title = QLabel("ANTICHRIST")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("""
            font-size: 32px;
            color: #ff3333;
            background: transparent;
            font-weight: 800;
            margin: 25px;
            letter-spacing: 5px;
            text-shadow: 2px 2px 15px rgba(255, 51, 51, 0.4),
                         -2px -2px 15px rgba(255, 51, 51, 0.4),
                         0 0 30px rgba(255, 102, 102, 0.6);
            animation: glow 3s infinite ease-in-out;
        }
        @keyframes glow {
            0% { text-shadow: 2px 2px 15px rgba(255, 51, 51, 0.4),
                             -2px -2px 15px rgba(255, 51, 51, 0.4),
                             0 0 30px rgba(255, 102, 102, 0.6); }
            50% { text-shadow: 2px 2px 20px rgba(255, 51, 51, 0.6),
                              -2px -2px 20px rgba(255, 51, 51, 0.6),
                              0 0 40px rgba(255, 102, 102, 0.8); }
            100% { text-shadow: 2px 2px 15px rgba(255, 51, 51, 0.4),
                               -2px -2px 15px rgba(255, 51, 51, 0.4),
                               0 0 30px rgba(255, 102, 102, 0.6); }
        }
        """)
        self.osint_layout.addWidget(title)
        
        search_container = QFrame()
        search_container.setStyleSheet("""
            QFrame {
                background: rgba(30, 30, 30, 0.6);
                border-radius: 15px;
                border: 1px solid rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(10px);
            }
            QFrame:hover {
                background: rgba(35, 35, 35, 0.65);
                border: 1px solid rgba(255, 255, 255, 0.15);
                box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
            }
        """)
        search_layout = QHBoxLayout(search_container)
        search_layout.setContentsMargins(20, 10, 20, 10)
        search_layout.setSpacing(15)
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter your search query...")
        self.search_input.setFixedHeight(38)
        self.search_input.setCursor(Qt.CursorShape.IBeamCursor)
        self.search_input.setStyleSheet("""
            QLineEdit {
                background: rgba(30, 30, 30, 0.7);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                padding: 4px 15px 6px 15px;
                font-size: 14px;
                color: #ffffff;
                font-family: 'Segoe UI', Arial;
                line-height: 28px;
                qproperty-alignment: AlignVCenter;
            }
            QLineEdit:hover {
                background: rgba(35, 35, 35, 0.8);
                border: 1px solid rgba(255, 255, 255, 0.15);
            }
            QLineEdit:focus {
                background: rgba(40, 40, 40, 0.9);
                border: 1px solid rgba(255, 51, 51, 0.4);
                box-shadow: 0 0 15px rgba(255, 51, 51, 0.2);
            }
            QLineEdit::placeholder {
                color: rgba(255, 255, 255, 0.4);
                font-style: italic;
            }
        """)
        self.search_input.returnPressed.connect(self.start_search)
        
        self.search_button = QPushButton("Search")
        self.search_button.setMinimumHeight(35)
        self.search_button.setCursor(Qt.CursorShape.ArrowCursor)
        self.search_button.clicked.connect(self.start_search)
        self.search_button.setStyleSheet("""
            QPushButton {
                background: rgba(255, 51, 51, 0.8);
                border: 1px solid rgba(255, 255, 255, 0.1);
                padding: 8px 20px;
                border-radius: 8px;
                color: white;
                font-weight: bold;
                font-size: 13px;
                transition: all 0.3s ease;
            }
            QPushButton:hover {
                background: rgba(255, 71, 71, 0.9);
                border: 1px solid rgba(255, 255, 255, 0.2);
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(255, 51, 51, 0.3);
            }
            QPushButton:pressed {
                background: rgba(235, 31, 31, 0.8);
                transform: translateY(1px);
                box-shadow: 0 2px 5px rgba(255, 51, 51, 0.2);
            }
        """)
        
        search_layout.addWidget(self.search_input)
        search_layout.addWidget(self.search_button)
        
        self.osint_layout.addWidget(search_container)
        
        results_container = QWidget()
        results_container.setStyleSheet("""
            QWidget {
                background-color: rgba(30, 30, 30, 0.7);
                border-radius: 15px;
                border: 1px solid rgba(255, 255, 255, 0.1);
            }
            QWidget:hover {
                background-color: rgba(35, 35, 35, 0.75);
                border: 1px solid rgba(255, 255, 255, 0.15);
            }
        """)
        results_layout = QVBoxLayout(results_container)
        results_layout.setContentsMargins(15, 15, 15, 15)
        
        self.results_area = QTextEdit()
        self.results_area.setReadOnly(True)
        self.results_area.setCursor(Qt.CursorShape.IBeamCursor)
        self.results_area.setStyleSheet("""
            QTextEdit {
                background: rgba(30, 30, 30, 0.7);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 15px;
                color: white;
                font-size: 13px;
            }
            QTextEdit:hover {
                background: rgba(35, 35, 35, 0.75);
                border: 1px solid rgba(255, 255, 255, 0.15);
            }
        """)
        results_layout.addWidget(self.results_area)
        
        self.osint_layout.addWidget(results_container, 1)
        
        status_container = QWidget()
        status_container.setStyleSheet("""
            QWidget {
                background-color: rgba(30, 30, 30, 0.7);
                border-radius: 12px;
                border: 1px solid rgba(255, 255, 255, 0.1);
            }
            QWidget:hover {
                background-color: rgba(35, 35, 35, 0.75);
                border: 1px solid rgba(255, 255, 255, 0.15);
            }
        """)
        status_layout = QVBoxLayout(status_container)
        status_layout.setContentsMargins(15, 10, 15, 10)
        
        self.status_bar = QProgressBar()
        self.status_bar.setTextVisible(True)
        self.status_bar.setFormat("")
        self.status_bar.setMinimumHeight(28)
        self.status_bar.setMaximumHeight(28)
        self.status_bar.setCursor(Qt.CursorShape.ArrowCursor)
        self.status_bar.setStyleSheet("""
            QProgressBar {
                background: rgba(255, 255, 255, 0.1);
                border: none;
                border-radius: 7px;
                height: 14px;
                text-align: center;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(255, 51, 51, 0.8),
                    stop:1 rgba(255, 102, 102, 0.8));
                border-radius: 7px;
            }
        """)
        status_layout.addWidget(self.status_bar)
        
        self.osint_layout.addWidget(status_container)
        
        self.setMinimumSize(900, 700)
        self.center_window()

    def center_window(self):
        screen = QApplication.primaryScreen().geometry()
        size = self.geometry()
        self.move(
            (screen.width() - size.width()) // 2,
            (screen.height() - size.height()) // 2
        )

    def start_search(self):
        query = self.search_input.text().strip()
        if not query:
            QMessageBox.warning(self, "Warning", "Please enter a search query")
            return
        
        self.results_area.clear()
        self.status_bar.setFormat("Searching...")
        self.status_bar.setRange(0, 0)
        self.search_button.setEnabled(False)
        self.search_input.setEnabled(False)
        
        self.worker.set_query(query)
        self.worker.start()

    def handle_search_result(self, result):
        if not result:
            self.status_bar.setFormat("No results found")
            self.search_button.setEnabled(True)
            self.search_input.setEnabled(True)
            return
            
        self.results_area.clear()
        self.results_area.append(result)
        self.status_bar.setRange(0, 100)
        self.status_bar.setValue(100)
        self.status_bar.setFormat("Search completed")
        self.search_button.setEnabled(True)
        self.search_input.setEnabled(True)

    def handle_error(self, error_msg):
        QMessageBox.critical(self, "Error", error_msg)
        self.status_bar.setRange(0, 100)
        self.status_bar.setValue(0)
        self.status_bar.setFormat("Error occurred")
        self.search_button.setEnabled(True)
        self.search_input.setEnabled(True)

    def update_status(self, message):
        self.status_bar.setFormat(message)

    def init_vuln_scanner_ui(self):
        vuln_scanner_container = QWidget()
        vuln_scanner_main_layout = QVBoxLayout(vuln_scanner_container)
        vuln_scanner = QWidget()
        vuln_scanner_layout = QVBoxLayout(vuln_scanner)
        vuln_scanner_layout.setSpacing(10)
        title_label = QLabel("Vulnerability Scanner")
        title_label.setStyleSheet("""
            QLabel {
                color: #ff3333;
                font-size: 18px;
                font-weight: bold;
                padding: 5px;
            }
        """)
        vuln_scanner_layout.addWidget(title_label)
        self.vuln_input = QLineEdit()
        self.vuln_input.setPlaceholderText("Enter IP address or domain...")
        self.vuln_input.setStyleSheet("""
            QLineEdit {
                background: rgba(30, 30, 30, 0.7);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                padding: 10px 15px;
                color: white;
                font-size: 14px;
            }
            QLineEdit:hover {
                background: rgba(35, 35, 35, 0.8);
                border: 1px solid rgba(255, 255, 255, 0.15);
            }
            QLineEdit:focus {
                background: rgba(40, 40, 40, 0.9);
                border: 1px solid rgba(255, 51, 51, 0.4);
                box-shadow: 0 0 15px rgba(255, 51, 51, 0.2);
            }
            QLineEdit::placeholder {
                color: rgba(255, 255, 255, 0.4);
                font-style: italic;
            }
        """)
        vuln_scanner_layout.addWidget(self.vuln_input)
        settings_panel = QWidget()
        settings_layout = QVBoxLayout(settings_panel)
        settings_layout.setSpacing(10)
        
        settings_label = QLabel("Scanner Settings")
        settings_label.setStyleSheet("""
            QLabel {
                color: #ff3333;
                font-size: 16px;
                font-weight: bold;
                padding: 5px;
            }
        """)
        settings_layout.addWidget(settings_label)
        self.enable_ports = QCheckBox("Enable Port Scanner")
        self.enable_sqli = QCheckBox("Enable SQL Injection Tests")
        self.enable_ssl = QCheckBox("Enable SSL/TLS Check")
        self.enable_web = QCheckBox("Enable Web Vulnerability Scan")
        for checkbox in [self.enable_ports, self.enable_sqli, self.enable_ssl, self.enable_web]:
            checkbox.setChecked(True)
            checkbox.setStyleSheet("""
                QCheckBox {
                    color: #ffffff;
                    spacing: 8px;
                }
                QCheckBox::indicator {
                    width: 18px;
                    height: 18px;
                    border: 2px solid #ff3333;
                    border-radius: 4px;
                    background: rgba(43, 43, 43, 0.7);
                }
                QCheckBox::indicator:checked {
                    background: #ff3333;
                }
            """)
            settings_layout.addWidget(checkbox)
        
        settings_panel.setStyleSheet("""
            QWidget {
                background: rgba(43, 43, 43, 0.7);
                border: 1px solid rgba(255, 51, 51, 0.3);
                border-radius: 10px;
                padding: 15px;
            }
        """)
        
        vuln_scanner_layout.addWidget(settings_panel)
        self.vuln_scan_button = QPushButton("Scan")
        self.vuln_scan_button.clicked.connect(self.scan_vuln)
        self.vuln_scan_button.setStyleSheet("""
            QPushButton {
                background: rgba(255, 51, 51, 0.8);
                border: 1px solid rgba(255, 255, 255, 0.1);
                padding: 8px 20px;
                border-radius: 8px;
                color: white;
                font-weight: bold;
                font-size: 13px;
                transition: all 0.3s ease;
            }
            QPushButton:hover {
                background: rgba(255, 71, 71, 0.9);
                border: 1px solid rgba(255, 255, 255, 0.2);
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(255, 51, 51, 0.3);
            }
            QPushButton:pressed {
                background: rgba(235, 31, 31, 0.8);
                transform: translateY(1px);
                box-shadow: 0 2px 5px rgba(255, 51, 51, 0.2);
            }
        """)
        vuln_scanner_layout.addWidget(self.vuln_scan_button)
        self.vuln_results = QTextEdit()
        self.vuln_results.setReadOnly(True)
        self.vuln_results.setStyleSheet("""
            QTextEdit {
                background: rgba(30, 30, 30, 0.7);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 15px;
                color: white;
                font-size: 13px;
            }
            QTextEdit:hover {
                background: rgba(35, 35, 35, 0.75);
                border: 1px solid rgba(255, 255, 255, 0.15);
            }
        """)
        vuln_scanner_layout.addWidget(self.vuln_results)
        vuln_scanner_main_layout.addWidget(vuln_scanner)
        self.vuln_scanner_layout.addWidget(vuln_scanner_container)

    def scan_vuln(self):
        ip = self.vuln_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "Warning", "Please enter an IP address or domain")
            return
        
        settings = {
            'enable_ports': self.enable_ports.isChecked(),
            'enable_sqli': self.enable_sqli.isChecked(),
            'enable_ssl': self.enable_ssl.isChecked(),
            'enable_web': self.enable_web.isChecked()
        }
        self.vuln_results.clear()
        self.vuln_results.append("🔄 Initializing vulnerability scan...")
        self.vuln_scan_button.setEnabled(False)
        self.vuln_thread = QThread()
        self.vuln_worker = VulnScanWorker(ip, settings)
        self.vuln_worker.moveToThread(self.vuln_thread)
        self.vuln_thread.started.connect(self.vuln_worker.run)
        self.vuln_worker.finished.connect(self.scan_completed)
        self.vuln_worker.finished.connect(self.vuln_worker.deleteLater)
        self.vuln_thread.finished.connect(self.vuln_thread.deleteLater)
        self.vuln_worker.result.connect(self.update_vuln_scan_results)
        self.vuln_worker.progress.connect(self.update_scan_progress)
        self.vuln_thread.start()

    def scan_completed(self):
        self.vuln_scan_button.setEnabled(True)
        if self.vuln_thread:
            self.vuln_thread.quit()
            self.vuln_thread.wait()
            self.vuln_thread = None
            self.vuln_worker = None

    def update_scan_progress(self, message):
        self.vuln_results.append(message)

    def update_vuln_scan_results(self, results):
        self.vuln_results.clear()
        self.vuln_results.append(results)

class SplashScreen(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(500, 300)
        
        screen = QApplication.primaryScreen().geometry()
        self.move(
            (screen.width() - self.width()) // 2,
            (screen.height() - self.height()) // 2
        )
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(0)
        
        container = QFrame()
        container.setObjectName("container")
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(20, 20, 20, 20)
        container_layout.setSpacing(10)
        
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 100))
        shadow.setOffset(0, 0)
        container.setGraphicsEffect(shadow)
        
        title_label = QLabel("Antichrist")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setObjectName("title")
        
        subtitle_label = QLabel("Pentest Framework")
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle_label.setObjectName("subtitle")
        
        self.loading_progress = QProgressBar()
        self.loading_progress.setObjectName("loading")
        self.loading_progress.setTextVisible(False)
        self.loading_progress.setFixedHeight(4)
        
        self.loading_label = QLabel("Starting...")
        self.loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.loading_label.setObjectName("loading_text")
        
        container_layout.addStretch()
        container_layout.addWidget(title_label)
        container_layout.addWidget(subtitle_label)
        container_layout.addStretch()
        container_layout.addWidget(self.loading_progress)
        container_layout.addWidget(self.loading_label)
        
        layout.addWidget(container)
        
        self.setStyleSheet("""
            QFrame#container {
                background-color: #2b2b2b;
                border-radius: 10px;
            }
            QLabel#title {
                color: #ffffff;
                font-size: 36px;
                font-weight: bold;
                font-family: 'Segoe UI', Arial;
            }
            QLabel#subtitle {
                color: rgba(255, 255, 255, 0.7);
                font-size: 14px;
                font-family: 'Segoe UI', Arial;
            }
            QLabel#loading_text {
                color: rgba(255, 255, 255, 0.5);
                font-size: 12px;
                font-family: 'Segoe UI', Arial;
            }
            QProgressBar#loading {
                background: rgba(255, 255, 255, 0.1);
                border: none;
                border-radius: 2px;
            }
            QProgressBar#loading::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(255, 51, 51, 0.8),
                    stop:1 rgba(255, 102, 102, 0.8));
                border-radius: 2px;
            }
        """)
        
        self.counter = 0
        self.loading_texts = [
            "Starting...",
            "Checking configuration...",
            "Initializing server side...",
            "Loading user interface...",
            "Almost ready..."
        ]
        
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_progress)
        self.timer.start(30)
        
    def update_progress(self):
        self.counter += 1
        self.loading_progress.setValue(self.counter)
        
        text_index = min(self.counter // 20, len(self.loading_texts) - 1)
        self.loading_label.setText(self.loading_texts[text_index])
        
        if self.counter >= 100:
            self.timer.stop()
            self.main_window = AntichristGUI()
            self.main_window.show()
            self.close()

def main():
    app = QApplication(sys.argv)
    splash = SplashScreen()
    splash.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
