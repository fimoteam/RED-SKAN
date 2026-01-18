import urllib.request
import urllib.error
import urllib.parse
import time
import argparse
import sys
import os
import re
import random
from datetime import datetime

# Цвета для вывода в консоль
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class RedScanner:
    def __init__(self, target_url, delay=0.5):
        self.target_url = target_url.rstrip('/')
        self.delay = delay
        self.results = {
            "headers": [],
            "directories": [],
            "sqli_potential": [],
            "xss_potential": [],
            "robots_paths": []
        }
        self.start_time = datetime.now()
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'RedScan-Olympiad-Bot/2.0'
        ]

    def _get_random_ua(self):
        return random.choice(self.user_agents)

    def _make_request(self, url):
        """Обертка для запросов с обработкой ошибок и кодировок"""
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', self._get_random_ua())
            response = urllib.request.urlopen(req, timeout=10)
            content = response.read().decode('utf-8', errors='ignore')
            return response.getcode(), response.info(), content
        except urllib.error.HTTPError as e:
            return e.code, None, None
        except Exception:
            return None, None, None

    def print_log(self, message, level="INFO"):
        """Вывод логов в консоль"""
        prefix = "[*]"
        color = Colors.BLUE
        if level == "SUCCESS":
            prefix = "[+]"
            color = Colors.GREEN
        elif level == "WARNING":
            prefix = "[!]"
            color = Colors.WARNING
        elif level == "ERROR":
            prefix = "[-]"
            color = Colors.FAIL
        
        print(f"{color}{prefix} {message}{Colors.ENDC}")

    def check_security_headers(self):
        """1. Модуль проверки заголовков безопасности"""
        print(f"\n{Colors.HEADER}--- ЭТАП 1: Анализ HTTP-заголовков ---{Colors.ENDC}")
        code, headers, _ = self._make_request(self.target_url)
        
        if not headers:
            self.print_log("Не удалось получить заголовки.", "ERROR")
            return

        security_headers = [
            'X-Frame-Options',
            'X-XSS-Protection',
            'Content-Security-Policy',
            'Strict-Transport-Security',
            'X-Content-Type-Options',
            'Referrer-Policy'
        ]

        for sec_header in security_headers:
            if sec_header in headers:
                self.print_log(f"Найден заголовок: {sec_header}", "SUCCESS")
                self.results["headers"].append({"header": sec_header, "status": "Found", "value": headers[sec_header]})
            else:
                self.print_log(f"Отсутствует заголовок: {sec_header}", "WARNING")
                self.results["headers"].append({"header": sec_header, "status": "Missing", "value": "N/A"})
        
        if 'Server' in headers:
            self.print_log(f"Раскрытие версии сервера: {headers['Server']}", "WARNING")
            self.results["headers"].append({"header": "Server Info Disclosure", "status": "Warning", "value": headers['Server']})

    def check_robots_txt(self):
        """2. Модуль анализа robots.txt"""
        print(f"\n{Colors.HEADER}--- ЭТАП 2: Анализ Robots.txt ---{Colors.ENDC}")
        url = f"{self.target_url}/robots.txt"
        code, _, content = self._make_request(url)

        if code == 200 and content:
            self.print_log(f"Файл robots.txt найден!", "SUCCESS")
            # Поиск запрещенных путей
            disallows = re.findall(r"Disallow:\s*(.*)", content)
            for path in disallows:
                path = path.strip()
                if path and path != '/':
                    self.print_log(f"Найден скрытый путь в robots.txt: {path}", "WARNING")
                    self.results["robots_paths"].append(path)
        else:
            self.print_log("Robots.txt не найден.", "INFO")

    def scan_directories(self):
        """3. Модуль поиска скрытых директорий (Directory Busting)"""
        print(f"\n{Colors.HEADER}--- ЭТАП 3: Поиск скрытых путей ---{Colors.ENDC}")
        
        common_paths = [
            'admin', 'login', 'dashboard', 'config', 'backup', 'db', 
            'sitemap.xml', '.env', '.git/HEAD', 'uploads',
            'api', 'test', 'phpmyadmin', 'wp-config.php.bak', 
            'server-status', '.htaccess'
        ]
        
        scan_list = list(set(common_paths + [p.lstrip('/') for p in self.results["robots_paths"]]))

        for path in scan_list:
            full_url = f"{self.target_url}/{path}"
            code, _, _ = self._make_request(full_url)
            
            if code == 200:
                self.print_log(f"Найден путь: /{path} (Code: 200)", "SUCCESS")
                self.results["directories"].append({"path": path, "code": 200})
            elif code == 403:
                self.print_log(f"Доступ запрещен (существует): /{path} (Code: 403)", "WARNING")
                self.results["directories"].append({"path": path, "code": 403})
            elif code == 500:
                 self.print_log(f"Ошибка сервера: /{path} (Code: 500)", "WARNING")
            
            time.sleep(self.delay)

    def test_sqli(self):
        """4. Улучшенная проверка на SQL Injection (GET параметры)"""
        print(f"\n{Colors.HEADER}--- ЭТАП 4: Проверка на SQL Injection (Error-Based) ---{Colors.ENDC}")
        
        parsed = urllib.parse.urlparse(self.target_url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        if not query_params:
            self.print_log("URL не содержит параметров. Тестирование параметров пропущено.", "INFO")
            # Проверка базового URL на всякий случай
            test_url = f"{self.target_url}'"
            code, _, content = self._make_request(test_url)
            if code == 500:
                self.print_log(f"Возможна SQLi (500 Error) на корневом URL: {test_url}", "FAIL")
                self.results["sqli_potential"].append({"url": test_url, "payload": "'"})
            return

        # Сигнатуры ошибок SQL
        sql_errors = {
            "MySQL": [r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."],
            "PostgreSQL": [r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."],
            "Microsoft SQL Server": [r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\."],
            "Microsoft Access": [r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"],
            "Oracle": [r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"],
        }

        payloads = ["'", '"', "')"]

        for param in query_params:
            for payload in payloads:
                params_copy = query_params.copy()
                params_copy[param] = [payload] 
                
                new_query = urllib.parse.urlencode(params_copy, doseq=True)
                new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                
                code, _, content = self._make_request(new_url)
                
                if content:
                    for db, errors in sql_errors.items():
                        for error in errors:
                            if re.search(error, content, re.IGNORECASE):
                                msg = f"Уязвимость SQLi ({db}) в параметре '{param}' с пейлоадом '{payload}'"
                                self.print_log(msg, "FAIL")
                                self.results["sqli_potential"].append({"url": new_url, "payload": payload, "db": db})
                                break

    def test_xss(self):
        """5. Модуль проверки на Reflected XSS"""
        print(f"\n{Colors.HEADER}--- ЭТАП 5: Проверка на Reflected XSS ---{Colors.ENDC}")
        
        parsed = urllib.parse.urlparse(self.target_url)
        query_params = urllib.parse.parse_qs(parsed.query)

        if not query_params:
            self.print_log("Нет параметров для проверки XSS.", "INFO")
            return

        xss_payload = "RedScan<script>alert(1)</script>"
        check_marker = "RedScan<script>"

        for param in query_params:
            params_copy = query_params.copy()
            params_copy[param] = [xss_payload]
            
            new_query = urllib.parse.urlencode(params_copy, doseq=True)
            new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
            
            code, _, content = self._make_request(new_url)
            
            if content and check_marker in content:
                msg = f"Потенциальная XSS в параметре '{param}'"
                self.print_log(msg, "FAIL")
                self.results["xss_potential"].append({"url": new_url, "param": param})
            else:
                self.print_log(f"Параметр '{param}' выглядит безопасным (экранирован)", "INFO")

    def generate_html_report(self):
        """Генерация расширенного HTML отчета"""
        filename = "redscan_report.html"
        
        headers_rows = ''.join([f"<tr><td>{h['header']}</td><td class='status-{h['status'].lower()}'>{h['status']}</td><td>{h['value'][:80]}...</td></tr>" for h in self.results['headers']])
        dir_rows = ''.join([f"<li><span class='status-found'>/{d['path']}</span> (HTTP {d['code']})</li>" for d in self.results['directories']]) or "<li>Скрытых путей не найдено</li>"
        
        sqli_rows = ""
        if self.results['sqli_potential']:
            for s in self.results['sqli_potential']:
                db_info = f" (DB: {s.get('db', 'Unknown')})" if 'db' in s else ""
                sqli_rows += f"<p class='status-missing'>[CRITICAL] SQLi в URL: {s['url']} <br>Payload: <b>{s['payload']}</b>{db_info}</p>"
        else:
            sqli_rows = "<p class='status-found'>Явных уязвимостей SQLi не обнаружено.</p>"

        xss_rows = ""
        if self.results['xss_potential']:
            for x in self.results['xss_potential']:
                xss_rows += f"<p class='status-missing'>[HIGH] XSS в параметре: <b>{x['param']}</b> <br>URL: {x['url']}</p>"
        else:
            xss_rows = "<p class='status-found'>Отраженных XSS не обнаружено.</p>"
        
        robots_rows = ""
        if self.results['robots_paths']:
            robots_rows = "<ul>" + ''.join([f"<li>Disallow: {p}</li>" for p in self.results['robots_paths']]) + "</ul>"
        else:
            robots_rows = "<p>Файл robots.txt пуст или отсутствует.</p>"

        html_content = f"""
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <title>RedScan Security Report v2.0</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1e1e1e; color: #e0e0e0; padding: 20px; }}
                h1 {{ color: #ff5252; border-bottom: 2px solid #ff5252; padding-bottom: 10px; }}
                h2 {{ color: #69f0ae; margin-top: 30px; border-left: 4px solid #69f0ae; padding-left: 10px; }}
                .card {{ background-color: #2d2d2d; padding: 15px; border-radius: 8px; margin-bottom: 15px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
                .status-found {{ color: #69f0ae; font-weight: bold; }}
                .status-missing {{ color: #ff5252; font-weight: bold; }}
                .status-warning {{ color: #ffd740; font-weight: bold; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #444; }}
                th {{ background-color: #333; }}
                code {{ background-color: #444; padding: 2px 5px; border-radius: 4px; }}
            </style>
        </head>
        <body>
            <h1>RedScan v2.0: Отчет о безопасности</h1>
            <p><strong>Цель:</strong> <a href="{self.target_url}" style="color:#64b5f6">{self.target_url}</a></p>
            <p><strong>Дата:</strong> {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>

            <h2>1. HTTP Заголовки</h2>
            <div class="card">
                <table>
                    <tr><th>Заголовок</th><th>Статус</th><th>Значение</th></tr>
                    {headers_rows}
                </table>
            </div>

            <h2>2. Файловая структура и Robots.txt</h2>
            <div class="card">
                <h3>Найденные директории:</h3>
                <ul>{dir_rows}</ul>
                <h3>Robots.txt Disallow:</h3>
                {robots_rows}
            </div>

            <h2>3. SQL Injection (Error-Based)</h2>
            <div class="card">
                {sqli_rows}
            </div>

            <h2>4. Cross-Site Scripting (XSS)</h2>
            <div class="card">
                {xss_rows}
            </div>
            
            <p style="text-align:center; color:#777; margin-top:50px;"><em>Generated by RedScan Olympiad Project</em></p>
        </body>
        </html>
        """
        
        counter = 1
        base_filename = filename.replace('.html', '')
        while os.path.exists(filename):
            filename = f"{base_filename}_{counter}.html"
            counter += 1
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"\n{Colors.GREEN}[+] Отчет успешно сохранен в файл: {filename}{Colors.ENDC}")

    def run(self):
        print(f"{Colors.HEADER}RedScan v2.0 - Starting Advanced Enumeration...{Colors.ENDC}")
        self.check_security_headers()
        self.check_robots_txt()
        self.scan_directories()
        self.test_sqli()
        self.test_xss()
        self.generate_html_report()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='RedScan - Automated Vulnerability Scanner')
    parser.add_argument('-u', '--url', help='Target URL (e.g., http://testphp.vulnweb.com)', required=False)
    parser.add_argument('-d', '--delay', help='Delay between requests (seconds)', type=float, default=0.5)
    
    args = parser.parse_args()

    print(f"{Colors.HEADER}==========================================")
    print("   RED SCAN - OLYMPIAD PROJECT")
    print("==========================================\n" + Colors.ENDC)
    
    target = args.url
    if not target:
        default_target = "http://testphp.vulnweb.com"
        print(f"URL не указан. Используется цель по умолчанию: {default_target}")
        print("Для указания своей цели используйте: python main.py -u http://example.com\n")
        target = default_target
    
    scanner = RedScanner(target, args.delay)
    scanner.run()

