"""
Поиск возможных уязвимостей XSS (Cross-Site Scripting) на сайте:
- Поиск в запросах по ключевым словам, связанным с инъекциями JavaScript, используемые для выполнения кода;
- Проверка параметров URL (GET-запросы) и тела запросов (POST-запросы)
"""

from scapy.all import *
from scapy.layers.inet import TCP, IP
import re
from datetime import datetime
from env import INTERFACE, TARGET_PORT as PORT


FILTER = f"tcp port {PORT}"

XSS_VULNERABILITIES = {
    "Stored XSS": {  # когда вредоносный код сохраняется на сервере
        r"<script.*?>.*?</script>": {
            "description": "Script Injection",
            "explanation": "Инъекция JavaScript-кода через тег <script>. Этот код сохраняется на сервере и может быть выполнен позже, когда другие пользователи посетят страницу.",
            "example": "<script>alert('XSS Stored');</script>"  # Пример: Ввод скрипта, который сохраняется и выполняется на странице.
        }
    },
    "Reflected XSS": {  # когда вредоносный код исполняется через параметры в URL или формы
        r"(on\w+=[\"'][^\"']*[;]*[^\"']*javascript:[^\"']*)": {
            "description": "Event Handler Injection",
            "explanation": "Инъекция JavaScript через события HTML-атрибутов. Код передается в запросе и немедленно исполняется при ответе.",
            "example": "<img src='invalid.jpg' onerror='alert(\"XSS Stored\")'>"  # Пример: Ввод вредоносного кода через атрибут события onerror.
        },
        r"(src=[\"'].*?javascript:[^\"']*)": {
            "description": "JavaScript Injection in src",
            "explanation": "Инъекция JavaScript-кода через атрибуты src тега HTML. Этот код может быть выполнен немедленно при загрузке страницы.",
            "example": "<img src='javascript:alert(\"XSS Stored\")'>"  # Пример: Вредоносная инъекция через атрибут src в изображении.
        },
        r"eval\s*\(.*\)": {
            "description": "Eval Function Injection",
            "explanation": "Использование функции eval(), которая может выполнить вредоносный код, переданный через параметры запроса или формы. Это типичная уязвимость, когда сервер выполняет переданный JavaScript-код.",
            "example": "eval('alert(\"XSS Stored\")');"  # Пример: Вредоносная инъекция с использованием eval(), чтобы выполнить JavaScript-код.
        },
        r"<iframe[^>]*src=[\"']javascript:[^\"']*['\"]": {
            "description": "JavaScript in iframe src",
            "explanation": "Инъекция JavaScript-кода через атрибут src тега <iframe>. Это позволяет внедрить вредоносный код на страницу, который будет выполняться при загрузке фрейма.",
            "example": "<iframe src='javascript:alert(\"XSS Stored\")'></iframe>"  # Пример: Вредоносный фрейм, который исполняет JavaScript.
        },
        r"(alert|confirm|prompt)\s*\(.*\)": {
            "description": "JavaScript Dialog Injection",
            "explanation": "Вредоносный код через вызовы JavaScript-функций alert(), confirm(), или prompt(), которые могут использоваться для создания всплывающих окон, выполняющих код на стороне клиента.",
            "example": "alert('XSS');"  # Пример: Вредоносный код, который вызывает всплывающее окно с сообщением.
        },
        r"(\/\?|\&|\?)\w*=[\"'][^\"']*(javascript:|data:).*?['\"]": {
            "description": "JavaScript in URL Parameters",
            "explanation": "Инъекция JavaScript в параметры URL. Этот код может быть исполнен при обработке запроса.",
            "example": "?user=javascript:alert(\"XSS Stored\")"  # Пример: Вредоносный параметр URL, который вызывает JavaScript через javascript:.
        },
    },
    "DOM-based XSS": {  # когда скрипт исполняется на клиентской стороне, без взаимодействия с сервером, через манипуляции с DOM
        r"(document\.location|window\.location)[\s]*=[\s]*['\"].*?javascript:[^\"']*": {
            "description": "Location Manipulation",
            "explanation": "Манипуляция с URL с целью выполнения JavaScript-кода через document.location или window.location. Код может быть исполнил в браузере жертвы, изменив URL или перезагрузив страницу.",
            "example": "document.location='javascript:alert(\"XSS Stored\")';"  # Пример: Вредоносная манипуляция с location через JavaScript.
        }
    }
}


def packet_parser_callback(packet: Packet) -> None:
    """
    обработка пакетов, проверяя, содержится ли в них XSS-пэйлоад
    (функция будет вызвана для каждого перехваченного пакета)
    :param packet: входящий пакет
    """
    # забираем только TCP пакеты с IP заголовком
    if packet.haslayer(TCP) and packet.haslayer(IP):
        # смотрим содержимое пакета только если TCP пакеты на 80 порту (HTTP)
        if packet[TCP].dport == PORT or packet[TCP].sport == PORT:
            # обрабатываем данные, только если запрос/ответ содержит полезную нагрузку (Raw слой)
            if packet.haslayer(Raw):
                try:
                    # декодируем запрос/ответ в строку
                    payload = packet[Raw].load.decode("utf-8", errors="ignore")
                    # Ищем потенциальные уязвимости XSS (<script> в параметрах запроса)
                    matches = []
                    for group, vulnerabilities in XSS_VULNERABILITIES.items():
                        for pattern, vulnerability in vulnerabilities.items():
                            match = re.search(pattern, payload, re.IGNORECASE)
                            if match:
                                matches.append(f"   [-] [{vulnerability["description"]} ({group}) DETECTED] payload: '{match.group()}'")
                    if matches:
                        ip_src = packet[IP].src
                        ip_dst = packet[IP].dst
                        print(f"[+] HTTP packet: {datetime.fromtimestamp(packet.time).strftime('%d-%m-%Y %H:%M:%S')}: src: {ip_src}, dst: {ip_dst}")
                        for res in matches:
                            print(res)
                except UnicodeDecodeError:
                    pass


if __name__ == '__main__':
    print(f"Listening HTTP traffic (interface={INTERFACE}, packet=TCP, port={PORT})...")
    sniff(iface=INTERFACE, filter=FILTER, prn=packet_parser_callback, store=0)
