"""
Поиск возможных уязвимостей XSS (Cross-Site Scripting) на сайте:
- Поиск в запросах по ключевым словам, связанным с инъекциями JavaScript, используемые для выполнения кода;
- Проверка параметров URL (GET-запросы) и тела запросов (POST-запросы)
"""
from scapy.all import *
from scapy.layers.inet import TCP, IP

import re
import chardet
import html
from urllib.parse import unquote
from datetime import datetime

from env import INTERFACE, TARGET_PORT as PORT


FILTER = f"tcp port {PORT}"

XSS_VULNERABILITIES = {
    "Stored XSS": {  # когда вредоносный код сохраняется на сервере
        r"<script.*?>.*?</script>": {
            "description": "Script Injection",
            "explanation": "Инъекция JavaScript-кода через тег <script>. Этот код сохраняется на сервере и может быть выполнен позже, когда другие пользователи посетят страницу.",
            "example": [
                "<script>alert('XSS Stored');</script>",  # Простой скрипт для выполнения alert
                "<script type='text/javascript'>alert('XSS Stored');</script>",  # Скрипт с типом JavaScript
            ]
        },
        r"<img.*?onerror=['\"].*?['\"].*?>": {
            "description": "Image Injection via onerror",
            "explanation": "Инъекция через атрибут onerror в теге <img>. Этот атрибут часто используется для выполнения JavaScript-кода, когда изображение не может быть загружено.",
            "example": [
                "<img src='invalid.jpg' onerror='alert(\"XSS Stored\");'>",  # Ошибка загрузки изображения и выполнение скрипта
                "<img src='test.jpg' onerror='console.log(\"XSS Stored\");'>"  # Вставка скрипта для логирования
            ]
        }
    },
    "Reflected XSS": {  # когда вредоносный код исполняется через параметры в URL или формы
        r"javascript:\s*alert\(\s*['\"]?.*?['\"]?\)": {
            "description": "JavaScript Alert Injection",
            "explanation": "Инъекция через ссылку или параметр URL с использованием JavaScript-кода для выполнения alert.",
            "example": [
                "http://example.com/?search=javascript:alert('XSS Reflected');",  # Вставка alert через URL
                "http://example.com/?search=javascript:console.log('XSS Reflected');",  # Вставка JavaScript-кода для логирования
            ]
        },
        r"javascript:\s*eval\(\s*['\"]?.*?['\"]?\)": {
            "description": "JavaScript Eval Injection",
            "explanation": "Инъекция с использованием функции eval(), которая может выполнить JavaScript-код из строки.",
            "example": [
                "http://example.com/?search=javascript:eval('alert(1)');",  # Использование eval для выполнения alert
                "http://example.com/?search=javascript:eval('console.log(\"XSS Reflected\");');"  # Использование eval для логирования
            ]
        }
    },
    "DOM-based XSS": {  # когда скрипт исполняется на клиентской стороне, без взаимодействия с сервером, через манипуляции с DOM
        r"(eval\(\s*['\"].*?['\"]\)|document\.write\(\s*['\"].*?['\"]\)|innerHTML\s*=\s*['\"].*?['\"])": {
            "description": "DOM Manipulation Injection",
            "explanation": "Инъекция через манипуляцию DOM, используя методы JavaScript, такие как eval(), document.write() и innerHTML.",
            "example": [
                "document.write('<script>alert(1);</script>');",  # Вставка скрипта с помощью document.write()
                "eval('alert(\"XSS DOM\");');",  # Выполнение JavaScript-кода через eval
                "document.getElementById('output').innerHTML = '<script>alert(1);</script>';"  # Вставка скрипта в элемент с id 'output'
            ]
        },
        r"(setTimeout\(\s*['\"].*?['\"]\)|setInterval\(\s*['\"].*?['\"]\))": {
            "description": "setTimeout/setInterval Injection",
            "explanation": "Инъекция с использованием setTimeout() или setInterval(), которые могут выполнить код через определенные интервалы.",
            "example": [
                "setTimeout(function(){ alert('XSS DOM'); }, 1000);",  # Вызов alert через setTimeout с задержкой 1 секунда
                "setInterval(function(){ alert('XSS DOM'); }, 1000);"  # Повторение выполнения alert каждые 1 секунду с setInterval
            ]
        }
    },
    "General XSS Patterns": {  # Общие шаблоны для всех типов XSS
        r"<iframe.*?src=['\"].*?['\"].*?>.*?</iframe>": {
            "description": "Iframe Injection",
            "explanation": "Инъекция через тег <iframe>, позволяющий внедрить чуждый контент на страницу.",
            "example": [
                "<iframe src='http://malicious.com'></iframe>",  # Встраивание вредоносного сайта через iframe
                "<iframe src='//attacker.com'></iframe>"  # Встраивание сайта злоумышленника через iframe
            ]
        },
        r"onmouseover=['\"].*?['\"]\s*alert\(\s*['\"]?.*?['\"]?\)": {
            "description": "Mouseover Event Injection",
            "explanation": "Инъекция через событие onmouseover, которое выполняет JavaScript, когда пользователь наводит курсор на элемент.",
            "example": [
                "<div onmouseover='alert(\"XSS\");'>Hover me!</div>",  # Выполнение alert при наведении курсора на элемент
                "<button onmouseover='alert(\"XSS Reflected\");'>Click me!</button>"  # Выполнение alert на кнопке
            ]
        }
    }
}


def decode_payload(payload) -> str:
    """
    Декодирование HTML и URL
    :param payload: строка ответа от сайта
    :return: обработанная и декодированная строка полезной нагрузки
    """
    # Декодируем HTML (&lt; в <)
    decoded_payload = html.unescape(payload)
    # Декодируем URL
    decoded_payload = unquote(decoded_payload)
    return decoded_payload

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
                    raw_data = packet.getlayer(Raw).load
                    detected_encoding = chardet.detect(raw_data).get("encoding")
                    if detected_encoding is None:
                        detected_encoding = "utf-8"
                    payload = raw_data.decode(encoding=detected_encoding, errors="ignore")

                    # Декодируем HTML и URL
                    payload = decode_payload(payload)

                    # Ищем потенциальные уязвимости XSS в параметрах запроса
                    found_vulnerabilities = []
                    for category, patterns in XSS_VULNERABILITIES.items():
                        for pattern, vulnerability in patterns.items():
                            matches = re.findall(pattern, payload, re.IGNORECASE)  # ищем все возможные совпадения
                            if matches:
                                found_vulnerabilities.append( f"   [-] [Vulnerability <{category}: {vulnerability["description"]}> DETECTED]:")
                                for match in matches:
                                    found_vulnerabilities.append(f"       {match}  # {vulnerability["explanation"]}")
                    if found_vulnerabilities:
                        print(f"[+] HTTP packet: {datetime.fromtimestamp(packet.time).strftime('%d-%m-%Y %H:%M:%S')}: src: {packet[IP].src}, dst: {packet[IP].dst}")
                        print('\n'.join(found_vulnerabilities))
                except UnicodeDecodeError:
                    pass


if __name__ == '__main__':
    print(f"Listening HTTP traffic (interface={INTERFACE}, packet=TCP, port={PORT})...")
    sniff(iface=INTERFACE, filter=FILTER, prn=packet_parser_callback, store=0)
