import socket

def send_icap_request():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 1344))

    # Формируем корректный ICAP-запрос
    icap_request = (
        "ICAP/1.0 REQMOD icap://localhost:1344\r\n"
        "Host: localhost\r\n"
        "Allow: 204\r\n"
        "Encapsulated: req-hdr=0, req-body=9\r\n"  # Обновляем размер тела на 9 байт
        "\r\n"
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Length: 9\r\n"
        "\r\n"
        "my_data"
    )

    print(f"Отправляем запрос:\n{icap_request}")
    s.sendall(icap_request.encode())

    response = s.recv(4096)
    print("Ответ сервера:\n", response.decode())
    s.close()

send_icap_request()
