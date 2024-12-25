import argparse
import socket


def send_icap_request(method, host, port, url=None, content=None):
    # Устанавливаем соединение
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        if method == "OPTIONS":
            icap_request = (
                f"OPTIONS icap://{host}:{port}/ ICAP/1.0\r\n"
                f"Host: {host}\r\n\r\n"
            )
        elif method == "REQMOD":
            encapsulated = "req-hdr=0"
            headers = (
                "GET / HTTP/1.1\r\n"
                f"Host: {url}\r\n\r\n"
            )
            icap_request = (
                f"REQMOD icap://{host}:{port}/reqmod ICAP/1.0\r\n"
                f"Host: {host}\r\n"
                f"Encapsulated: {encapsulated}\r\n\r\n"
                f"{headers}"
            )
        elif method == "RESPMOD":
            encapsulated = "res-hdr=0, res-body=12"
            headers = (
                "HTTP/1.1 200 OK\r\n"
                f"Host: {url}\r\n\r\n"
            )
            icap_request = (
                f"RESPMOD icap://{host}:{port}/respmod ICAP/1.0\r\n"
                f"Host: {host}\r\n"
                f"Encapsulated: {encapsulated}\r\n\r\n"
                f"{headers}"
            )
            if content:
                icap_request += content
        else:
            raise ValueError("Unsupported method. Use OPTIONS, REQMOD, or RESPMOD.")

        # Отправляем запрос
        print(f"Sending {method} request to {host}:{port}")
        s.sendall(icap_request.encode("utf-8"))

        # Получаем ответ
        response = s.recv(8192).decode("utf-8", errors="ignore")
        print(f"Server response:\n{response}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test ICAP server.")
    parser.add_argument(
        "method",
        choices=["OPTIONS", "REQMOD", "RESPMOD"],
        help="ICAP method to test: OPTIONS, REQMOD, or RESPMOD"
    )
    parser.add_argument(
        "--host",
        default="localhost",
        help="ICAP server host (default: localhost)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=1344,
        help="ICAP server port (default: 1344)"
    )
    parser.add_argument(
        "--url",
        default="example.com",
        help="URL for the test request (default: example.com)"
    )
    parser.add_argument(
        "--content",
        help="Content to include in the request body"
    )

    args = parser.parse_args()

    send_icap_request(
        method=args.method,
        host=args.host,
        port=args.port,
        url=args.url,
        content=args.content
    )
