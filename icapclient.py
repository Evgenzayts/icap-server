import argparse
import logging
import socket

# Конфигурация логгера
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")


def send_icap_request(method, url, content=None):
    try:
        # Создаем соединение с сервером
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("localhost", 1344))

            # Формируем запрос
            request = f"{method} {url} ICAP/1.0\r\n"
            request += "Host: localhost\r\n"
            if content:
                request += f"Content-Length: {len(content)}\r\n"
                request += "\r\n" + content
            else:
                request += "\r\n"

            s.sendall(request.encode("utf-8"))
            response = s.recv(1024).decode("utf-8")
            logging.info(f"Response from server: {response}")
            return response
    except Exception as e:
        logging.error(f"Error while sending request: {e}")
        return None


def handle_response(response):
    """Обрабатывает ответ сервера"""
    if "200 OK" in response:
        print("Response: 200 OK (Success)")
    elif "204 No Content" in response:
        print("Response: 204 No Content (No changes)")
    elif "500 Internal Server Error" in response:
        print("Response: 500 Internal Server Error")
    elif "405 Method Not Allowed" in response:
        print("Response: 405 Method Not Allowed")
    else:
        print("Response: Unknown")


def main():
    parser = argparse.ArgumentParser(description="ICAP client to send requests to the ICAP server.")
    parser.add_argument("method", choices=["OPTIONS", "REQMOD", "RESPMOD"], help="ICAP method")
    parser.add_argument("--url", required=True, help="URL to be processed")
    parser.add_argument("--content", help="Content to send (optional for OPTIONS)")
    parser.add_argument("--modified", action="store_true", help="Simulate modified content response")

    args = parser.parse_args()

    if args.method == "OPTIONS":
        response = send_icap_request("OPTIONS", args.url)
    elif args.method == "REQMOD":
        content = args.content if not args.modified else "Modified request content"
        response = send_icap_request("REQMOD", args.url, content)
    elif args.method == "RESPMOD":
        content = args.content if not args.modified else "Modified response content"
        response = send_icap_request("RESPMOD", args.url, content)

    if response:
        handle_response(response)


if __name__ == "__main__":
    main()
