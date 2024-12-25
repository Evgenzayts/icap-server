import hashlib
import yara
import logging
from socketserver import BaseRequestHandler, TCPServer

# Конфигурация логгера
logging.basicConfig(
    filename="icap_server.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# Загрузка YARA-правила
RULES_PATH = "/app/rules.yar"
yara_rules = yara.compile(filepath=RULES_PATH)


class ICAPServer(BaseRequestHandler):
    def handle(self):
        self.data = self.request.recv(65536).decode("utf-8", errors="ignore")
        if not self.data:
            return

        # Определяем метод ICAP
        if self.data.startswith("OPTIONS"):
            self.handle_options()
        elif self.data.startswith("REQMOD"):
            self.handle_reqmod()
        elif self.data.startswith("RESPMOD"):
            self.handle_respmod()
        else:
            self.send_error("405 Method Not Allowed")

    def handle_options(self):
        """Обработка OPTIONS-запроса."""
        response = (
            "ICAP/1.0 200 OK\r\n"
            "Methods: REQMOD RESPMOD\r\n"
            "Service: Python ICAP Server\r\n"
            "Max-Connections: 100\r\n"
            "Options-TTL: 3600\r\n"
            "Preview: 1024\r\n\r\n"
        )
        self.request.sendall(response.encode("utf-8"))
        logging.info("OPTIONS request handled successfully")

    def handle_reqmod(self):
        url = self.extract_url()
        logging.info(f"REQMOD: {url}")

        # Возвращаем 204 No Content (запрос не изменен)
        self.send_icap_response("ICAP/1.0 204 No Content")

    def handle_respmod(self):
        url = self.extract_url()
        logging.info(f"RESPMOD: {url}")

        # Извлечение контента
        content = self.extract_body()
        if content:
            # Вычисляем хэш
            content_hash = hashlib.sha256(content).hexdigest()
            logging.info(f"Content hash: {content_hash}")

            # Проверяем с помощью YARA
            matches = yara_rules.match(data=content)
            for match in matches:
                logging.info(f"YARA match: {match}")

        # Возвращаем 204 No Content (ответ не изменен)
        self.send_icap_response("ICAP/1.0 204 No Content")

    def extract_url(self):
        """Извлекает URL из заголовков запроса."""
        for line in self.data.splitlines():
            if line.startswith("Host:"):
                return line.split(":", 1)[1].strip()
        return "unknown"

    def extract_body(self):
        """Извлекает тело запроса/ответа."""
        parts = self.data.split("\r\n\r\n", 1)
        if len(parts) > 1:
            return parts[1].encode("utf-8")
        return None

    def send_icap_response(self, status_line):
        """Отправляет ICAP-ответ клиенту."""
        response = f"{status_line}\r\n\r\n"
        self.request.sendall(response.encode("utf-8"))

    def send_error(self, message):
        """Отправляет ошибку ICAP."""
        response = f"ICAP/1.0 500 Internal Server Error\r\n\r\n{message}\r\n"
        self.request.sendall(response.encode("utf-8"))


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 1344
    with TCPServer((HOST, PORT), ICAPServer) as server:
        logging.info("ICAP server started on port 1344")
        server.serve_forever()
