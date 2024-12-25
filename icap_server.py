import hashlib
import yara
import logging
import sys
from pyicap import ICAPServer, BaseICAPRequestHandler

# Настроим логирование в файл и консоль
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/icap_server.log'),
        logging.StreamHandler(sys.stdout)  # Добавляем вывод в консоль
    ]
)

# Загрузим YARA-правила
rules = yara.compile(filepath='/app/rules.yar')


def check_file_with_yara(file_data):
    matches = rules.match(data=file_data)
    if matches:
        logging.info("YARA правило сработало!")
        return True
    return False


class MyRequestHandler(BaseICAPRequestHandler):
    def do_REQMOD(self):
        try:
            print(f"Получен запрос от {self.client_address}")
            sys.stdout.flush()

            encapsulated_header = self.headers.get("Encapsulated")
            if not encapsulated_header:
                self.send_error(400, "Missing Encapsulated Header")
                return

            # Извлекаем информацию из Encapsulated
            encapsulated_parts = encapsulated_header.split(',')
            req_hdr_size = int(encapsulated_parts[0].split('=')[1])
            req_body_size = int(encapsulated_parts[1].split('=')[1])

            # Читаем тело запроса
            content_length = self.headers.get('Content-Length')
            if content_length:
                file_data = self.rfile.read(req_body_size)  # Читаем только тело, согласно Encapsulated
                print(f"Получено {len(file_data)} байт данных: {file_data[:50]}...")
                sys.stdout.flush()

            if file_data:
                file_hash = hashlib.sha256(file_data).hexdigest()
                print(f"Хеш файла: {file_hash}")
                sys.stdout.flush()

            # Отправка ответа ICAP
            print("Отправка ответа ICAP 200 OK")
            sys.stdout.flush()
            self.send_response(200)
            self.send_header('ICAP-Status', '200 OK')
            self.end_headers()

            self.wfile.write(b'')  # Отправляем пустое тело

        except Exception as e:
            print(f"Ошибка при обработке запроса: {str(e)}")
            sys.stdout.flush()
            self.send_error(500, "Internal Server Error")

    def send_error(self, code, message=None):
        if message is None:
            message = 'Bad Request'

        # Логируем подробности ошибки один раз
        print(f"Код ошибки: {code}, Сообщение: {message}")
        sys.stdout.flush()  # Принудительный сброс вывода
        logging.error(f"Код ошибки: {code}, Сообщение: {message}")
        logging.error(f"IP клиента: {self.client_address}")

        # Логируем всю строку запроса один раз
        if hasattr(self, 'requestline') and self.requestline:
            print(f"Строка запроса: {self.requestline}")
            sys.stdout.flush()  # Принудительный сброс вывода
            logging.error(f"Строка запроса: {self.requestline}")

        # Логируем заголовки запроса
        if hasattr(self, 'headers') and self.headers:
            print(f"Заголовки запроса: {self.headers}")
            sys.stdout.flush()  # Принудительный сброс вывода
            logging.error(f"Заголовки запроса: {self.headers}")

        # Формируем ICAP-ответ
        try:
            self.set_icap_response(code, message.encode('utf-8'))
            self.end_headers()
            self.wfile.write(self.icap_response)
        except Exception as e:
            print(f"Ошибка при отправке ICAP-ответа: {str(e)}")
            sys.stdout.flush()  # Принудительный сброс вывода
            logging.error(f"Ошибка при отправке ICAP-ответа: {str(e)}")

    def end_headers(self):
        """Завершаем отправку заголовков в ICAP-ответ."""
        self.wfile.write(b'\r\n')  # Отправляем завершающий пустой символ для заголовков


class MyICAPServer(ICAPServer):
    def __init__(self, address, port, handler_class):
        # Передаем адрес как кортеж (адрес, порт) и handler_class
        super().__init__((address, port), handler_class)

    def run(self):
        # Используем метод serve_forever для правильного запуска
        self.serve_forever()


if __name__ == "__main__":
    server = MyICAPServer('0.0.0.0', 1344, MyRequestHandler)  # Передаем handler_class
    server.run()
