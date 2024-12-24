import hashlib
import yara
import logging
from pyicap import ICAPServer, BaseICAPRequestHandler

# Настроим логирование
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

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
        url = self.headers.get('ICAP-URL')
        if url:
            logging.info(f"Получен запрос к URL: {url}")

        file_data = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        if file_data:
            file_hash = hashlib.sha256(file_data).hexdigest()
            logging.info(f"Хеш файла: {file_hash}")

            # Проверка через YARA
            if check_file_with_yara(file_data):
                logging.info("YARA правило сработало!")

        # Формируем правильный ICAP-ответ
        self.send_response(200)
        self.send_header('ICAP-Status', '200 OK')  # Добавляем корректный ICAP-статус
        self.end_headers()

        # Отправляем пустое тело (в случае, если не требуется модификация)
        self.wfile.write(b'')  # Отправляем пустое тело в виде байтов

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
