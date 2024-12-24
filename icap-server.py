import hashlib
import yara
import logging
from pyicap import ICAPServer, ICAPRequest, ICAPResponse

# Настроим логирование
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# Загрузим YARA-правила
rules = yara.compile(filepath='rules.yar')


def check_file_with_yara(file_data):
    matches = rules.match(data=file_data)
    if matches:
        logging.info("YARA правило сработало!")
        return True
    return False


class MyICAPServer(ICAPServer):

    def __init__(self, address, port):
        super().__init__(address, port)

    def process_request(self, request: ICAPRequest):
        url = request.headers.get('ICAP-URL')
        if url:
            logging.info(f"Получен запрос к URL: {url}")

        file_data = request.get_body()
        if file_data:
            file_hash = hashlib.sha256(file_data).hexdigest()
            logging.info(f"Хеш файла: {file_hash}")

            # Проверка через YARA
            if check_file_with_yara(file_data):
                logging.info("YARA правило сработало!")

        # Возвращаем пустой ICAP-ответ с кодом 200
        response = ICAPResponse(status_code=200, body=b"")
        return response


if __name__ == "__main__":
    server = MyICAPServer('0.0.0.0', 1344)
    server.run()
