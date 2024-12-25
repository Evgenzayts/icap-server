# Тестирование сервера
1. Проверка OPTIONS

Метод OPTIONS возвращает информацию о поддерживаемых методах и других параметрах сервера.

Пример вызова клиента:
```
python3 icapclient.py OPTIONS --url http://example.com
```
Ожидаемый ответ:
```
Response: 200 OK (Success)
```
2. Проверка REQMOD (без модификации)

Метод REQMOD используется для модификации запросов (например, их фильтрации или проверки). В данном случае сервер вернёт статус 204 No Content, что означает, что запрос не был изменен.

Пример вызова клиента:
```
python3 icapclient.py REQMOD --url http://example.com --content "Some request content"
```
Ожидаемый ответ:
```
Response: 204 No Content (No changes)
```
3. Проверка REQMOD (с модификацией)

Если активирована модификация контента (--modified), сервер должен изменить контент запроса и вернуть его с ответом.

Пример вызова клиента:
```
python3 icapclient.py REQMOD --url http://example.com --content "Some request content" --modified
```
Ожидаемый ответ:
```
Response: 204 No Content (No changes)
```
4. Проверка RESPMOD (без модификации)

Метод RESPMOD проверяет контент ответа. Сервер будет проверять контент на наличие вирусов и при необходимости изменит его.

Пример вызова клиента:
```
python3 icapclient.py RESPMOD --url http://example.com --content "Some response content"
```
Ожидаемый ответ:
```
Response: 204 No Content (No changes)
```
5. Проверка RESPMOD (с модификацией)

Если контент ответа соответствует сигнатурам вируса (например, если в контенте содержится строка "ThisProgramIsInfected"), сервер должен вернуть модифицированный контент, блокируя или изменяя его.

Пример вызова клиента:
```
python3 icapclient.py RESPMOD --url http://example.com --content "ThisProgramIsInfected"
```
Ожидаемый ответ:
```
Response: 200 OK (Success)
```
