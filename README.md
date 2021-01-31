# ransomware
Установка:
Скопировать ransomwaremonitor.dll в корень любого диска

В реестре: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs заменить на адрес dll для windows 32 bit
HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs для windows 64 bit

Компиляция через MS VC developer command prompt
cl /LD ransomwaremonitor.cpp

Далее программа перехватывает все вызовы к криптографической библиотеке и пишет перехваченные данные в файл C:\Ransomwaremonitor.log
При помощи перехваченных данных можно легко расшифровать файлы
