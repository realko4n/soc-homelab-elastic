# 02. Настройка сбора телеметрии конечной точки (Sysmon + Winlogbeat)

## 1. Зачем нужна связка Sysmon + Winlogbeat
Стандартные журналы аудита Windows (Security, System, Application) фиксируют только базовые события, которых недостаточно для глубокого расследования инцидентов (например, они не отражают полные аргументы командной строки, родительские процессы и сетевые соединения конкретных исполняемых файлов).

Для обеспечения видимости на уровне EDR на целевую рабочую станцию **Windows 10 Pro (`192.168.1.207`)** развернут стек:
* **Microsoft Sysmon** — системный драйвер и служба для записи детальной телеметрии процессов, сетевой активности, изменений реестра и DNS-запросов.
* **Elastic Winlogbeat 9.5.7** — легковесный агент доставки, пересылающий события из журналов Windows напрямую в кластер Elasticsearch.

## 2. Установка и конфигурация Sysmon
Для фильтрации легитимного системного шума и фокусировки на техниках злоумышленников (по матрице MITRE ATT&CK) использована эталонная конфигурация **SwiftOnSecurity** (`sysmonconfig-export.xml`).

```powershell
# Установка службы Sysmon64 с кастомным XML-профилем
.\Sysmon64.exe -accepteula -i .\sysmonconfig.xml
```

Ключевые отслеживаемые события (`Microsoft-Windows-Sysmon/Operational`):
* **Event ID 1:** Создание процесса (с фиксацией хэшей SHA256, командной строки и родительского процесса).
* **Event ID 3:** Сетевые подключения (особенно от нетипичных системных утилит: `powershell.exe`, `cmd.exe`, `certutil.exe`).
* **Event ID 11:** Создание файлов в чувствительных директориях (`AppData`, `Temp`, `Downloads`).
* **Event ID 12 / 13:** Изменение ключей реестра (механизмы закрепления в системе / Persistence).
* **Event ID 22:** DNS-запросы процессов.

## 3. Настройка и запуск Winlogbeat
Агент развернут в `C:\Program Files\Winlogbeat` и настроен на сбор как классических журналов (`Security`, `System`, `Application`), так и расширенных каналов (`Sysmon/Operational`, `PowerShell/Operational`).

### Основные параметры конфигурации (`winlogbeat.yml`):
```yaml
winlogbeat.event_logs:
  - name: Application
    ignore_older: 72h
  - name: System
  - name: Security
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Microsoft-Windows-PowerShell/Operational

output.elasticsearch:
  hosts: ["https://192.168.1.206:9200"]
  username: "elastic"
  password: "<ELASTIC_PASSWORD>"
  ssl.verification_mode: none

setup.kibana:
  host: "http://192.168.1.206:5601"
```

### Инициализация и запуск службы:
```powershell
.\winlogbeat.exe test config -c .\winlogbeat.yml
.\winlogbeat.exe setup -e
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
```

## 4. Проверка результата
* Службы `Sysmon64` и `winlogbeat` запущены в автоматическом режиме (`Running`).
* В веб-интерфейсе Kibana (**Analytics → Discover**, шаблон индексов `winlogbeat-*`) подтверждено поступление и корректный парсинг событий в реальном времени.
* Создан снимок состояния (Snapshot) виртуальной машины.
