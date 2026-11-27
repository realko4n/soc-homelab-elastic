# Кейс 03: Обнаружение закрепления в системе через ключ автозагрузки реестра (Registry Run Keys)

## 1. Описание сценария и MITRE ATT&CK
* **Тактика:** Persistence (TA0003)
* **Техника:** Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder ([T1547.001](https://attack.mitre.org/techniques/T1547/001))
* **Целевой узел (Endpoint):** Windows 10 Pro (`192.168.1.207`, хост `DESKTOP-6OV69S7`)
* **Инструмент симуляции:** Штатная утилита `reg.exe` (тактика *Living off the Land*)

### Механизм атаки:
После успешного выполнения кода в памяти злоумышленнику необходимо обеспечить повторный запуск полезной нагрузки при перезагрузке ОС. Ветка реестра `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` позволяет прописать программу в автозагрузку текущего пользователя **без прав локального администратора**. Для маскировки запись часто именуется под системную службу (например, `SecurityUpdater`).

## 2. Симуляция закрепления (Red Team)
На рабочей станции `192.168.1.207` через командную строку выполнена запись параметра `SecurityUpdater` в раздел автозагрузки `Run` для скрытого запуска PowerShell при входе пользователя в систему:

```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdater" /t REG_SZ /d "powershell.exe -WindowStyle Hidden -Command Write-Host PersistenceTest" /f
```

## 3. Обнаружение и анализ в SIEM (Blue Team — Kibana)

### Поисковый запрос KQL:
```kql
(event.code: "1" and *reg.exe* and *CurrentVersion\Run*) or (event.code: ("12" or "13") and *CurrentVersion\Run*)
```

### Ключевые артефакты расследования:
1. **Запуск консольного редактора реестра (`Sysmon Event ID 1`):**
   * **Процесс (`winlog.event_data.Image`):** `C:\Windows\System32\reg.exe`
   * **Командная строка (`winlog.event_data.CommandLine`):** содержит точные аргументы модификации ветки автозагрузки (`reg add "...\CurrentVersion\Run" /v "SecurityUpdater"`) и команду запуска скрытого интерпретатора `powershell.exe -WindowStyle Hidden`.
2. **Фиксация изменения значения в реестре (`Sysmon Event ID 13` — Registry Value Set):**
   * **Целевой объект (`winlog.event_data.TargetObject`):** `HKU\S-1-5-21-...\Software\Microsoft\Windows\CurrentVersion\Run\SecurityUpdater`
   * **Записанное значение (`winlog.event_data.Details`):** `powershell.exe -WindowStyle Hidden -Command Write-Host PersistenceTest`

### Доказательства (Kibana Discover):
<img width="1280" height="610" alt="image" src="https://github.com/user-attachments/assets/0080a459-b4b2-4354-802e-14408943c168" />
<img width="1280" height="592" alt="image" src="https://github.com/user-attachments/assets/98c5c0f7-3c34-476f-b917-09aac706f3bb" />


## 4. Реагирование и очистка системы (Remediation)
1. **Искоренение (Eradication):** вредоносный параметр автозагрузки удален с целевой рабочей станции:
   ```cmd
   reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdater" /f
   ```
2. **Проактивная охота (Threat Hunting):** выполнить ретроспективный поиск по всей инфраструктуре на наличие новых записей в разделах `CurrentVersion\Run`, `CurrentVersion\RunOnce` и `Wow6432Node\...\Run` (особенно ссылающихся на `powershell.exe`, `cmd.exe`, `mshta.exe` или исполняемые файлы из директорий `AppData` / `Temp` / `Public`).
3. **Автоматизация детекта в SIEM:** настроить правило корреляции в Elastic Security на срабатывание при `Sysmon Event ID 13` в ветках автозагрузки, если поле `Details` содержит вызов скриптовых интерпретаторов или пути к пользовательским директориям.
