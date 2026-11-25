# Кейс 01: Обнаружение атаки подбора паролей по протоколу SMB (Brute Force)

## 1. Описание сценария и MITRE ATT&CK
* **Тактика:** Credential Access (TA0006)
* **Техника:** Brute Force: Password Guessing ([T1110.001](https://mitre.org))
* **Атакующий (Red Team):** Kali Linux (`192.168.1.208`), утилита `netexec`
* **Жертва (Endpoint):** Windows 10 Pro (`192.168.1.207`, хост `DESKTOP-6OV69S7`), служба SMB (порт `445/tcp`)

### Подготовка и выявленные нюансы телеметрии:
1. В ходе настройки эксперимента обнаружено, что в клиентской Windows 10 Pro аудит неудачных входов в систему по умолчанию отключен. Политика активирована через `auditpol` (`/subcategory:"Logon"` и `"Credential Validation"`).
2. Первичная попытка атаки через модуль `smb://` утилиты `hydra` была отклонена хостом на уровне рукопожатия из-за отключения устаревшего протокола SMBv1 (`SMBv1:None`). Атака успешно воспроизведена через `netexec` по актуальному протоколу SMBv2/v3.

## 2. Симуляция атаки
С хоста `192.168.1.208` запущен перебор паролей по словарю (15 попыток) для локальной учетной записи `qqq`:

```bash
┌──(kali㉿kali)-[~]
└─\$ netexec smb 192.168.1.207 -u qqq -p passwords.txt
SMB         192.168.1.207   445    DESKTOP-6OV69S7  [*] Windows 10 / Server 2019 Build 19041 x64 (name:DESKTOP-6OV69S7) (domain:DESKTOP-6OV69S7) (signing:False) (SMBv1:None)
SMB         192.168.1.207   445    DESKTOP-6OV69S7  [-] DESKTOP-6OV69S7\qqq:123456 STATUS_LOGON_FAILURE
SMB         192.168.1.207   445    DESKTOP-6OV69S7  [-] DESKTOP-6OV69S7\qqq:password STATUS_LOGON_FAILURE
SMB         192.168.1.207   445    DESKTOP-6OV69S7  [-] DESKTOP-6OV69S7\qqq:admin STATUS_LOGON_FAILURE
SMB         192.168.1.207   445    DESKTOP-6OV69S7  [-] DESKTOP-6OV69S7\qqq:qwerty STATUS_LOGON_FAILURE
SMB         192.168.1.207   445    DESKTOP-6OV69S7  [-] DESKTOP-6OV69S7\qqq:12345678 STATUS_LOGON_FAILURE
SMB         192.168.1.207   445    DESKTOP-6OV69S7  [-] DESKTOP-6OV69S7\qqq:letmein STATUS_LOGON_FAILURE
SMB         192.168.1.207   445    DESKTOP-6OV69S7  [-] DESKTOP-6OV69S7\qqq:welcome STATUS_LOGON_FAILURE
SMB         192.168.1.207   445    DESKTOP-6OV69S7  [-] DESKTOP-6OV69S7\qqq:monkey STATUS_LOGON_FAILURE
SMB         192.168.1.207   445    DESKTOP-6OV69S7  [-] DESKTOP-6OV69S7\qqq:dragon STATUS_LOGON_FAILURE
SMB         192.168.1.207   445    DESKTOP-6OV69S7  [-] DESKTOP-6OV69S7\qqq:master STATUS_LOGON_FAILURE
SMB         192.168.1.207   445    DESKTOP-6OV69S7  [-] DESKTOP-6OV69S7\qqq:111111 STATUS_ACCOUNT_LOCKED_OUT
SMB         192.168.1.207   445    DESKTOP-6OV69S7  [-] DESKTOP-6OV69S7\qqq:baseball STATUS_ACCOUNT_LOCKED_OUT
SMB         192.168.1.207   445    DESKTOP-6OV69S7  [-] DESKTOP-6OV69S7\qqq:iloveyou STATUS_ACCOUNT_LOCKED_OUT
SMB         192.168.1.207   445    DESKTOP-6OV69S7  [-] DESKTOP-6OV69S7\qqq:trustno1 STATUS_ACCOUNT_LOCKED_OUT
SMB         192.168.1.207   445    DESKTOP-6OV69S7  [-] DESKTOP-6OV69S7\qqq:sunshine STATUS_ACCOUNT_LOCKED_OUT
```

**Наблюдаемое поведение:**
* Первые 10 попыток вернули статус `STATUS_LOGON_FAILURE`.
* На 11-й попытке сработала встроенная политика блокировки учетных записей Windows (порог — 10 неудачных попыток), последующие запросы возвращали `STATUS_ACCOUNT_LOCKED_OUT`.

## 3. Обнаружение и анализ в SIEM (Kibana)

### Поисковый запрос KQL:
```kql
event.code: ("4625" or "4740") and host.name: "DESKTOP-6OV69S7"
```

### Ключевые артефакты расследования:
* **Всплеск событий:** зафиксировано ровно **11 событий Event ID `4625`** (*An account failed to log on*) за несколько секунд.
* **Источник атаки (`source.ip`):** `192.168.1.208` (Kali Linux).
* **Тип входа (`winlog.event_data.LogonType`):** `3` (Network — сетевая аутентификация по SMB).
* **Эволюция кодов статуса (`winlog.event_data.SubStatus`):**
  * Первые 10 событий содержат код `0xc000006a` (неверный пароль).
  * 11-е событие содержит код `0xc0000234` (учетная запись заблокирована).
* **Событие блокировки:** зафиксировано **Event ID `4740`** (*A user account was locked out*) для пользователя `qqq`.

### Доказательства (Kibana Discover):
<img width="2229" height="1070" alt="image" src="https://github.com/user-attachments/assets/e0ed4a91-5d61-40a9-a970-f52ae7fe0060" />


## 4. Рекомендации по реагированию и защите (Remediation)
1. **Изоляция источника:** заблокировать IP-адрес атакующего (`192.168.1.208`) на уровне межсетевого экрана / IDS.
2. **Контроль политик блокировки (Account Lockout Policy):** убедиться, что на всех рабочих станциях и контроллерах домена активирована блокировка учетных записей при множественных ошибках ввода пароля.
3. **Ограничение доступа к SMB:** закрыть порт `445/tcp` между клиентскими рабочими станциями (микросегментация сети), оставив доступ только к файловым серверам.
4. **Автоматизация детекта:** настроить правило корреляции (Threshold Rule) в Elastic Security на срабатывание при **≥ 5 событиях `4625`** с одного `source.ip` в течение **1 минуты**.
