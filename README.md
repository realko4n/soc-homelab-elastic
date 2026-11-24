# 🛡️ SOC Home Lab: Threat Detection & Incident Response with Elastic Stack

Домашняя лаборатория информационной безопасности, созданная для практики мониторинга событий (SIEM), анализа телеметрии конечных точек (EDR/Sysmon), симуляции атак (Red Team) и написания правил обнаружения (Blue Team) по матрице MITRE ATT&CK.

## 🏗️ Архитектура стенда

Лаборатория развернута на базе гипервизора **Oracle VirtualBox** Все виртуальные машины подключены в режиме **Сетевого моста (Bridged Adapter)** в единую локальную подсеть (`192.168.1.0/24`) для прямого сетевого взаимодействия между узлами стенда и удобного администрирования с хост-машины.

| Роль в лабе | ОС / Инструменты | IP-адрес | Ресурсы | Назначение |
| :--- | :--- | :--- | :--- | :--- |
| **SIEM Server** | Ubuntu Server 24.04.1 LTS<br>Elasticsearch 9.5.7 + Kibana 9.5.7 | `192.168.1.206` | 4 vCPU / 8 GB RAM | Сбор, индексация, корреляция и визуализация логов |
| **Victim / Endpoint** | Windows 10 Pro (22H2)<br>Sysmon + Winlogbeat | `192.168.1.207` | 2 vCPU / 4 GB RAM | Целевая рабочая станция, генерация телеметрии хоста |
| **Attacker (Red Team)** | Kali Linux 2026.1 | `TBD` | 2 vCPU / 4 GB RAM | Проведение атак (сканирование, брутфорс, эксплуатация) |

## 📂 Структура репозитория

* [`01-infrastructure-setup/`](./01-infrastructure-setup/README.md) — Развертывание виртуальных машин, настройка сети, установка и конфигурация Elasticsearch и Kibana.
* [`02-endpoint-telemetry/`](./02-endpoint-telemetry/README.md) — *(В процессе)* Установка Sysmon с кастомной конфигурацией и настройка отправки логов через Winlogbeat.
* [`03-attack-simulations/`](./03-attack-simulations/README.md) — *(В процессе)* Практические сценарии атак, их разбор по MITRE ATT&CK, KQL-запросы для поиска и рекомендации по защите.

## 🎯 Отрабатываемые навыки
* Развертывание и администрирование **Elastic Stack (ELK)** в Linux.
* Сбор и нормализация журналов событий Windows (Security, PowerShell, Sysmon).
* Поиск угроз (Threat Hunting) с использованием **KQL (Kibana Query Language)**.
* Симуляция атак и сопоставление артефактов с матрицей **MITRE ATT&CK**.
