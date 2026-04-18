Autonomní IDS systém na základu Raspberry Pi 5 se schopností real-time detekce a klasifikace anomálií síťového provozu.


Složka MAC_detekce je kompletní složkou MAC_detekce, se kterou pracuje celý systém, obsahuje natrénované modely, veškeré whitelisty, blacklisty a skripty potřebné k běhu.

Složka ZEEK_LOGS obsahuje složky trénovacích JSON logů pro modely HOME a AWAY a složku TEST, která obsahuje data z doby, kdy byl model testován v reálném čase. Dále obsahuje CSV soubory s vyexportovanými "tabulkami" anomálií z InfluxDB podle jejich klasifikace.

DATA_TRAFFIC.json - Konfigurace Grafana dashboardu

LOG.json - Konfigurace Grafana dashboardu

realtime_ml_monitor.py - Hlavní detekční skript

train_network_model_v5.py - Trénovací skript pro ML model

Příloha č. 1 - Příprava Prostředí (Priloha_1_Priprava_Prostredi.pdf) popisuje instalaci všech potřebných programů a jejich konfiguraci. Dále trénování modelů a spuštění samotného monitorovacího skriptu.

Příloha č. 2 - Příprava Grafany (Priloha_2_Priprava_Grafany.pdf) popisuje způsob konfigurace Dashboardů a varovných alertů
