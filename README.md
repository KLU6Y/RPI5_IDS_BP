Tento repozitář obsahuje zdrojové kódy, konfigurační soubory a dokumentaci k bakalářské práci vytvořené na Přírodovědecké fakultě Jihočeské univerzity v Českých Budějovicích v roce 2026.

Autor: Michal Kluger

📖 O projektu
Projekt představuje komplexní, plně lokální a nízkonákladový systém detekce průniků (NIDS) navržený primárně pro nasazení v menších lokálních sítích (SOHO) využívajících protokol IPv4. Cílem řešení je demonstrovat, že pokročilá kybernetická bezpečnost a behaviorální analýza sítě není výsadou pouze velkých korporátních infrastruktur.

Systém využívá pasivní monitorování provozu (pomocí funkce Port Mirroring na chytrém switchi), takže do sítě aktivně nezasahuje a v případě selhání nezpůsobí její výpadek. Je postaven na levném mikropočítači Raspberry Pi 5 a plně využívá moderních open-source technologií.

🛡️ Klíčové vlastnosti (Hybridní detekční model)
Systém kombinuje dva přístupy pro zajištění maximální bezpečnosti:

1. Signaturní detekce (Pravidla)
Neznámá zařízení: Detekce cizích MAC adres vůči dynamickému Whitelistu.
ARP Spoofing: Detekce útoků typu Man-in-the-Middle pomocí heuristiky na L3 vrstvě.
Mapování sítě: Pokročilá identifikace vertikálního a horizontálního skenování portů (Nmap, stealth scany).
Nadměrný datový tok: Hlídání neobvyklých objemů stahování a detekce potenciální exfiltrace dat.
Škodlivé domény: Kontrola překladu DNS a šifrované SNI komunikace vůči zavedeným Blacklistům (AdBlock seznamy).

2. Behaviorální analýza (Strojové učení)
Využívá algoritmus Isolation Forest pro učení bez učitele (Unsupervised learning).
Model se sám naučí "normální" profil chování vaší sítě (Baseline).
Detekuje nestandardní odchylky v reálném čase bez nutnosti psát na ně specifická pravidla (inovativní identifikace tichých a neznámých hrozeb).
Podpora vysoce citlivého režimu AWAY (pro sledování sítě v době nepřítomnosti uživatelů) a režimu HOME.



⚙️ Architektura a použité technologie
Architektura je logicky rozdělena do čtyř vrstev:

- Sběr a normalizace: Zeek zpracovává surové pakety a převádí je do strukturovaných JSON logů.
- Analytické jádro: Autorský Python skript (s využitím knihoven Pandas a Scikit-Learn) provádí Feature Engineering do časových oken a vyhodnocuje události.
- Úložiště: Rychlá time-series databáze InfluxDB pro záznam událostí a metrik.
- Vizualizace a varování: Grafana poskytuje interaktivní dashboardy a zajišťuje okamžité notifikace skrze webové webhooky na Discord.
