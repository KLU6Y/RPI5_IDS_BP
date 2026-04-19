import os
import json
import time
import joblib
import pandas as pd
import ipaddress
from datetime import datetime
from collections import defaultdict
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

# Tento skript provádí nepřetržité sledování Zeek logů.
# Detekce anomálií kombinuje heuristická kritéria (např. skenování portů,
# zakázané domény, neznámé MAC adresy) s předtrénovaným modelem pro
# strukturální anomálie.
SPOOL_DIR = "/opt/zeek/spool/zeek"
MODE_FILE = "/home/klugy/MAC_detekce/AWAY_MODE.lock"

LOGS = {
    "conn": os.path.join(SPOOL_DIR, "conn.log"),
    "dns": os.path.join(SPOOL_DIR, "dns.log"),
    "http": os.path.join(SPOOL_DIR, "http.log"),
    "ssl": os.path.join(SPOOL_DIR, "ssl.log")
}

# Cesty ke konfiguračním souborům, které se mohou v průběhu běhu aplikace
# dynamicky aktualizovat.
WHITELIST_FILE = "/home/klugy/MAC_detekce/WhitelistMAC.csv"
VENDORS_FILE = "/home/klugy/MAC_detekce/mac-vendor.txt"
BANNED_DIR = "/home/klugy/MAC_detekce/Banned"
ALERT_INTERVAL = 30
ROUTER_IP = "192.168.69.254"

INFLUX_URL = "http://localhost:8086"
INFLUX_TOKEN = "VÁŠ_TOKEN"
INFLUX_ORG = "home"
INFLUX_BUCKET = "zeek"

# Globální proměnné uchovávají průběžná agregovaná data, kontextové struktury
# a předem načtené artefakty modelu, které jsou potřeba při každé iteraci
# monitorovací smyčky.
ts = datetime.now().strftime('%H:%M:%S')
print(f"[{ts}] [SYSTEM] Nacitam ML modely a scalery...")

# Načtené modely a škálovače pro jednotlivé režimy provozu.
models = {
    "home": joblib.load("model_home.pkl"),
    "away": joblib.load("model_away.pkl")
}
scalers = {
    "home": joblib.load("scaler_home.pkl"),
    "away": joblib.load("scaler_away.pkl")
}
feature_cols = joblib.load("columns_home.pkl")

# Aktuální agregovaná statistika pro minutové vyhodnocení.
ml_stats = {
    "orig_bytes": 0, "resp_bytes": 0,
    "unique_ports": set(), "unique_ips": set(),
    "tcp": 0, "udp": 0, "icmp": 0,
    "dns_queries": 0, "web_activity": 0,
    "total_duration": 0.0, "duration_count": 0,
    "failed_conns": 0
}

# Pomocné kontejnery uchovávají kontextové informace o přenesených datech
# a počtech spojení pro jednotlivé IP adresy, cíle a služby.
ctx_bytes = {"ip": defaultdict(int), "dest_ips": defaultdict(int), "proto_port": defaultdict(int)}
ctx_count = {"ip": defaultdict(int), "dest_ips": defaultdict(int), "proto_port": defaultdict(int), "domains": defaultdict(int)}

# Sady a čítače pro monitorování potenciálních útočníků podle unikátních
# cílových portů, adres a selhaných spojení.
attacker_u_ports = defaultdict(set)
attacker_u_ips = defaultdict(set)
attacker_local_ips = defaultdict(set)
attacker_fails = defaultdict(int)

# Mapování mezi IP adresami, MAC adresami a doménami pro následnou
# identifikaci zařízení a cílových služeb.
ip_to_mac = {}
ip_to_domain = {}
known_ip_mac_map = {}
arp_alert_cooldown = {}

# Stav pro detekci zakázaných domén a jejich četnosti.
banned_hits = defaultdict(int)
banned_domains_set = set()

mac_state = {
    "whitelist": {}, "vendors": {},
    "last_mtime": 0, "last_reported": {}, "last_check": time.time()
}
banned_state = {"last_mtime": 0, "last_check": time.time()}

# Helper funkce poskytují abstrahovaný přístup k souborovým zdrojům,
# aktualizují kontext a transformují externí konfigurace do interních
# datových struktur.
def load_whitelist():
    """
    Načte seznam povolených MAC adres z CSV souboru.

    Vrátí mapu MAC -> popis zařízení. Slouží ke snížení falešných poplachů
    u známých místních zařízení.
    """
    wl = {}
    try:
        df = pd.read_csv(WHITELIST_FILE, sep=';')
        name_col = next((col for col in df.columns if col.lower() in ['name', 'device', 'zarizeni', 'nazev']), None)
        for _, row in df.iterrows():
            mac = str(row['MAC']).strip().lower()
            name = str(row[name_col]).strip() if name_col else "Zname zarizeni"
            wl[mac] = name
        return wl
    except Exception:
        return {}

def load_vendors():
    """
    Načte databázi výrobců podle MAC OUI.

    Výstupem je slovník prefix -> název výrobce, který se používá pro bližší
    identifikaci anonymních zařízení.
    """
    v_db = {}
    try:
        with open(VENDORS_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(maxsplit=1)
                if len(parts) == 2:
                    v_db[parts[0].strip().lower()] = parts[1].strip()
        return v_db
    except Exception:
        return {}

def load_banned_domains():
    """
    Načte zakázané domény ze složky s listy a normalizuje je pro porovnání.

    Podporuje formát Adblock/hosts, kde se ignorují komentáře a speciální
    konstrukce.
    """
    b_set = set()
    if not os.path.exists(BANNED_DIR):
        os.makedirs(BANNED_DIR)
        return b_set
    for filename in os.listdir(BANNED_DIR):
        if filename.endswith(".txt"):
            filepath = os.path.join(BANNED_DIR, filename)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        d = line.strip().lower()
                        if not d or d.startswith('!') or d.startswith('#') or d.startswith('['):
                            continue
                        d = d.replace('||', '').split('^')[0].strip()
                        if d:
                            b_set.add(d)
            except Exception:
                pass
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [SYSTEM] Nacteno {len(b_set)} zakazanych domen.")
    return b_set

def get_banned_mtime():
    if not os.path.exists(BANNED_DIR): return 0
    max_mtime = os.stat(BANNED_DIR).st_mtime
    for f in os.listdir(BANNED_DIR):
        if f.endswith(".txt"): max_mtime = max(max_mtime, os.stat(os.path.join(BANNED_DIR, f)).st_mtime)
    return max_mtime

def get_device_info(mac):
    if mac in mac_state["whitelist"]: return mac_state["whitelist"][mac]
    return mac_state["vendors"].get(mac.replace(':', '')[:6], "Neznamy vyrobce")

def get_device_vendor(mac):
    return mac_state["vendors"].get(mac.replace(':', '')[:6], "Neznamy")

def check_files_update():
    now = time.time()
    if now - mac_state["last_check"] > 2:
        try:
            current_mtime = os.path.getmtime(WHITELIST_FILE)
            if current_mtime > mac_state["last_mtime"]:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [SYSTEM] Whitelist aktualizovan z disku")
                mac_state["whitelist"] = load_whitelist()
                mac_state["last_mtime"] = current_mtime
        except OSError: pass
        try:
            current_b_mtime = get_banned_mtime()
            if current_b_mtime > banned_state["last_mtime"]:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [SYSTEM] Zmena ve slozce Banned! Aktualizuji seznam...")
                global banned_domains_set
                banned_domains_set = load_banned_domains()
                banned_state["last_mtime"] = current_b_mtime
        except OSError: pass
        mac_state["last_check"] = now

def get_current_mode(): 
    return "away" if os.path.exists(MODE_FILE) else "home"

def open_log_tail(filepath):
    if not os.path.exists(filepath): return None
    f = open(filepath, 'r')
    f.seek(0, 2)
    return f

def check_banned(domain, ip):
    if not domain or not ip or ":" in ip: return
    domain = domain.lower().strip().rstrip('.')
    parts = domain.split('.')
    for i in range(len(parts)):
        sub = '.'.join(parts[i:])
        if sub in banned_domains_set:
            banned_hits[(ip, sub)] += 1
            break

# Zpracování jednotlivých záznamů logů provádí rozpoznání relevantních
# metrik, aktualizaci detekčních struktur a zařazení okamžitého kontextu
# do kumulativních statistik.
def process_line(log_type, line, write_api, mode):
    """
    Zpracuje jeden řádek logu podle typu a aktualizuje interní detekční statistiky.

    Kód rozlišuje spojení, DNS a webový provoz a akumuluje metriky pro
    následnou minutovou evaluaci.
    """
    if line.startswith('#'):
        return
    try:
        data = json.loads(line)
        orig_h = data.get("id.orig_h", "")
        resp_h = data.get("id.resp_h", "")
        if ":" in orig_h or ":" in resp_h: return

        log_ts = data.get("ts")
        if log_ts:
            connection_end = log_ts + data.get("duration", 0)
            if (time.time() - connection_end) > 600: return

        if log_type == "conn":
            mac = data.get("orig_l2_addr", "").lower()
            ip = orig_h
            
            if ip and ip != "unknown" and ip != "0.0.0.0" and mac:
                if ip in known_ip_mac_map:
                    if known_ip_mac_map[ip] != mac:
                        now = time.time()
                        if ip not in arp_alert_cooldown or (now - arp_alert_cooldown[ip]) > 60:
                            ts = datetime.now().strftime('%H:%M:%S')
                            old_mac = known_ip_mac_map[ip]
                            print(f"[{ts}] [{mode.upper()}] ANOMALIE: ARP Spoofing detekovan na L3! IP {ip} zmenila MAC z {old_mac} na {mac}")
                            p = Point("anomaly_arp_spoof").tag("mode", mode).tag("mac", mac).tag("old_mac", old_mac).field("ip", ip)
                            write_api.write(bucket=INFLUX_BUCKET, record=p)
                            arp_alert_cooldown[ip] = now
                        known_ip_mac_map[ip] = mac
                else:
                    known_ip_mac_map[ip] = mac

            if mac and mac not in mac_state["whitelist"] and ip:
                now = time.time()
                if mac not in mac_state["last_reported"] or (now - mac_state["last_reported"][mac]) > ALERT_INTERVAL:
                    vendor = get_device_vendor(mac)
                    ts = datetime.now().strftime('%H:%M:%S')
                    print(f"[{ts}] [{mode.upper()}] ANOMALIE: Neznama MAC | MAC: {mac} ({vendor}) | IP: {ip}")
                    p = Point("anomaly_unknown_mac").tag("mode", mode).tag("mac", mac).tag("vendor", vendor).field("ip", ip)
                    write_api.write(bucket=INFLUX_BUCKET, record=p)
                    mac_state["last_reported"][mac] = now

            c_state = data.get("conn_state", "")
            if c_state in ["REJ", "S0", "S1", "OTHR"]: 
                ml_stats["failed_conns"] += 1
                if ip and ip != "unknown": attacker_fails[ip] += 1

            o_bytes = data.get("orig_bytes", 0)
            r_bytes = data.get("resp_bytes", 0)
            total_bytes = o_bytes + r_bytes
            
            try: dur = float(data.get("duration", 0))
            except ValueError: dur = 0.0
            
            ml_stats["total_duration"] += dur
            ml_stats["duration_count"] += 1
            ml_stats["orig_bytes"] += o_bytes
            ml_stats["resp_bytes"] += r_bytes
            
            resp_p = data.get("id.resp_p")
            proto = data.get("proto", "")
            
            if resp_p: ml_stats["unique_ports"].add(resp_p)
            if resp_h: ml_stats["unique_ips"].add(resp_h)
            
            if proto == "tcp": ml_stats["tcp"] += 1
            elif proto == "udp": ml_stats["udp"] += 1
            elif proto == "icmp": ml_stats["icmp"] += 1
            
            if ip and ip != "unknown":
                ctx_bytes["ip"][ip] += total_bytes
                ctx_count["ip"][ip] += 1
                ip_to_mac[ip] = mac
                if resp_p: attacker_u_ports[ip].add(resp_p)
                if resp_h: 
                    attacker_u_ips[ip].add(resp_h)
                    try:
                        if ipaddress.ip_address(resp_h).is_private:
                            attacker_local_ips[ip].add(resp_h)
                    except ValueError: pass
                
            if resp_h:
                ctx_bytes["dest_ips"][resp_h] += total_bytes
                ctx_count["dest_ips"][resp_h] += 1
            if proto and resp_p:
                proto_port = f"{proto.upper()}/{resp_p}"
                ctx_bytes["proto_port"][proto_port] += total_bytes
                ctx_count["proto_port"][proto_port] += 1

        elif log_type == "dns":
            ml_stats["dns_queries"] += 1
            query = data.get("query")
            if query: 
                ctx_count["domains"][query] += 1
                check_banned(query, orig_h)
                for ans in data.get("answers", []):
                    if "." in ans and ":" not in ans: ip_to_domain[ans] = query
                
        elif log_type in ["http", "ssl"]:
            ml_stats["web_activity"] += 1
            domain = data.get("host") or data.get("server_name")
            if domain:
                ctx_count["domains"][domain] += 1
                check_banned(domain, orig_h)
                if resp_h: ip_to_domain[resp_h] = domain
            
    except json.JSONDecodeError: pass

# Hlavní smyčka orchestrace spojení logů, periodicita vyhodnocení,
# přepínání režimů a záznam výsledků do InfluxDB.
def run_ml_monitor():
    mac_state["whitelist"] = load_whitelist()
    mac_state["vendors"] = load_vendors()
    if os.path.exists(WHITELIST_FILE): mac_state["last_mtime"] = os.path.getmtime(WHITELIST_FILE)
    
    global banned_domains_set
    banned_domains_set = load_banned_domains()
    banned_state["last_mtime"] = get_banned_mtime()
    
    client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
    write_api = client.write_api(write_options=SYNCHRONOUS)
    
    file_handles = {}
    for ltype, path in LOGS.items():
        fh = open_log_tail(path)
        if fh: file_handles[ltype] = fh
        
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] [SYSTEM] SITOVY MONITORING SPUSTEN...")
    last_eval_time = time.time()
    
    try:
        while True:
            current_time = time.time()
            data_read = False
            check_files_update()
            mode = get_current_mode()
            
            for ltype, path in LOGS.items():
                fh = file_handles.get(ltype)
                if fh:
                    try:
                        current_inode = os.stat(path).st_ino
                        active_inode = os.fstat(fh.fileno()).st_ino
                        if current_inode != active_inode:
                            ts = datetime.now().strftime('%H:%M:%S')
                            print(f"[{ts}] [{mode.upper()}] UPOZORNENI: Detekovana pulnocni rotace logu ({ltype}). Ctu novy soubor.")
                            fh.close()
                            fh = open(path, 'r')
                            file_handles[ltype] = fh
                    except OSError: pass
                    line = fh.readline()
                    if line:
                        process_line(ltype, line, write_api, mode)
                        data_read = True
                else:
                    new_fh = open_log_tail(path)
                    if new_fh: file_handles[ltype] = new_fh
            
            if not data_read: time.sleep(0.1)
                
            if current_time - last_eval_time >= 60:
                total_conns = ml_stats["tcp"] + ml_stats["udp"] + ml_stats["icmp"]
                u_ports = len(ml_stats["unique_ports"])
                u_ips = len(ml_stats["unique_ips"])
                up_mb = round(ml_stats["orig_bytes"] / 1048576, 2)
                down_mb = round(ml_stats["resp_bytes"] / 1048576, 2)
                fail_ratio = ml_stats["failed_conns"] / total_conns if total_conns > 0 else 0

                top_ip_bytes = max(ctx_bytes["ip"], key=ctx_bytes["ip"].get) if ctx_bytes["ip"] else "N/A"
                top_dest_bytes = max(ctx_bytes["dest_ips"], key=ctx_bytes["dest_ips"].get) if ctx_bytes["dest_ips"] else "N/A"
                top_svc_bytes = max(ctx_bytes["proto_port"], key=ctx_bytes["proto_port"].get) if ctx_bytes["proto_port"] else "N/A"
                mac_bytes = ip_to_mac.get(top_ip_bytes, "")
                dev_bytes = get_device_info(mac_bytes)
                dom_bytes = ip_to_domain.get(top_dest_bytes, "Zadna")

                top_ip_conns = max(ctx_count["ip"], key=ctx_count["ip"].get) if ctx_count["ip"] else "N/A"
                top_dest_conns = max(ctx_count["dest_ips"], key=ctx_count["dest_ips"].get) if ctx_count["dest_ips"] else "N/A"
                top_svc_conns = max(ctx_count["proto_port"], key=ctx_count["proto_port"].get) if ctx_count["proto_port"] else "N/A"
                conns_max = ctx_count["ip"].get(top_ip_conns, 0)
                mac_conns = ip_to_mac.get(top_ip_conns, "")
                dev_conns = get_device_info(mac_conns)
                dom_conns = ip_to_domain.get(top_dest_conns, "Zadna")
                
                top_attacker_ip = max(attacker_fails, key=attacker_fails.get) if attacker_fails else top_ip_conns
                atk_conns = ctx_count["ip"].get(top_attacker_ip, 0)
                atk_fails = attacker_fails.get(top_attacker_ip, 0)
                atk_fail_ratio = atk_fails / atk_conns if atk_conns > 0 else 0
                atk_mac = ip_to_mac.get(top_attacker_ip, "")
                atk_dev = get_device_info(atk_mac)

                anomalies_detected = []

                # 1. Analýza objemového provozu pro detekci nadměrných toků dat
                if up_mb > 50 or down_mb > 100:
                    anomalies_detected.append({
                        "table": "anomaly_high_traffic", "label": "Nadmerny datovy prenos",
                        "ip": top_ip_bytes, "mac": mac_bytes, "dev": dev_bytes, "dest": top_dest_bytes, "svc": top_svc_bytes, "dom": dom_bytes,
                        "extra": f"[Prijato: {down_mb}MB, Odeslano: {up_mb}MB]", "up": up_mb, "down": down_mb,
                        "value_key": "total_mb", "value_val": up_mb + down_mb
                    })

                # 2. Heuristická analýza skenovacích vzorů v lokální a externí síti
                if top_attacker_ip != "N/A" and top_attacker_ip != ROUTER_IP:
                    def get_dest_str(ip_set, is_local=False):
                        count = len(ip_set)
                        if count == 1: return list(ip_set)[0]
                        if 1 < count <= 3: return f"IP: {', '.join(map(str, sorted(ip_set)))}"
                        return f"Lokální síť ({count} IP)" if is_local else f"Externí síť ({count} IP)"
                    def get_svc_str(port_set):
                        count = len(port_set)
                        if count == 1: return str(list(port_set)[0])
                        if 1 < count <= 5: return f"Porty: {', '.join(map(str, sorted(port_set)))}"
                        return f"Více portů ({count})"

                    s_ports = attacker_u_ports[top_attacker_ip]
                    s_local_ips = attacker_local_ips[top_attacker_ip]
                    s_total_ips = attacker_u_ips[top_attacker_ip]
                    u_ports_atk = len(s_ports)
                    u_total_ips_atk = len(s_total_ips)
                    u_local_ips_atk = len(s_local_ips)

                    # A. Vertikální Port Sken
                    if u_ports_atk > 100 and u_total_ips_atk <= 3 and atk_fail_ratio > 0.2:
                        anomalies_detected.append({
                            "table": "anomaly_port_scan", "label": "Vertikální Port Sken",
                            "ip": top_attacker_ip, "mac": atk_mac, "dev": atk_dev,
                            "dest": get_dest_str(s_total_ips, is_local=(u_local_ips_atk > 0)),
                            "svc": get_svc_str(s_ports), "dom": "Zadna",
                            "extra": f"Intenzivní průzkum služeb ({atk_conns} spojení)",
                            "value_key": "connections", "value_val": atk_conns, "fail_ratio": atk_fail_ratio
                        })
                    # B. Horizontální síťový průzkum
                    elif u_local_ips_atk > 10 and u_ports_atk <= 5 and atk_fail_ratio > 0.25:
                        noisy_ports = ["137", "138", "1900", "5353", "7680", "9993"]
                        if not any(str(p) in str(top_svc_conns) for p in noisy_ports) or atk_fails > 50:
                            anomalies_detected.append({
                                "table": "anomaly_port_scan", "label": "Horizontální síťový průzkum",
                                "ip": top_attacker_ip, "mac": atk_mac, "dev": atk_dev,
                                "dest": get_dest_str(s_local_ips, True), 
                                "svc": get_svc_str(s_ports), "dom": "Zadna",
                                "extra": f"Mapování aktivních zařízení v LAN ({atk_conns} spojení)",
                                "value_key": "connections", "value_val": atk_conns, "fail_ratio": atk_fail_ratio
                            })
                    # C. Cílený průzkum služby
                    elif u_local_ips_atk >= 3 and u_ports_atk <= 2 and atk_fail_ratio > 0.3:
                        anomalies_detected.append({
                            "table": "anomaly_port_scan", "label": "Cílený průzkum služby",
                            "ip": top_attacker_ip, "mac": atk_mac, "dev": atk_dev,
                            "dest": get_dest_str(s_local_ips, True), 
                            "svc": get_svc_str(s_ports), "dom": "Zadna",
                            "extra": f"Hledání konkrétní služby napříč LAN ({atk_conns} spojení)",
                            "value_key": "connections", "value_val": atk_conns, "fail_ratio": atk_fail_ratio
                        })
                    # D. Heuristický anomální sken
                    elif atk_fails > 100 and atk_fail_ratio > 0.4:
                        anomalies_detected.append({
                            "table": "anomaly_port_scan", "label": "Heuristický anomální sken",
                            "ip": top_attacker_ip, "mac": atk_mac, "dev": atk_dev,
                            "dest": get_dest_str(s_total_ips, is_local=(u_local_ips_atk > 0)),
                            "svc": get_svc_str(s_ports), "dom": "Zadna",
                            "extra": f"Vysokofrekvenční anomální provoz ({atk_conns} spojení)",
                            "value_key": "connections", "value_val": atk_conns, "fail_ratio": atk_fail_ratio
                        })

                # 3. Identifikace komunikace na zakázané domény
                if banned_hits:
                    for (b_ip, b_dom), b_count in banned_hits.items():
                        b_mac, b_dev = ip_to_mac.get(b_ip, ""), get_device_info(ip_to_mac.get(b_ip, ""))
                        anomalies_detected.append({
                            "table": "anomaly_banned_domain", "label": "Zakazana domena",
                            "ip": b_ip, "mac": b_mac, "dev": b_dev,
                            "dest": "DNS/Web", "svc": "N/A", "dom": b_dom,
                            "extra": f"{b_count} pokus/y", "value_key": "connections", "value_val": b_count
                        })
                    banned_hits.clear()

                # 4. Vyhodnocení strukturálních anomálií pomocí předtrénovaného modelu
                avg_duration = ml_stats["total_duration"] / ml_stats["duration_count"] if ml_stats["duration_count"] > 0 else 0.0
                vec_data = {
                    "orig_bytes": ml_stats["orig_bytes"], "resp_bytes": ml_stats["resp_bytes"],
                    "id.resp_p": u_ports, "id.resp_h": u_ips,
                    "is_tcp": ml_stats["tcp"], "is_udp": ml_stats["udp"], "is_icmp": ml_stats["icmp"],
                    "failed_conns": ml_stats["failed_conns"], "duration": avg_duration,
                    "dns_queries": ml_stats["dns_queries"], "web_activity": ml_stats["web_activity"]
                }
                vec_df = pd.DataFrame([vec_data])[feature_cols]
                vec_scaled = scalers[mode].transform(vec_df)
                
                if models[mode].predict(vec_scaled)[0] == -1:
                    already_caught = any(a["table"] in ["anomaly_high_traffic", "anomaly_port_scan"] for a in anomalies_detected)
                    if not already_caught:
                        if (up_mb + down_mb > 0.7) or (u_ips > 30) or (fail_ratio > 0.4):
                            share_conns = conns_max / total_conns if total_conns > 0 else 0
                            total_bytes = ml_stats["orig_bytes"] + ml_stats["resp_bytes"]
                            share_bytes = ctx_bytes["ip"].get(top_ip_bytes, 0) / total_bytes if total_bytes > 0 else 0
                            if share_bytes > (share_conns - 0.2) and (up_mb + down_mb) > 1.0:
                                ml_ip, ml_mac, ml_dev = top_ip_bytes, mac_bytes, dev_bytes
                                ml_dest, ml_svc, ml_dom = top_dest_bytes, top_svc_bytes, dom_bytes
                            else:
                                ml_ip, ml_mac, ml_dev = top_ip_conns, mac_conns, dev_conns
                                ml_dest, ml_svc, ml_dom = top_dest_conns, top_svc_conns, dom_conns

                            ml_extra_info = f"| Spojeni: {total_conns} | Unikatni IP: {u_ips} | Porty: {u_ports} | Chybovost: {round(fail_ratio*100)}%"
                            anomalies_detected.append({
                                "table": "anomaly_ml", "label": "Strukturalni anomalie provozu (ML)",
                                "ip": ml_ip, "mac": ml_mac, "dev": ml_dev,
                                "dest": ml_dest, "svc": ml_svc, "dom": ml_dom,
                                "extra": ml_extra_info, "value_key": "connections", "value_val": total_conns,
                                "ml_global_ips": u_ips, "ml_global_ports": u_ports, "ml_fail_ratio": fail_ratio,
                                "up": up_mb, "down": down_mb
                            })

                # Výstupní fáze: záznam detekovaných anomálií do logu a do InfluxDB
                ts = datetime.now().strftime('%H:%M:%S')
                if anomalies_detected:
                    for anomaly in anomalies_detected:
                        if anomaly['table'] == "anomaly_banned_domain":
                            print(f"[{ts}] [{mode.upper()}] ANOMALIE: {anomaly['label']} | IP {anomaly['ip']} ({anomaly['dev']}) | Domena: {anomaly['dom']} | {anomaly['extra']}")
                        else:
                            print(f"[{ts}] [{mode.upper()}] ANOMALIE: {anomaly['label']} | IP {anomaly['ip']} ({anomaly['dev']}) -> Cil: {anomaly['dest']} | Sluzba: {anomaly['svc']} | Domena: {anomaly['dom']} | {anomaly['extra']}")
                        
                        p = Point(anomaly["table"]).tag("mode", mode).tag("label", anomaly["label"]) \
                            .tag("ip", anomaly["ip"]).tag("mac", anomaly["mac"]).tag("device", anomaly["dev"]) \
                            .tag("dest_ip", anomaly["dest"]).field("service", anomaly["svc"]).field("domain", anomaly["dom"]) \
                            .field(anomaly["value_key"], anomaly["value_val"])
                        if "up" in anomaly: p.field("up_mb", anomaly["up"]).field("down_mb", anomaly["down"])
                        if anomaly['table'] == "anomaly_ml":
                            p.field("global_ips", anomaly["ml_global_ips"]).field("global_ports", anomaly["ml_global_ports"]).field("fail_ratio", anomaly["ml_fail_ratio"])
                        elif anomaly['table'] == "anomaly_port_scan":
                            p.field("fail_ratio", float(anomaly["fail_ratio"]))
                        write_api.write(bucket=INFLUX_BUCKET, record=p)
                else:
                    print(f"[{ts}] [{mode.upper()}] Provoz v norme | Spojeni: {total_conns} | Chybovost: {round(fail_ratio*100)}% | Porty: {u_ports} | IP: {u_ips} | Nejaktivnejsi zarizeni: {top_ip_conns} ({dev_conns} - {mac_conns})")
                    p_ok = Point("normal_traffic").tag("mode", mode).tag("top_ip", top_ip_conns).tag("top_mac", mac_conns).tag("device", dev_conns) \
                        .field("connections", total_conns).field("unique_ports", u_ports).field("unique_ips", u_ips).field("fail_ratio", fail_ratio)
                    write_api.write(bucket=INFLUX_BUCKET, record=p_ok)
                
                for k in ["orig_bytes", "resp_bytes", "tcp", "udp", "icmp", "dns_queries", "web_activity", "total_duration", "duration_count", "failed_conns"]: 
                    ml_stats[k] = 0
                ml_stats["unique_ports"].clear(); ml_stats["unique_ips"].clear()
                ctx_bytes["ip"].clear(); ctx_bytes["dest_ips"].clear(); ctx_bytes["proto_port"].clear()
                ctx_count["ip"].clear(); ctx_count["dest_ips"].clear(); ctx_count["proto_port"].clear(); ctx_count["domains"].clear()
                ip_to_mac.clear(); attacker_u_ports.clear(); attacker_u_ips.clear(); attacker_local_ips.clear(); attacker_fails.clear()
                last_eval_time = current_time

    except KeyboardInterrupt: print("\nUkoncuji monitoring...")
    finally:
        for fh in file_handles.values(): fh.close()
        client.close()

if __name__ == "__main__":
    run_ml_monitor()