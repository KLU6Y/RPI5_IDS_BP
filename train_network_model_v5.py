import gzip
import json
import os
import pandas as pd
import joblib
import glob
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Tento modul zahrnuje přípravu trénovacích dat a konstrukci detekčního modelu
# založeného na archivovaných Zeek síťových logech. Cílem je vytvořit dvě
# odlišné charakterizace denního provozu, které pomáhají rozlišit běžný provoz
# od neobvyklého chování v domácí síti.

# Kořenová cesta k adresáři obsahujícímu archivované denní složky se Zeek logy.
# Každý den je reprezentován samostatným adresářem, v němž se očekávají soubory
# conn.log.gz, dns.log.gz, http.log.gz a ssl.log.gz.
BASE_LOG_DIR = "/home/klugy/ARCHIVE"

# Definice referenčních období pro trénink modelů.
# QUIET_DAYS reprezentují období s nízkou aktivitou (pouze "away" režim),
# zatímco NORMAL_DAYS obsahují typický domácí provoz pro režim "home".
QUIET_DAYS = ["2026-03-06", "2026-03-07", "2026-03-08", "2026-03-09", "2026-03-10", "2026-03-11", "2026-03-12", "2026-03-13"]
NORMAL_DAYS = ["2026-03-15", "2026-03-16", "2026-03-17", "2026-03-18", "2026-03-19", "2026-03-20", "2026-03-21", "2026-03-22"]


def load_zeek_logs(day_path, log_type):
    """
    Načte všechny dostupné gzipované Zeek logy daného typu z cílové složky,
    dekóduje je jako JSON a vrátí je jako Pandas DataFrame.

    Parametry:
    - day_path: cesta ke složce se soubory pro konkrétní den
    - log_type: typ logu (např. conn, dns, http, ssl)

    Pokud logy existují v rotovaném formátu, použije se vzor s hvězdičkou.
    V opačném případě se pokusí načíst základní soubor bez rotace.
    """
    search_pattern = os.path.join(day_path, f"{log_type}.*.log.gz")
    files = glob.glob(search_pattern)

    if not files:
        base_file = os.path.join(day_path, f"{log_type}.log.gz")
        if os.path.exists(base_file):
            files = [base_file]

    combined_data = []
    for file in files:
        try:
            with gzip.open(file, 'rt') as f:
                for line in f:
                    # Příchozí řádky mohou obsahovat hlavičky Zeek, které je třeba ignorovat.
                    if line.startswith('#'):
                        continue
                    combined_data.append(json.loads(line))
        except Exception as e:
            print(f"Chyba pri cteni {file}: {e}")

    return pd.DataFrame(combined_data)


def extract_features(day_folder):
    """
    Zpracuje Zeek logy pro zadaný den do minutové agregační matice příznaků.

    Funkce vrátí DataFrame s časovým indexem o kroku 1 minuta, ve kterém jsou
    shrnuty základní metriky datového toku, počty unikátních cílových portů
    a IP adres, typy protokolů a informace o selhaných spojení.

    Parametry:
    - day_folder: název složky s denními logy v adresáři BASE_LOG_DIR
    """
    path = os.path.join(BASE_LOG_DIR, day_folder)
    print(f"--- Agreguji data ze slozky: {day_folder} ---")

    df_conn = load_zeek_logs(path, "conn")
    df_dns = load_zeek_logs(path, "dns")
    df_http = load_zeek_logs(path, "http")
    df_ssl = load_zeek_logs(path, "ssl")

    if df_conn.empty:
        return None

    # Převede unixová časová razítka na objekt datetime pro resampling podle času.
    df_conn['ts'] = pd.to_datetime(df_conn['ts'], unit='s')
    # Zařadí do dat známky chybějící nebo nedefinované délky spojení jako nulu.
    df_conn['duration'] = pd.to_numeric(df_conn['duration'], errors='coerce').fillna(0)

    # Vytvoří binární indikátory protokolů pro souhrnné statistiky.
    if 'proto' in df_conn.columns:
        df_conn['is_tcp'] = (df_conn['proto'] == 'tcp').astype(int)
        df_conn['is_udp'] = (df_conn['proto'] == 'udp').astype(int)
        df_conn['is_icmp'] = (df_conn['proto'] == 'icmp').astype(int)
    else:
        df_conn['is_tcp'] = df_conn['is_udp'] = df_conn['is_icmp'] = 0

    # Identifikuje selhaná spojení, která mohou indikovat skenování portů nebo
    # zneužití síťových služeb.
    if 'conn_state' in df_conn.columns:
        df_conn['failed_conns'] = df_conn['conn_state'].isin(['REJ', 'S0', 'S1', 'OTHR']).astype(int)
    else:
        df_conn['failed_conns'] = 0

    # Agreguje napříč jednotlivými minutovými intervaly tak, aby vznikla časová
    # řada s jedním vzorkem za minutu.
    features = df_conn.resample('1Min', on='ts').agg({
        'orig_bytes': 'sum',
        'resp_bytes': 'sum',
        'id.resp_p': 'nunique',
        'id.resp_h': 'nunique',
        'is_tcp': 'sum',
        'is_udp': 'sum',
        'is_icmp': 'sum',
        'failed_conns': 'sum',
        'duration': 'mean'
    }).fillna(0)

    # Připojí další protokolové zdroje jako DNS, HTTP a SSL podle časového indexu.
    if not df_dns.empty:
        df_dns['ts'] = pd.to_datetime(df_dns['ts'], unit='s')
        dns_res = df_dns.resample('1Min', on='ts').size().rename('dns_queries')
        features = features.join(dns_res).fillna(0)
    else:
        features['dns_queries'] = 0

    if not df_http.empty:
        df_http['ts'] = pd.to_datetime(df_http['ts'], unit='s')
        http_res = df_http.resample('1Min', on='ts').size().rename('http_count')
        features = features.join(http_res).fillna(0)
    else:
        features['http_count'] = 0

    if not df_ssl.empty:
        df_ssl['ts'] = pd.to_datetime(df_ssl['ts'], unit='s')
        ssl_res = df_ssl.resample('1Min', on='ts').size().rename('ssl_count')
        features = features.join(ssl_res).fillna(0)
    else:
        features['ssl_count'] = 0

    # Sloučí HTTP a SSL do jedné metriky webové aktivity, která reprezentuje
    # šíření zabezpečeného i nezabezpečeného webového provozu.
    features['web_activity'] = features['http_count'] + features['ssl_count']
    features = features.drop(columns=['http_count', 'ssl_count'])

    return features


def train(days, mode_name):
    """
    Vytvoří tréninkovou množinu a natrénuje model IsolationForest pro daný režim.

    Parametry:
    - days: seznam datových složek odpovídajících tréninkovým dnům
    - mode_name: název režimu, který se použije pro ukládání modelu a škálovače
    """
    all_dfs = []
    for day in days:
        df = extract_features(day)
        if df is not None:
            all_dfs.append(df)

    if not all_dfs:
        print(f"Zadna data pro {mode_name}!")
        return

    # Spojí agregované denní DataFrame do jedné tréninkové množiny.
    full_df = pd.concat(all_dfs)
    full_df = full_df.fillna(0)

    print(f"Trenuji model pro rezim: {mode_name} (vzorku: {len(full_df)})")

    # Normalizuje měřítka jednotlivých příznaků pro stabilní fungování IsolationForest.
    scaler = StandardScaler()
    scaled_data = scaler.fit_transform(full_df)

    # Trénuje izolovaný les s očekávanou mírou kontaminace 1 %.
    model = IsolationForest(n_estimators=150, contamination=0.01, random_state=42)
    model.fit(scaled_data)

    joblib.dump(model, f"model_{mode_name}.pkl")
    joblib.dump(scaler, f"scaler_{mode_name}.pkl")
    joblib.dump(list(full_df.columns), f"columns_{mode_name}.pkl")

    print(f" Hotovo: model_{mode_name}.pkl a scaler_{mode_name}.pkl")
    print(f"Vygenerovane sloupce: {list(full_df.columns)}\n")


if __name__ == "__main__":
    train(QUIET_DAYS, "away")
    train(NORMAL_DAYS, "home")