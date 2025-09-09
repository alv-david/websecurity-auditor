import pandas as pd
import os
import json
import tkinter as tk
from tkinter import filedialog
from colorama import Fore, Style, init
import requests

from modules.sechead import analyze_host
from modules.exporter import export_json
from modules import sslauditor
from modules import bola_idor
# from modules import subdomain_takeover
from modules import dir_fuzz

init(autoreset=True)

def load_config(json_path):
    with open(json_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def read_hosts_file(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    if ext in [".xls", ".xlsx"]:
        df = pd.read_excel(file_path, header=None)
    elif ext == ".csv":
        df = pd.read_csv(file_path, header=None)
    elif ext == ".txt":
        df = pd.read_csv(file_path, header=None)
    else:
        raise Exception("Formato não suportado! Use .csv, .xls, .xlsx ou .txt")
    return [str(h).strip() for h in df.iloc[:, 0].dropna().unique() if str(h).strip()]

def select_hosts_file():
    """Seleciona arquivo contendo lista de URLs/hosts"""
    root = tk.Tk()
    root.withdraw()
    path = filedialog.askopenfilename(
        title="Selecionar arquivo com lista de Hosts/URLs",
        filetypes=[("Planilha ou texto", "*.xlsx *.xls *.csv *.txt")]
    )
    root.destroy()
    return path

def select_wordlist_file():
    """Seleciona arquivo de wordlist de diretórios (fuzzing)"""
    root = tk.Tk()
    root.withdraw()
    path = filedialog.askopenfilename(
        title="Escolher wordlist de diretórios",
        filetypes=[("Arquivo TXT", "*.txt")]
    )
    root.destroy()
    return path

def select_json_file():
    root = tk.Tk()
    root.withdraw()
    path = filedialog.askopenfilename(
        title="Abrir arquivo JSON",
        filetypes=[("Arquivo JSON", "*.json")]
    )
    root.destroy()
    return path

def select_output_file(suggestion="resultado.json"):
    root = tk.Tk()
    root.withdraw()
    path = filedialog.asksaveasfilename(
        defaultextension=".json",
        title="Salvar resultado",
        initialfile=suggestion,
        filetypes=[("Arquivo JSON", "*.json")]
    )
    root.destroy()
    return path

def limpar_terminal():
    os.system("cls" if os.name == "nt" else "clear")

def validar_url_https(url):
    url = url.strip()
    if url.lower().startswith("http://"):
        print("Somente URLs HTTPS/TLS.")
        return None
    if url.lower().startswith("https://"):
        return url
    dominio = url.replace("http://", "").replace("https://", "").split('/')[0]
    test_url = "https://" + dominio
    try:
        resp = requests.get(test_url, timeout=6)
        if resp.status_code == 200:
            return test_url
    except:
        pass
    return None

def normalizar_url(url):
    """Corrige URLs sem http/https, testando https primeiro"""
    url = url.strip()
    if url.startswith("http://") or url.startswith("https://"):
        return url.rstrip("/")

    test_https = f"https://{url}"
    try:
        requests.get(test_https, timeout=4)
        return test_https
    except:
        pass

    test_http = f"http://{url}"
    try:
        requests.get(test_http, timeout=4)
        return test_http
    except:
        pass

    return test_https  # fallback

def print_cli_result(analysis, config, score_info=None):
    print(f"{Fore.LIGHTCYAN_EX}--- Security Headers ---")
    for cwe, data in analysis['cwe'].items():
        desc = config.get('cwe_descriptions', {}).get(cwe, '-')
        if any([data['security_headers'], data['missing_security_headers'], data['sensitive_headers']]):
            print(f"{Fore.LIGHTCYAN_EX}\n[{cwe}] {desc}")
            for h in data['security_headers']:
                valor = h.get('valor', '')
                if h["header"].lower() == "x-xss-protection":
                    if h.get('cor') == 'verde':
                        print(f"  {Fore.GREEN}{h['header']} (Desativado, OK)")
                    else:
                        print(f"  {Fore.YELLOW}{h['header']} (ATIVO) → Valor: {valor}")
                else:
                    print(f"  {Fore.GREEN}{h['header']}: {valor}")
            for h in data['missing_security_headers']:
                print(f"  {Fore.RED}{h} (faltante)")
            for h in data['sensitive_headers']:
                print(f"  {Fore.LIGHTMAGENTA_EX}{h['header']}: {h['valor']}")
    if "tls" in analysis:
        tls_info = analysis["tls"]
        color = Fore.GREEN if tls_info.get("seguro") else Fore.RED
        print(f"\nTLS: {color}{tls_info.get('versao')}{Style.RESET_ALL}")
    if score_info:
        print(f"\nSCORE: {score_info['score']}/100 → {score_info['rating']['label']} ({score_info['rating']['color']})")
    print(f"{Fore.LIGHTWHITE_EX}\nMais info: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html\n")

def print_simple_batch_result(results, config=None):
    for analysis in results:
        host = analysis.get("host", "[Host não identificado]")
        status_code = analysis.get("status_code", "N/A")
        print(f"\n{Fore.LIGHTCYAN_EX}HOST: {host}")
        print(f"STATUS CODE: {status_code}")

def importar_resultados():
    file_path = select_json_file()
    if not file_path or not os.path.exists(file_path):
        print("Arquivo não encontrado ou não selecionado.")
        return
    with open(file_path, 'r', encoding='utf-8') as f:
        results = json.load(f)
    if isinstance(results, dict):
        results = [results]
    print_simple_batch_result(results)

def perguntar_salvar_resultado(sugestao_nome, resultado):
    resp = input("\nSalvar resultados? (S/n): ").strip().lower()
    if resp in ['', 's', 'sim']:
        file_path = select_output_file(suggestion=sugestao_nome)
        if file_path:
            export_json(resultado, file_path)
            print(f"Arquivo salvo em: {file_path}")

def avaliar_tls(host, score_conf):
    versao = sslauditor.check_tls_version(host)
    seguro = versao in ["TLSv1.2", "TLSv1.3"]
    return {"versao": versao, "seguro": seguro, "penalty": None if seguro else "insecure_tls"}

def calcular_score(analysis, score_conf):
    score = score_conf['base_score']
    for cwe_data in analysis.get("cwe", {}).values():
        for _ in cwe_data.get('missing_security_headers', []):
            score -= score_conf['penalties'].get("missing_security_header", 0)
        for h in cwe_data.get('sensitive_headers', []):
            penalty = h.get("penalty", "sensitive_header_present")
            score -= score_conf['penalties'].get(penalty, 0)
    tls_info = analysis.get("tls")
    if tls_info and tls_info.get("penalty"):
        score -= score_conf['penalties'].get(tls_info["penalty"], 0)
    score = max(score, 0)
    rating = next((v for k,v in score_conf['ratings'].items() if score >= v['min']), None)
    return {"score": score, "rating": rating}

def escolher_tipo_scan():
    print("Tipo de análise:\n1. Web\n2. API Backend")
    t = input("Escolha: ").strip()
    if t == "1":
        return "headers_web.json", "score_criteria_web.json"
    elif t == "2":
        return "headers_api_backend.json", "score_criteria_api.json"
    else:
        return None, None


def main():
    limpar_terminal()
    print("Selecione:")
    print("1. Headers (scan individual)")
    print("2. Headers (scan múltiplo)")
    print("3. Importar JSON")
    print("4. Testar BOLA/IDOR")

    opt = input("Opção: ").strip()

    if opt in ["1", "2"]:
        cf_headers, cf_score = escolher_tipo_scan()
        if not cf_headers:
            return
        config = load_config(os.path.join("config", cf_headers))
        score_conf = load_config(os.path.join("config", cf_score))

    if opt == "1":
        url = validar_url_https(input("URL: ").strip())
        if not url: return
        analysis = analyze_host(url, config)
        host = url.split("://")[-1].split("/")[0]
        analysis["tls"] = avaliar_tls(host, score_conf)
        score_info = calcular_score(analysis, score_conf)
        print_cli_result(analysis, config, score_info)
        perguntar_salvar_resultado(f"resultado_{host}.json", analysis)

    elif opt == "2":
        file_in = select_hosts_file()
        if not file_in: return
        hosts = read_hosts_file(file_in)
        results = []
        for h in hosts:
            url = validar_url_https(h)
            if not url: continue
            analysis = analyze_host(url, config)
            hostn = url.split("://")[-1].split("/")[0]
            analysis["tls"] = avaliar_tls(hostn, score_conf)
            results.append(analysis)
        print_simple_batch_result(results, config)
        perguntar_salvar_resultado("resultado_lote.json", results)

    elif opt == "3":
        importar_resultados()

    elif opt == "4":
        file_path = select_json_file()
        if file_path:
            bola_idor.test_bola_idor(file_path)

    elif opt == "6":
        print("1. URL única")
        print("2. Lista via arquivo")
        modo = input("Opção: ").strip()

        if modo == "1":
            print("\n[Etapa 1/2] Informe a URL ou domínio para teste")
            url = input("Digite a URL ou domínio: ").strip()
            if not url:
                print("[ERRO] Nenhuma URL informada.")
                return
            urls_norm = [normalizar_url(url)]

        elif modo == "2":
            print("\n[Etapa 1/2] Selecionar arquivo contendo lista de URLs/hosts")
            file_path = select_hosts_file()
            if not file_path:
                print("[ERRO] Nenhum arquivo informado.")
                return
            urls = read_hosts_file(file_path)
            urls_norm = [normalizar_url(u) for u in urls]

        print("\n[Etapa 2/2] Selecione agora a wordlist de diretórios para o fuzzing")
        wl_path = select_wordlist_file()
        if not wl_path:
            print("[ERRO] Nenhuma wordlist informada. Cancelando fuzzing.")
            return

        print(f"\n[Iniciando fuzzing em {len(urls_norm)} alvo(s)] Wordlist: {os.path.basename(wl_path)}\n" + "-"*55)
        dir_fuzz.fuzz_multiple_targets(urls_norm, wordlist_file=wl_path, output_file="fuzz_results.json")

if __name__ == "__main__":
    main()
