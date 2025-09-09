import json
import os
import requests
import urllib3
import time
import pandas as pd
import yaml
from colorama import Fore, Style, init
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

payload_teste = {
    "id": 999999,
    "test": True,
    "msg": "BOLA/IDOR scan"
}

methods_with_body = {"POST", "PUT", "PATCH", "DELETE"}

def limpar_terminal():
    os.system("cls" if os.name == "nt" else "clear")

def read_hosts_file(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    if ext in [".xls", ".xlsx"]:
        df = pd.read_excel(file_path, header=None)
    elif ext == ".csv":
        df = pd.read_csv(file_path, header=None)
    elif ext == ".txt":
        df = pd.read_csv(file_path, header=None)
    else:
        raise Exception(f"Formato {ext} não suportado! Use .csv, .xls, .xlsx ou .txt")
    return [str(h).strip() for h in df.iloc[:, 0].dropna().unique() if str(h).strip()]

def read_yaml_routes(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    out_data = {}
    services = data.get("services", [])
    for service in services:
        host = service.get("host")
        protocol = service.get("protocol", "https")
        port = service.get("port", 443)
        routes = []
        for route in service.get("routes", []):
            route_data = {
                "methods": route.get("methods", ["GET"]),
                "paths": [p.lstrip("~") for p in route.get("paths", [])]
            }
            routes.append(route_data)
        if host:
            out_data.setdefault(host, []).append({
                "protocol": protocol,
                "port": port,
                "routes": routes
            })
    return out_data

def build_data_from_list(urls):
    out = {}
    for url in urls:
        if not url:
            continue
        try:
            proto, remainder = url.split("://", 1)
        except ValueError:
            proto = "https"
            remainder = url
        if "/" in remainder:
            host_port, path = remainder.split("/", 1)
            path = "/" + path
        else:
            host_port = remainder
            path = "/"
        if ":" in host_port:
            host, port = host_port.split(":")
            port = int(port)
        else:
            host = host_port
            port = 443 if proto == "https" else 80
        out.setdefault(host, []).append({
            "protocol": proto,
            "port": port,
            "routes": [{"methods": ["GET"], "paths": [path]}]
        })
    return out

def parse_custom_headers():
    headers_input = input(f"{Fore.YELLOW}Deseja adicionar headers extras? (ex: X-Forwarded-For: 1.1.1.1, User-Agent: teste) {Fore.CYAN}[Enter para pular]: {Style.RESET_ALL}").strip()
    custom_headers = {}
    if headers_input:
        for item in headers_input.split(","):
            if ":" in item:
                k, v = item.strip().split(":", 1)
                custom_headers[k.strip()] = v.strip()
    return custom_headers

def parse_custom_query():
    query_input = input(f"{Fore.YELLOW}Deseja adicionar parâmetros extras na URL? (ex: parametro=abc&teste=123) {Fore.CYAN}[Enter para pular]: {Style.RESET_ALL}").strip()
    return query_input

def parse_proxy_settings():
    proxy_input = input(f"{Fore.YELLOW}Deseja enviar as requests por um proxy? (ex: 127.0.0.1:8080) {Fore.CYAN}[Enter para pular]: {Style.RESET_ALL}").strip()
    if proxy_input:
        return {
            "http": f"http://{proxy_input}",
            "https": f"http://{proxy_input}"
        }
    return None

def append_query_to_url(url, extra_query):
    if not extra_query:
        return url
    if "?" in url:
        return url + "&" + extra_query
    else:
        return url + "?" + extra_query

def carregar_wordlist(caminho):
    if not os.path.exists(caminho):
        print(f"{Fore.RED}Arquivo de wordlist não encontrado: {caminho}{Style.RESET_ALL}")
        return []
    with open(caminho, "r", encoding="utf-8") as f:
        linhas = [linha.strip() for linha in f if linha.strip() and not linha.startswith("#")]
    return linhas

def gerar_urls_mutadas(url_original, valores_teste):
    urls_mutadas = []
    partes = urlparse(url_original)
    query_params = parse_qs(partes.query)
    for param in query_params:
        for valor in valores_teste:
            params_modificados = query_params.copy()
            params_modificados[param] = [valor]
            nova_query = urlencode(params_modificados, doseq=True)
            url_mutada = urlunparse(partes._replace(query=nova_query))
            urls_mutadas.append((param, valor, url_mutada))
    return urls_mutadas

# -------------------------------
# Funções principais
# -------------------------------

def processar_resposta(resp, metodo_rotulo, url, resultados, count_refs):
    status = resp.status_code
    try:
        preview = json.dumps(resp.json(), ensure_ascii=False)[:500]
    except ValueError:
        preview = resp.text[:500]

    if status in [200, 301, 302]:
        cores = {
            200: Fore.RED + "[200 POSSÍVEL IDOR]" + Style.RESET_ALL,
            301: Fore.BLUE + "[301 Moved Permanently]" + Style.RESET_ALL,
            302: Fore.CYAN + "[302 Found]" + Style.RESET_ALL
        }
        print(f"  {cores[status]} {metodo_rotulo} {url}")
        print(f"{Fore.LIGHTBLACK_EX}    BODY: {preview}{Style.RESET_ALL}")
        if status == 200:
            count_refs["idor"] += 1
        resultados.append({
            "metodo": metodo_rotulo,
            "url": url,
            "status": status,
            "tipo": "Possível IDOR" if status == 200 else "Redirect",
            "preview": preview
        })
    elif status == 401:
        print(f"  {Fore.GREEN}[401 Unauthorized]{Style.RESET_ALL} {metodo_rotulo} {url}")
        count_refs["401"] += 1
        resultados.append({"metodo": metodo_rotulo, "url": url, "status": status, "tipo": "Unauthorized", "preview": None})
    elif status == 403:
        print(f"  {Fore.YELLOW}[403 Forbidden]{Style.RESET_ALL} {metodo_rotulo} {url}")
        count_refs["403"] += 1
        resultados.append({"metodo": metodo_rotulo, "url": url, "status": status, "tipo": "Forbidden", "preview": None})
    else:
        print(f"  {Fore.MAGENTA}[{status}]{Style.RESET_ALL} {metodo_rotulo} {url}")
        count_refs["outros"] += 1
        resultados.append({"metodo": metodo_rotulo, "url": url, "status": status, "tipo": "Outros", "preview": None})

def request_segura(metodo, url, timeout_req, proxies, headers=None, json_data=None):
    try:
        return requests.request(metodo, url, timeout=timeout_req, verify=False,
                                proxies=proxies, headers=headers, json=json_data)
    except requests.exceptions.Timeout:
        print(f"{Fore.LIGHTBLACK_EX}[TIMEOUT]{Style.RESET_ALL} {metodo} {url}")
        return {"erro": "Timeout"}
    except requests.exceptions.RequestException as e:
        print(f"{Fore.LIGHTBLACK_EX}[ERRO]{Style.RESET_ALL} {metodo} {url} → {e}")
        return {"erro": str(e)}

def test_bola_idor(file_path_or_list, timeout_req=5, delay=0.2):
    limpar_terminal()
    custom_headers = parse_custom_headers()
    extra_query = parse_custom_query()
    proxies = parse_proxy_settings()

    modo_teste = input(
        f"{Fore.YELLOW}Selecione o modo:{Style.RESET_ALL}\n"
        f"  1 - Manual (inserir valores)\n"
        f"  2 - Wordlist (arquivos de parâmetros e valores)\n"
        f"{Fore.CYAN}Escolha: {Style.RESET_ALL}"
    ).strip()

    if modo_teste == "2":
        arq_params = input(f"{Fore.YELLOW}Caminho da wordlist de parâmetros: {Style.RESET_ALL}").strip()
        arq_valores = input(f"{Fore.YELLOW}Caminho da wordlist de valores: {Style.RESET_ALL}").strip()
        lista_parametros = carregar_wordlist(arq_params)
        lista_valores = carregar_wordlist(arq_valores)

        def gerar_urls_wordlist(url_base):
            urls_mutadas = []
            for param in lista_parametros:
                for valor in lista_valores:
                    if "?" in url_base:
                        url_mutada = url_base + f"&{param}={valor}"
                    else:
                        url_mutada = url_base + f"?{param}={valor}"
                    urls_mutadas.append((param, valor, url_mutada))
            return urls_mutadas

    else:
        valores_teste_mutacao_input = input(
            f"{Fore.YELLOW}Digite um ou mais valores para teste de parâmetros mutáveis "
            f"(ex: 1, 2, 3) {Fore.CYAN}[Enter para usar padrão 'IDORTEST']: {Style.RESET_ALL}"
        ).strip()
        if valores_teste_mutacao_input:
            valores_teste_mutacao = [v.strip() for v in valores_teste_mutacao_input.split(",") if v.strip()]
        else:
            valores_teste_mutacao = ["IDORTEST"]

    resultados = []
    count_refs = {"idor": 0, "401": 0, "403": 0, "outros": 0}

    if isinstance(file_path_or_list, list):
        data = build_data_from_list(file_path_or_list)
    elif isinstance(file_path_or_list, str):
        if not os.path.exists(file_path_or_list):
            print(f"{Fore.RED}Arquivo não encontrado: {file_path_or_list}")
            return
        ext = os.path.splitext(file_path_or_list)[1].lower()
        if ext == ".json":
            with open(file_path_or_list, 'r', encoding='utf-8') as f:
                data = json.load(f)
        elif ext in [".txt", ".csv", ".xls", ".xlsx"]:
            urls = read_hosts_file(file_path_or_list)
            data = build_data_from_list(urls)
        elif ext in [".yaml", ".yml"]:
            data = read_yaml_routes(file_path_or_list)
        else:
            print(f"{Fore.RED}Formato {ext} não suportado.")
            return

    print(f"{Fore.CYAN}Iniciando testes...\n")
    count_total = 0

    for hostname, services in data.items():
        print(f"{Fore.LIGHTCYAN_EX}Host: {hostname}")
        for svc in services:
            protocol = svc.get("protocol", "https")
            port = svc.get("port", 443)
            base_url = f"{protocol}://{hostname}:{port}"
            for route in svc.get("routes", []):
                methods = route.get("methods", ["GET"])
                for path in route.get("paths", ["/"]):
                    if not path.startswith("/"):
                        path = "/" + path
                    for method in methods:
                        method_u = method.upper()
                        if method_u in ["OPTIONS", "DELETE"]:
                            continue
                        if method_u == "GET":
                            url_base = base_url + path
                            for label, u in [
                                (method_u, url_base),
                                (method_u + " [HEADERS]", url_base),
                                (method_u + " [HEADERS+PARAMS]", append_query_to_url(url_base, extra_query))
                            ]:
                                resp = request_segura("GET", u, timeout_req, proxies,
                                                       headers=custom_headers if "HEADERS" in label else None)
                                if isinstance(resp, dict) and "erro" in resp:
                                    resultados.append({"metodo": label, "url": u, "status": None,
                                                       "tipo": "Erro", "preview": resp["erro"]})
                                else:
                                    processar_resposta(resp, label, u, resultados, count_refs)
                            # parâmetros mutáveis
                            if modo_teste == "2":
                                urls_mutadas = gerar_urls_wordlist(append_query_to_url(url_base, extra_query))
                            else:
                                urls_mutadas = gerar_urls_mutadas(append_query_to_url(url_base, extra_query), valores_teste_mutacao)

                            for nome_param, valor_usado, url_mutada in urls_mutadas:
                                resp = request_segura("GET", url_mutada, timeout_req, proxies, headers=custom_headers)
                                label = method_u+f" [MUT-PARAM:{nome_param}={valor_usado}]"
                                if isinstance(resp, dict) and "erro" in resp:
                                    resultados.append({"metodo": label, "url": url_mutada, "status": None,
                                                       "tipo": "Erro", "preview": resp["erro"]})
                                else:
                                    processar_resposta(resp, label, url_mutada, resultados, count_refs)
                        else:
                            resp = request_segura(method_u, base_url+path, timeout_req, proxies,
                                                  headers=custom_headers,
                                                  json_data=payload_teste if method_u in methods_with_body else None)
                            if isinstance(resp, dict) and "erro" in resp:
                                resultados.append({"metodo": method_u, "url": base_url+path, "status": None,
                                                   "tipo": "Erro", "preview": resp["erro"]})
                            else:
                                processar_resposta(resp, method_u, base_url+path, resultados, count_refs)
                        count_total += 1
                        time.sleep(delay)

    with open("resultados_bola_idor.json", "w", encoding="utf-8") as fjson:
        json.dump(resultados, fjson, indent=4, ensure_ascii=False)
    pd.DataFrame(resultados).to_csv("resultados_bola_idor.csv", index=False, encoding="utf-8")

    print(f"\n{Fore.CYAN}Resumo:")
    print(f"  {Fore.RED}Possível IDOR (200): {count_refs['idor']}")
    print(f"  {Fore.GREEN}401 Unauthorized: {count_refs['401']}")
    print(f"  {Fore.YELLOW}403 Forbidden: {count_refs['403']}")
    print(f"  {Fore.MAGENTA}Outros códigos: {count_refs['outros']}")
    print(f"  {Fore.LIGHTWHITE_EX}Total testado: {count_total}")
    print(f"{Fore.CYAN}Arquivos exportados: resultados_bola_idor.json, resultados_bola_idor.csv{Style.RESET_ALL}")
