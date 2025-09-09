import requests
import json
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed

TAKEOVER_SIGNATURES = [
    "There is no such app",
    "NoSuchBucket",
    "no such app",
    "No Such Account",
    "No Such Domain",
    "project not found",
    "Repository not found",
    "The specified bucket does not exist",
    "heroku | no such app",
    "github.com 404",
    "unrecognized domain",
    "domain not found",
    "does not exist"
]

def read_hosts_file(file_path):
    """Lê TXT, CSV ou Excel e retorna lista de hosts."""
    ext = file_path.split(".")[-1].lower()
    if ext in ["txt", "csv"]:
        df = pd.read_csv(file_path, header=None)
    elif ext in ["xls", "xlsx"]:
        df = pd.read_excel(file_path, header=None)
    else:
        raise Exception("Formato inválido. Use TXT, CSV, XLS ou XLSX.")
    return [str(h).strip() for h in df[0].dropna() if str(h).strip()]

def normalizar_url(url):
    """Garantir protocolo HTTP/HTTPS no subdomínio testado."""
    url = url.strip()
    if url.startswith("http://") or url.startswith("https://"):
        return url
    test_https = f"https://{url}"
    try:
        requests.get(test_https, timeout=4)
        return test_https
    except:
        pass
    return f"http://{url}"

def check_subdomain(subdomain):
    """Verifica se subdomínio está potencialmente vulnerável a takeover."""
    url_norm = normalizar_url(subdomain)
    result = {"domain": subdomain, "vulnerable": False, "status": None, "reason": ""}

    try:
        resp = requests.get(url_norm, timeout=6)
        result["status"] = resp.status_code
        if any(sig.lower() in resp.text.lower() for sig in TAKEOVER_SIGNATURES):
            result["vulnerable"] = True
            result["reason"] = f"Assinatura detectada"
        elif resp.status_code in [404, 400]:
            result["vulnerable"] = True
            result["reason"] = f"Status code suspeito: {resp.status_code}"
    except requests.ConnectionError:
        result["status"] = "CONNECTION_ERROR"
        result["reason"] = "Falha de conexão"
    except requests.Timeout:
        result["status"] = "TIMEOUT"
        result["reason"] = "Tempo limite excedido"
    except Exception as e:
        result["status"] = "ERROR"
        result["reason"] = str(e)

    return result

def scan_subdomains(subdomains, output_file="sub_takeover_results.json", threads=10):
    """Executa verificação de takeover em lista de subdomínios."""
    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_domain = {executor.submit(check_subdomain, dom): dom for dom in subdomains}
        for future in as_completed(future_to_domain):
            dom = future_to_domain[future]
            try:
                data = future.result()
                results.append(data)
                if data["vulnerable"]:
                    print(f"[!!!] {dom} ({data['status']}) -> POSSÍVEL TAKEOVER ({data['reason']})")
                else:
                    print(f"[OK] {dom} ({data['status']})")
            except Exception as e:
                print(f"[ERRO] {dom} -> {e}")

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        print(f"\n[✓] Resultados salvos em: {output_file}")
    except Exception as e:
        print(f"[ERRO] Falha ao salvar resultados: {e}")

    return results
