import requests
import json
import sys
import os

def normalizar_url(url):
    url = url.strip()
    if url.startswith("http://") or url.startswith("https://"):
        return url.rstrip("/")
    test_https = f"https://{url.strip('/')}"
    try:
        requests.get(test_https, timeout=4)
        return test_https
    except:
        pass
    test_http = f"http://{url.strip('/')}"
    try:
        requests.get(test_http, timeout=4)
        return test_http
    except:
        pass
    return test_https

def mostrar_barra_progresso(atual, total, largura=30):
    proporcao = atual / total
    preenchido = int(largura * proporcao)
    vazio = largura - preenchido
    barra = "/" * preenchido + "*" * vazio
    sys.stdout.write(f"\r[{barra}] - {atual}/{total}")
    sys.stdout.flush()

def fuzz_single_target(url, wordlist_file):
    url_norm = normalizar_url(url)

    try:
        with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as f:
            paths = [p.strip() for p in f if p.strip()]
    except Exception as e:
        print(f"[ERRO] Não foi possível ler a wordlist: {e}")
        return []

    found = []
    total = len(paths)

    for idx, path in enumerate(paths, start=1):
        target = f"{url_norm}/{path.lstrip('/')}"
        try:
            resp = requests.get(target, timeout=5)
            if resp.status_code not in [404, 400]:
                found.append({"url": target, "status": resp.status_code, "length": len(resp.text)})
        except:
            pass
        mostrar_barra_progresso(idx, total)

    sys.stdout.write("\n")
    return found

def fuzz_multiple_targets(urls, wordlist_file, output_file="fuzz_results.json"):
    results = []
    for i, url in enumerate(urls, start=1):
        print(f"\n[{i}/{len(urls)}] Fuzzing em {url}")
        data = fuzz_single_target(url, wordlist_file)
        results.append({"host": url, "found": data})

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        print(f"\n[✓] Resultados salvos em: {output_file}")
    except Exception as e:
        print(f"[ERRO] Não foi possível salvar arquivo: {e}")
