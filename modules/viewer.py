import json
from colorama import Fore, Style, init
import os

init(autoreset=True)

def load_results_from_json(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        results = json.load(f)
    if isinstance(results, dict):
        results = [results]
    return results

def print_simple_batch_result(results):
    for analysis in results:
        host = analysis.get("host", "[Host não identificado]")
        status_code = analysis.get("status_code", "N/A")
        print(f"\n{Fore.LIGHTCYAN_EX}HOST: {host}")
        print(f"STATUS CODE: {status_code}")

        ativos = []
        inativos = []

        for cwe_data in analysis.get("cwe", {}).values():
            for h in cwe_data.get('security_headers', []):
                if h['header'].lower() == "x-xss-protection":
                    if h.get('cor') == 'verde':
                        ativos.append(f"{Fore.GREEN}{h['header']} (Desativado){Style.RESET_ALL}")
                    else:
                        ativos.append(f"{Fore.YELLOW}{h['header']} (ATIVO) - Ativar X-XSS-Protection não é recomendado{Style.RESET_ALL}")
                else:
                    ativos.append(f"{Fore.GREEN}{h['header']}{Style.RESET_ALL}")
            for h in cwe_data.get('missing_security_headers', []):
                inativos.append(f"{Fore.RED}{h}{Style.RESET_ALL}")

        if ativos:
            print(f"{Fore.LIGHTGREEN_EX}\nATIVOS:")
            for h in ativos:
                print("  " + h)
        else:
            print(f"{Fore.LIGHTGREEN_EX}ATIVOS: nenhum detectado.")

        if inativos:
            print(f"{Fore.LIGHTRED_EX}\nINATIVOS:")
            for h in inativos:
                print("  " + h)
        else:
            print(f"{Fore.LIGHTRED_EX}INATIVOS: nenhum ausente.")

        print(f"\n{Fore.LIGHTWHITE_EX}{'-'*45}")

    print(f"{Fore.LIGHTWHITE_EX}\nPara mais info: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html\n")

def main():
    file_path = input("Digite o caminho do arquivo JSON de resultado: ").strip()
    if not file_path or not os.path.exists(file_path):
        print("Arquivo não encontrado.")
        return
    results = load_results_from_json(file_path)
    print_simple_batch_result(results)

if __name__ == "__main__":
    main()