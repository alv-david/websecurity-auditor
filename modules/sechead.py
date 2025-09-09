import requests
import re

tech_version_pattern = re.compile(r".+\/\d+(\.\d+){0,2}", re.IGNORECASE)

def analyze_headers(headers, config):
    result_json = {}
    cwe_results = {}

    headers_normalized = {k.lower(): v for k, v in headers.items()}

    for header_info in config['owasp_security_headers']:
        header_name = header_info['name']
        cwe = header_info['cwe']
        if cwe not in cwe_results:
            cwe_results[cwe] = {
                "security_headers": [],
                "sensitive_headers": [],
                "missing_security_headers": []
            }
        val = headers_normalized.get(header_name.lower())

        if header_name.lower() == 'x-xss-protection':
            if val is None or str(val).strip().lower() in ["0", "false", "off", "disable"]:
                cwe_results[cwe]["security_headers"].append({
                    "header": header_name,
                    "valor": "Desativado",
                    "cor": "verde"
                })
            else:
                cwe_results[cwe]["security_headers"].append({
                    "header": header_name,
                    "valor": str(val).strip(),
                    "cor": "amarelo",
                    "penalty": "sensitive_header_present"
                })
        else:
            if val is not None and str(val).strip() != "":
                cwe_results[cwe]["security_headers"].append({
                    "header": header_name,
                    "valor": str(val).strip(),
                    "cor": "verde"
                })
            else:
                cwe_results[cwe]["missing_security_headers"].append(header_name)

    for sh in config['sensitive_headers']:
        header_name = sh['name']
        cwe = sh['cwe']
        if cwe not in cwe_results:
            cwe_results[cwe] = {
                "security_headers": [],
                "sensitive_headers": [],
                "missing_security_headers": []
            }
        val = headers_normalized.get(header_name.lower())
        if val is not None:
            vstr = str(val).strip()
            if tech_version_pattern.match(vstr):
                cor = "vermelho"
                penalty = "tech_disclosure_name_and_version"
            elif vstr != "":
                cor = "amarelo"
                penalty = "tech_disclosure_name"
            else:
                cor = "amarelo"
                penalty = "sensitive_header_present"
            cwe_results[cwe]["sensitive_headers"].append({
                "header": header_name,
                "valor": vstr,
                "cor": cor,
                "penalty": penalty
            })

    result_json['cwe'] = cwe_results
    result_json['headers'] = {k: v for k, v in headers.items()}
    return result_json

def analyze_host(url, config):
    try:
        
        r = requests.get(url, timeout=15, verify=False)
        headers = r.headers
        analysis = analyze_headers(headers, config)
        analysis['status_code'] = r.status_code
        analysis['host'] = url
        return analysis
    except Exception as e:
        return {"host": url, "erro": str(e)}
