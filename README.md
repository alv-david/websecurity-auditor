# webbecurity-auditor

Ferramenta em Python para **auditoria de segurança de aplicações web e APIs**, unificando múltiplos tipos de análise em um único CLI interativo.

O objetivo é possibilitar, a partir de um mesmo binário/script:
- Auditoria de **Headers de Segurança** (Web e API Backend)
- Análise de **TLS/SSL Version**
- Testes para **IDOR / BOLA**
- Fuzzing de diretórios (em breve)
- Subdomain Takeover (em breve)
- Importação de resultados prévios para consulta
- Exportação dos resultados em JSON, CSV e XLSX

---

## Funcionalidades

### 1. Auditoria de Security Headers
- Analisa cabeçalhos HTTP com base nas recomendações do **OWASP Security Headers**
- Detecta **Sensitive Headers** e exposição de tecnologia/versão
- Calcula **score de segurança** com base em penalidades configuráveis
- Avalia a configuração atual de **TLS/SSL**, marcando como "seguro" apenas `TLSv1.2` ou `TLSv1.3`
- Usa **arquivos de configuração** customizáveis em `config/` (ex.: `headers_web.json`, `headers_api_backend.json`)

### 2. Teste de BOLA / IDOR
- Lê entradas de `.json` ou arquivos de lista de URLs/rotas
- Modo **manual** ou **via wordlist** (Tkinter)
  - Substitui valores de parâmetros existentes
  - Adiciona parâmetros extras
- Permite uso de **headers customizados**, **query params adicionais** e **proxy**
- Exporta resultados em `.json` e `.csv`

### 3. Fuzzing de Diretórios
- Teste de descoberta de diretórios/arquivos ocultos
- Seleção de **wordlist** via interface Tkinter
- Suporte a múltiplos alvos
- Salva resultados no arquivo `fuzz_results.json`

### 4. Importação de Resultados
- Leitura e exibição simples de resultados prévios já exportados em JSON

---

## 📦 Instalação

### Clonando e instalando dependências
```bash
git clone https://github.com/alv-david/websecurity-auditor.git
cd websecurity-auditor
pip install -r requirements.txt
