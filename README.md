# ConfigGuard Security

CLI de DevSecOps em Python puro (somente biblioteca padrão) que audita repositórios, Dockerfiles e arquivos de configuração em busca de **segredos expostos** e **configurações inseguras** antes que cheguem ao deploy.

```
$ configguard scan examples/vulnerable_sample
[CRITICAL] .env.example:10  AWS Access Key ID
[HIGH] Dockerfile:13  Container final executa explicitamente como root
[HIGH] deploy.sh:10  Token Bearer em cabeçalho de autorização
...
Resumo:   critical: 4  high: 8  medium: 2  low: 0  |  total: 14
Nota:     0/100 (F)
Status:   REPROVADO (12 achado(s) >= high)
```

## Sumário

- [Motivação](#motivação)
- [O que é detectado](#o-que-é-detectado)
- [Arquitetura](#arquitetura)
- [Instalação](#instalação)
- [Uso](#uso)
- [Interpretando os relatórios](#interpretando-os-relatórios)
- [Supressão de falsos positivos](#supressão-de-falsos-positivos)
- [Limitações conhecidas](#limitações-conhecidas)
- [Desenvolvimento](#desenvolvimento)

## Motivação

Boa parte dos incidentes de segurança em aplicações não nasce de vulnerabilidades sofisticadas, e sim de **falhas de gestão de configuração**: uma chave de nuvem commitada por engano, um `DEBUG=True` que sobe para produção, uma imagem Docker rodando como root com SSH exposto, um script de deploy com `chmod 777`. São erros triviais de introduzir e caros de remediar depois que entram no histórico do git ou em uma imagem publicada.

O ConfigGuard aplica o princípio de *shift-left* da AppSec a esse problema:

- **Configuration Management**: trata arquivos de infraestrutura (`Dockerfile`, `docker-compose.yml`, `.env`, `settings.py`, YAML/TOML/INI) como artefatos auditáveis, com regras explícitas e reprodutíveis.
- **AppSec**: identifica credenciais expostas combinando assinaturas conhecidas (regex) com análise estatística (entropia de Shannon) para pegar segredos que não seguem um formato público.
- **Feedback no momento certo**: roda como hook `pre-commit`, bloqueando o problema antes de ele virar histórico, e como etapa de CI com exit codes previsíveis.
- **Rastreabilidade**: cada execução é registrada em SQLite com branch e commit, permitindo acompanhar a evolução da postura de segurança ao longo do tempo.

Sem dependências externas, roda em qualquer ambiente com Python 3.11+: runners de CI isolados, containers mínimos e máquinas sem acesso a um índice de pacotes.

## O que é detectado

### Segredos (`scanners/secrets.py`)

| Regra | Exemplo | Severidade |
|---|---|---|
| `private-key` | `-----BEGIN RSA PRIVATE KEY-----` | critical |
| `aws-access-key-id` / `aws-secret-access-key` | `AKIA...`, `aws_secret_access_key = ...` | critical |
| `stripe-secret-key` | `sk_live_...` | critical |
| `database-connection-string` | `postgresql://user:senha@host/db`, `Server=...;Password=...` | critical |
| `github-token`, `gitlab-token`, `slack-token`, `slack-webhook` | `ghp_...`, `glpat-...`, `xoxb-...` | high |
| `google-api-key`, `openai-api-key`, `anthropic-api-key` | `AIza...`, `sk-...`, `sk-ant-...` | high |
| `jwt` | `eyJ...eyJ...assinatura` | high |
| `bearer-token` | `Authorization: Bearer <token opaco>` | high |
| `generic-secret-assignment` | `API_KEY = "..."`, `"client_secret": "..."` | medium |
| `high-entropy-base64` / `high-entropy-hex` | strings aleatórias com 20+ caracteres | medium |

A análise de entropia calcula `H = -Σ p(c) · log2 p(c)` sobre cada token candidato. Tokens base64 com `H >= 4.0` e mistura de maiúsculas, minúsculas e dígitos, ou hexadecimais com 32+ caracteres e `H >= 3.0`, são reportados. Digests (`sha256:...`, `sha512-...`), UUIDs e sequências de alfabeto (`ABCDEF...`) são descartados.

### Configurações (`scanners/configs.py`)

| Regra | O que verifica | Severidade |
|---|---|---|
| `dockerfile-missing-user` | Estágio final sem instrução `USER` (container roda como root) | high |
| `dockerfile-root-user` | Estágio final com `USER root` / `USER 0` | high |
| `dockerfile-critical-port` | `EXPOSE` de SSH, Telnet, RDP, VNC, bancos de dados, Redis, Elasticsearch, Docker API etc. | high / critical |
| `compose-critical-port` | Porta crítica publicada no host em `docker-compose.yml` (bindings em `127.0.0.1` são aceitos) | high / critical |
| `permissive-chmod` | `chmod 777`, `666`, `o+w`, `a+rwx` em `RUN` de Dockerfile ou scripts shell (`chmod 1777` é aceito) | high |
| `debug-enabled` | `DEBUG=True`, `FLASK_DEBUG=1`, `debug: true`, `app.run(debug=True)` | high |
| `development-environment` | `FLASK_ENV=development`, `NODE_ENV=dev` | medium |
| `permissions-0777` / `permissions-world-writable` | Modo POSIX de scripts, executáveis e arquivos sensíveis (`.env`, `.pem`, `id_rsa`, `credentials.json`...) | high / critical |

Builds multi-stage são avaliados corretamente: apenas o último estágio determina o usuário de execução, e imagens base `*:nonroot` são reconhecidas.

## Arquitetura

```
configguard-sec/
├── pyproject.toml
├── src/configguard/
│   ├── cli.py              # argparse: scan, history, install-hook
│   ├── audit.py            # orquestra os scanners, modelo ScanResult, nota, contexto git
│   ├── storage.py          # histórico SQLite e métricas por branch
│   ├── reporter.py         # terminal (ANSI), JSON e Markdown
│   └── scanners/
│       ├── secrets.py      # regex + entropia de Shannon
│       └── configs.py      # Dockerfile, compose, flags de debug, permissões
├── tests/                  # unittest: unidade + integração (inclui git real)
└── examples/vulnerable_sample/
```

Fluxo de um `configguard scan`:

```
 cli.py ──> audit.run_scan()
               │
               ├─ percorre arquivos (ignora .git, node_modules, venv, lockfiles, binários)
               ├─ SecretScanner.scan_file()  ─┐
               ├─ ConfigScanner.scan_file()  ─┴─> AuditFinding (modelo unificado)
               └─ detect_git_context()  ──> branch + commit
               │
               v
           ScanResult ──> storage.AuditStorage.record()   (SQLite)
                     └──> reporter.render()               (terminal | json | markdown)
                     └──> exit code conforme --fail-on
```

Decisões de projeto:

- **Funções puras por regra.** `audit_dockerfile(text)`, `audit_debug_flags(text)`, `audit_permissions(path, mode)` e `SecretScanner.scan_text(text)` não tocam o disco, o que torna as regras testáveis isoladamente e reutilizáveis.
- **Deduplicação por sobreposição.** Regras específicas rodam antes das genéricas. Um JWT dentro de `Bearer ...` é reportado uma vez como `jwt`, e um token já classificado não volta como "alta entropia".
- **Evidência sempre mascarada.** Relatórios e banco de dados guardam apenas `AKIA********LE`; o valor completo do segredo nunca é persistido.
- **Permissões só em POSIX.** No Windows o `st_mode` não reflete ACLs reais (todo arquivo gravável aparece como `0o666`), então a checagem em disco é desativada automaticamente fora de POSIX. A regra continua disponível via `audit_permissions(path, mode)`.

## Instalação

Requisitos: Python 3.11+ e, para `--staged`, `history` por branch e `install-hook`, o `git` no `PATH`.

```bash
git clone https://github.com/Pedro-Dirickson/configguard-sec.git
cd configguard-sec

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install .

configguard --version
```

Sem instalar (útil em CI ou containers mínimos):

```bash
PYTHONPATH=src python -m configguard scan .           # Linux/macOS
$env:PYTHONPATH="src"; python -m configguard scan .   # Windows PowerShell
```

## Uso

### Teste rápido com a amostra vulnerável

`examples/vulnerable_sample/` contém três arquivos **propositalmente inseguros** com credenciais fictícias ou exemplos públicos (chaves de exemplo da documentação AWS, JWT de exemplo do jwt.io):

| Arquivo | Problemas plantados |
|---|---|
| `.env.example` | `DEBUG=True`, `FLASK_ENV=development`, URLs Postgres/Redis com senha, par de chaves AWS, `SECRET_KEY` hardcoded e dois placeholders que **não** devem ser reportados |
| `Dockerfile` | `USER root`, `EXPOSE 22 5432`, `chmod -R 777` |
| `deploy.sh` | JWT e token Bearer embutidos, `chmod 777` |

```bash
configguard scan examples/vulnerable_sample --no-history
```

O resultado esperado é 14 achados (4 critical, 8 high, 2 medium) e exit code `1`.

### `scan`

```bash
configguard scan [PATH] [opções]
```

| Opção | Descrição |
|---|---|
| `-f, --format {terminal,json,markdown}` | Formato da saída (padrão: `terminal`) |
| `-o, --output ARQUIVO` | Grava o relatório em arquivo em vez de imprimir |
| `--fail-on {critical,high,medium,low,none}` | Severidade mínima que gera exit code `1` (padrão: `high`) |
| `--staged` | Analisa somente arquivos em stage no git |
| `--no-secrets` / `--no-configs` | Desativa um dos scanners |
| `--no-entropy` | Desativa a análise de entropia (reduz ruído em bases com muitos hashes) |
| `--db ARQUIVO` | Banco do histórico (padrão: `$CONFIGGUARD_DB` ou `./audit_history.db`) |
| `--no-history` | Não registra a execução |
| `--no-color` | Desativa ANSI (também respeita `NO_COLOR`) |

Exemplos:

```bash
# Relatório Markdown para anexar a um PR ou ticket
configguard scan . -f markdown -o reports/audit.md

# JSON para consumo por outra ferramenta
configguard scan . -f json --no-history | jq '.findings[] | select(.severity == "critical")'

# Só bloquear em achados críticos
configguard scan services/api --fail-on critical

# Apenas auditoria de infraestrutura
configguard scan deploy/ --no-secrets
```

### `history`

```bash
configguard history [--db ARQUIVO] [--target PATH] [--branch NOME] [-n LIMITE] [-f {terminal,json}]
```

```
Métricas por branch
branch               scans   nota  tend.  média crit high  commit        alvo
-----------------------------------------------------------------------------
main                     4     90    +20   72.5    0    1  9c1e0b7d2a44  /home/dev/payments-api
feature/login            2     71    -19   80.5    1    0  41f7a2c90e1b  /home/dev/payments-api

Scans recentes
  id  data (UTC)                branch           commit        nota achados  alvo
---------------------------------------------------------------------------------
   6  2026-11-24T18:42:10+00:00 main             9c1e0b7d2a44    90       1  /home/dev/payments-api
   5  2026-11-24T17:03:55+00:00 feature/login    41f7a2c90e1b    71       2  /home/dev/payments-api
```

### `install-hook`

```bash
configguard install-hook [REPO] [--fail-on SEVERIDADE] [--force]
```

Instala `.git/hooks/pre-commit` (respeitando `core.hooksPath`). A cada commit, o hook executa `configguard scan --staged`, imprime os achados e aborta o commit se houver algo no nível de `--fail-on` ou acima. O histórico do hook fica em `.git/configguard/audit_history.db`, fora da árvore versionada.

```
$ git commit -m "add config"
[CRITICAL] config.py:1  AWS Access Key ID
    aws-access-key-id | AKIA********LE
...
ConfigGuard: commit bloqueado. Corrija os achados acima ou use 'git commit --no-verify' conscientemente.
```

Um hook `pre-commit` existente que não tenha sido criado pelo ConfigGuard nunca é sobrescrito sem `--force`. O script gerado aponta para o interpretador Python usado na instalação; reinstale o hook se mover o ambiente virtual.

### Integração contínua

```yaml
# .github/workflows/configguard.yml
name: configguard
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install git+https://github.com/Pedro-Dirickson/configguard-sec.git
      - run: configguard scan . --no-history --fail-on high -f markdown -o configguard-report.md
      - if: always()
        uses: actions/upload-artifact@v4
        with:
          name: configguard-report
          path: configguard-report.md
```

## Interpretando os relatórios

### Severidades

| Severidade | Significado | Ação esperada |
|---|---|---|
| `critical` | Credencial com acesso direto a infraestrutura ou dados (chave de nuvem, chave privada, senha de banco) ou serviço exposto sem autenticação | Revogar/rotacionar imediatamente; remover do histórico git |
| `high` | Token de API, container como root, porta sensível exposta, debug ligado, permissão de escrita global | Corrigir antes do merge |
| `medium` | Indício que exige revisão humana: atribuição genérica de segredo, string de alta entropia, ambiente de desenvolvimento | Confirmar se é segredo real ou suprimir |
| `low` | Reservado para higiene de configuração | Opcional |

### Anatomia de um achado (terminal)

```
[HIGH] Dockerfile:13  Container final executa explicitamente como root
    dockerfile-root-user | USER root
    -> Troque para um usuário não-root (UID >= 1000) no estágio final.
```

1. Severidade, `arquivo:linha` (relativo ao alvo) e descrição.
2. ID da regra e evidência. Para segredos, a evidência é sempre mascarada.
3. Recomendação de correção.

Achados de permissão de arquivo usam linha `0`, pois se referem ao arquivo inteiro.

### Nota de qualidade

```
nota = max(0, 100 - 25·critical - 10·high - 4·medium - 1·low)
```

| Nota | Conceito |
|---|---|
| 90-100 | A |
| 75-89 | B |
| 50-74 | C |
| 25-49 | D |
| 0-24 | F |

A nota existe para comparação ao longo do tempo (coluna `tend.` do `history`: diferença entre a última nota e a anterior na mesma branch e alvo). A decisão de bloquear é feita pelo `--fail-on`, não pela nota.

### Exit codes

| Código | Significado |
|---|---|
| `0` | Nenhum achado no nível de `--fail-on` ou acima |
| `1` | Há achados bloqueantes |
| `2` | Erro de uso (caminho inexistente, `--staged` fora de repositório git, histórico ausente) |

### JSON

```json
{
  "tool": "configguard",
  "version": "0.1.0",
  "target": "/home/dev/payments-api",
  "started_at": "2026-11-24T18:42:10+00:00",
  "duration_ms": 41,
  "files_scanned": 128,
  "branch": "main",
  "commit": "9c1e0b7d2a44f0c3...",
  "score": 90.0,
  "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0},
  "total_findings": 1,
  "findings": [
    {
      "category": "config",
      "rule_id": "debug-enabled",
      "severity": "high",
      "file_path": "config/settings.py",
      "line_number": 12,
      "description": "Modo debug habilitado em configuração",
      "evidence": "DEBUG = True",
      "recommendation": "Desative o debug em produção e controle-o por variável de ambiente com padrão False."
    }
  ]
}
```

`category` é `secret` ou `config`. Os achados vêm ordenados por severidade, arquivo e linha.

### Markdown

O relatório Markdown contém uma tabela de metadados (alvo, branch, commit, nota, status), um resumo por severidade, a tabela de achados e uma seção de recomendações deduplicadas por regra, pronta para colar em PRs, tickets ou wikis.

## Supressão de falsos positivos

- **Comentário inline**: qualquer linha contendo `configguard:ignore` é ignorada pelo scanner de segredos.

  ```python
  TEST_FIXTURE_KEY = "AKIAIOSFODNN7EXAMPLE"  # configguard:ignore
  ```

- **Placeholders** são reconhecidos automaticamente e não geram achado: `${VAR}`, `$VAR`, `<valor>`, `{{ var }}`, `%s`, `****`, `xxxx`, `changeme`, `password`, `example`.
- **Referências de código** não são tratadas como segredo: `os.environ["X"]`, `settings.API_KEY`, `get_secret()`, `Optional[str]`.
- **Diretórios e arquivos ignorados**: `.git`, `node_modules`, `venv`/`.venv`, `__pycache__`, `dist`, `build`, lockfiles (`package-lock.json`, `poetry.lock`, `go.sum`...), `*.min.js` e binários.

## Limitações conhecidas

- O scanner analisa o **estado atual dos arquivos**, não o histórico do git. Um segredo removido em um commit posterior continua no histórico e deve ser tratado com rotação da credencial e reescrita do histórico (`git filter-repo`).
- `--staged` lê a versão dos arquivos na árvore de trabalho, não o conteúdo exato do índice. Alterações feitas após o `git add` também são analisadas.
- No hook `pre-commit`, o commit registrado no histórico é o `HEAD` anterior, pois o novo commit ainda não existe.
- Flags de debug definidas via `ENV` dentro de Dockerfiles ainda não são auditadas.
- Detecção por regex e entropia é heurística: segredos sem formato conhecido e com baixa entropia (ex.: senhas curtas fora de variáveis com nome sensível) podem passar.
- Rodar o scanner na raiz deste repositório reporta achados nos testes e em `examples/`, que contêm segredos fictícios intencionalmente.

## Desenvolvimento

```bash
python -m unittest discover -s tests -v
```

A suíte cobre casos positivos e falsos positivos de cada regra, persistência SQLite, renderização dos relatórios e integração de ponta a ponta com git real (incluindo um `git commit` bloqueado pelo hook). Os testes de integração isolam a configuração global do git e são pulados se o `git` não estiver disponível.
