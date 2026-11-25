# CLAUDE.md — ConfigGuard Security & Configuration Auditor

## Visão Geral do Projeto
Ferramenta CLI de DevSecOps e Configuration Management em Python puro (stdlib) para auditar repositórios Git, arquivos de configuração, Dockerfiles e código-fonte em busca de credenciais expostas e falhas de configuração antes do deploy.

## Regras de Arquitetura e Código
- Utilizar exclusivamente a biblioteca padrão do Python 3.11+ (sem dependências externas pesadas) para facilitar a execução em ambientes isolados e pipelines CI/CD.
- Separar responsabilidades em módulos limpos dentro de `src/configguard/`:
  - `cli.py`: interface de linha de comando (`argparse`) com os subcomandos `scan`, `history` e `install-hook`.
  - `scanners/secrets.py`: detecção de segredos via Regex + Entropia de Shannon.
  - `scanners/configs.py`: auditoria de configurações inseguras (`Dockerfile`, `.env`, permissões POSIX, flags de debug).
  - `storage.py`: persistência do histórico de auditorias em SQLite (`audit_history.db`).
  - `reporter.py`: geração de relatórios técnicos em terminal, JSON e Markdown.
- Todo código, docstrings e testes devem ser claros, modulares e sem comentários óbvios gerados por IA.
- Incluir testes unitários com `unittest` em `tests/`, cobrindo casos positivos e falsos positivos.

## Estrutura Esperada
```
configguard-sec/
├── CLAUDE.md
├── README.md
├── pyproject.toml
├── src/
│   └── configguard/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── storage.py
│       ├── reporter.py
│       └── scanners/
│           ├── __init__.py
│           ├── secrets.py
│           └── configs.py
└── tests/
    ├── __init__.py
    ├── test_secrets.py
    ├── test_configs.py
    ├── test_storage.py
    └── test_reporter.py
```

## Fluxo de Trabalho Git
- Nunca fazer um único commit gigante. Dividir o desenvolvimento em commits atômicos e semânticos (`feat:`, `test:`, `docs:`).
- Antes de codificar cada etapa, apresentar o plano de arquivos e validar os testes antes do commit.
- Rodar a suíte com `python -m unittest discover -s tests -v` antes de cada commit; não commitar com testes falhando.

## Publicação Automática no GitHub
- Ao finalizar todas as etapas e commits, verificar a autenticação com `gh auth status`.
- Criar o repositório público `configguard-sec` diretamente na conta `Pedro-Dirickson` com:
  ```bash
  gh repo create configguard-sec --public --source=. --remote=origin --push \
    --description "CLI de DevSecOps em Python puro que audita repositórios, Dockerfiles e configs em busca de segredos expostos e configurações inseguras."
  ```
- Confirmar que a branch `main` e todos os commits foram enviados corretamente com `git status` e exibir a URL final do repositório publicado.
