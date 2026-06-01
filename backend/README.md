# Casa & Terra IAM Backend

Backend inicial para sincronizar informacoes do Active Directory de forma somente leitura.

Nesta fase o sistema nao altera objetos no AD. Ele apenas:

- autentica usando uma conta de leitura LDAP;
- consulta usuarios e grupos;
- grava um cache local SQLite;
- expoe endpoints para o frontend consumir;
- registra historico das sincronizacoes.

## Rodando no Ubuntu

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
mkdir -p data
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Primeiro sync

```bash
curl -X POST http://localhost:8000/api/sync/ad
```

## Endpoints iniciais

- `GET /api/health`
- `POST /api/sync/ad`
- `GET /api/identities`
- `GET /api/groups`
- `GET /api/operators`
- `GET /api/critical-permissions`
- `GET /api/sync-runs`

## Operadores do IAM

Usuarios que pertencem ao grupo configurado em `LDAP_OPERATOR_GROUP`, por padrao
`GG-IAM-OPERADORES`, sao importados para a tabela local `iam_operators`.

Eles entram com `status = pending` e `permissions_json = {}`. Ou seja: conseguem ser
identificados como candidatos a operador do sistema, mas nao recebem permissao operacional
automaticamente.

## Garantia de baixo impacto no AD

O codigo usa apenas operacoes LDAP de busca. Nao ha chamadas LDAP de modify, add, delete, modify_dn ou alteracao de senha nesta fase.

Use uma conta dedicada somente leitura, por exemplo:

```txt
CN=svc-iam-readonly,OU=Service Accounts,DC=casaeterra,DC=local
```

Quando evoluirmos para alteracoes, criaremos um modulo separado, com permissao explicita, auditoria obrigatoria e endpoints diferentes.
