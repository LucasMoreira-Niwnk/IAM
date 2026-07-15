# Casa & Terra IAM Backend

Backend inicial para sincronizar informações do Active Directory de forma somente leitura.

Nesta fase o sistema nao altera objetos no AD. Ele apenas:

- autentica usando uma conta de leitura LDAP;
- consulta usuários e grupos;
- grava um cache local SQLite;
- expoe endpoints para o frontend consumir;
- registra histórico das sincronizações.

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

## Primeiro sync sem login

```bash
cd backend
source .venv/bin/activate
python -m app.cli sync-ad
```

## Endpoints iniciais

- `GET /api/health`
- `POST /api/sync/ad`
- `GET /api/identities`
- `GET /api/groups`
- `GET /api/operators`
- `GET /api/critical-permissions`
- `GET /api/sync-runs`

## Frontend

O `app.js` consome a API usando caminhos relativos, por exemplo `/api/identities`.
Em produção, o ideal é publicar o frontend e o backend atrás do mesmo Nginx e encaminhar
`/api` para o FastAPI.

Se precisar apontar o frontend para outro host durante testes, defina no console do navegador:

```js
localStorage.setItem("IAM_API_BASE_URL", "http://servidor:8000");
location.reload();
```

Para voltar ao modo com caminhos relativos:

```js
localStorage.removeItem("IAM_API_BASE_URL");
location.reload();
```

## Operadores do IAM

Usuários que pertencem ao grupo configurado em `LDAP_OPERATOR_GROUP`, por padrão
`GG-IAM-OPERADORES`, sao importados para a tabela local `iam_operators`.

Eles entram com `status = pending` e `permissions_json = {}`. Ou seja: conseguem ser
identificados como candidatos a operador do sistema, mas não recebem permissão operacional
automaticamente.

## Garantia de baixo impacto no AD

O código usa apenas operações LDAP de busca. Não há chamadas LDAP de modify, add, delete, modify_dn ou alteração de senha nesta fase.

Use uma conta dedicada somente leitura, por exemplo:

```txt
CN=svc-iam-readonly,OU=Service Accounts,DC=casaeterra,DC=local
```

Quando evoluirmos para alterações, criaremos um módulo separado, com permissão explícita, auditoria obrigatória e endpoints diferentes.
