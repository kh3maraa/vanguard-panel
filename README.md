# Vanguard Panel

Panel de licensing pour VanSpoofer. HWID lock strict, sync post-spoof, admin UI.

## Deploy from zero (Fly.io + GitHub)

### 1. Push le repo sur GitHub

```bash
git init
git remote add origin https://github.com/<toi>/vanguard-panel.git
git add .
git commit -m "initial"
git push -u origin main
```

Le `.gitignore` vire `.env`, `*.db`, `.vanguard_secret` — aucun secret commit.

### 2. Cree l'app Fly

- Va sur https://fly.io/dashboard
- **Launch an app** -> connecte ton repo GitHub `vanguard-panel`
- Nom de l'app : `vanguard-panel` (ou ce que tu veux)
- Region : `cdg` (Paris)
- **Skip** la creation Postgres/Redis
- **Deploy Now**

Fly build le Dockerfile automatiquement.

### 3. Cree le volume persistant (OBLIGATOIRE)

Sans ca ta DB se wipe a chaque redeploy.

- Sidebar Fly -> **Volumes**
- **Create volume**
  - Name : `vanguard_data`
  - Region : `cdg` (meme que primary_region)
  - Size : `1` GB
- Restart la machine pour qu'elle mount le volume

### 4. Configure les Secrets

Sidebar Fly -> **Secrets** -> **New Secret** (une fois par ligne) :

| Nom | Valeur |
|---|---|
| `INIT_ADMIN_USER` | `admin` (ou le username que tu veux) |
| `INIT_ADMIN_PASS` | `TonMotDePasseFort123!` (change-le !) |
| `INIT_APP_NAME` | `vanguard` |
| `INIT_APP_SECRET` | genere une string random 64+ chars |
| `SECRET_KEY` | *optionnel* — genere une string random 64+ chars |

Genere une string aleatoire :
- Linux/Mac : `openssl rand -hex 32`
- Windows PowerShell : `-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 64 | % {[char]$_})`
- Ou site : https://randomkeygen.com/

### 5. Restart la machine

Chaque secret ajoute demande un restart pour etre pris en compte.

Sidebar Fly -> **Machines** -> clic sur ta machine -> **Restart**

Au premier boot avec `INIT_ADMIN_PASS` set, l'app cree l'admin automatiquement.
Regarde **Logs & Errors** : tu dois voir
```
[bootstrap] admin 'admin' created from env
[bootstrap] application 'vanguard' created from env
```

### 6. Login sur le panel

- Va sur `https://vanguard-panel.fly.dev/auth/login`
- User = `INIT_ADMIN_USER` que tu as set (ex: `admin`)
- Password = `INIT_ADMIN_PASS`

### 7. Configure le client

Le client (`VanSpoofer.exe`) lit ses parametres depuis un fichier
`vanguard.config.json` a cote du .exe. Ce fichier contient :

```json
{
  "base_url":   "https://vanguard-panel.fly.dev/api/v1",
  "app_name":   "vanguard",
  "app_secret": "<la MEME valeur que INIT_APP_SECRET dans Fly>",
  "version":    "1.0.0"
}
```

Si `app_secret` cote client ne matche pas `INIT_APP_SECRET` cote panel,
tout signature HMAC echoue et le client voit `server unavailable`.

### 8. Deploy suivants

- Push sur `main` = Fly redeploy automatique (si tu as connecte GitHub)
- OU `fly deploy` en local si tu utilises la CLI
- La DB persiste sur le volume `vanguard_data`
- Les secrets restent, aucun besoin de les re-mettre

## Bootstrap re-run

Si tu perds l'admin, delete l'admin dans la table `admin_users` OU
change `INIT_ADMIN_USER` en un nouveau nom -> restart machine -> nouveau
admin cree.

## Local dev

```bash
python -m venv venv
source venv/bin/activate  # ou .\venv\Scripts\activate sur Windows
pip install -r requirements.txt
cp .env.example .env      # remplis les valeurs
export $(cat .env | xargs)
python -c "from app import create_app; create_app().run(host='0.0.0.0', port=8080)"
```
