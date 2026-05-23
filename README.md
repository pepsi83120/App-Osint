# 🔍 OSINT Platform

Application SaaS de renseignement open source propulsée par Claude.

## ✨ Fonctionnalités

- **Username Recon** — Scan sur 20+ plateformes (réseaux sociaux, forums, code, gaming...)
- **Domain / IP Analysis** — WHOIS, DNS, SSL, géolocalisation, score de menace
- **Email Analysis** — Validation, détection de fuites, exposition en ligne
- **Authentification** — Inscription / connexion sécurisée (bcrypt + sessions)
- **Quota** — 5 recherches/jour en plan gratuit (configurable)
- **Historique** — 50 dernières recherches sauvegardées
- **Base de données** — SQLite locale (zero config)

## 🚀 Installation

### 1. Prérequis
- **Node.js** v18+ → https://nodejs.org
- Une **clé API Anthropic** → https://console.anthropic.com

### 2. Cloner / décompresser le projet

```bash
cd osint-saas
```

### 3. Installer les dépendances

```bash
npm install
```

### 4. Configurer l'environnement

```bash
cp .env.example .env
```

Éditez `.env` et renseignez :
```
ANTHROPIC_API_KEY=sk-ant-votre-clé-ici
SESSION_SECRET=un-secret-aléatoire-long
PORT=3000
```

### 5. Lancer

```bash
# Mode développement (rechargement auto)
npm run dev

# Mode production
npm start
```

Ouvrez http://localhost:3000 🎉

## 📁 Structure

```
osint-saas/
├── src/
│   ├── server.js              # Serveur Express principal
│   ├── routes/
│   │   ├── auth.js            # Inscription, connexion, déconnexion
│   │   └── search.js          # Recherches OSINT + historique
│   ├── middleware/
│   │   └── auth.js            # Protection des routes
│   ├── services/
│   │   ├── db.js              # SQLite (better-sqlite3)
│   │   └── osint.js           # Appels API Anthropic
│   └── public/
│       └── index.html         # Frontend SPA complet
├── data/                      # Base SQLite (créée auto)
├── .env.example
├── package.json
└── README.md
```

## 🔌 API Routes

| Méthode | Route | Description |
|---------|-------|-------------|
| POST | `/api/auth/register` | Créer un compte |
| POST | `/api/auth/login` | Se connecter |
| POST | `/api/auth/logout` | Se déconnecter |
| GET | `/api/auth/me` | Infos utilisateur connecté |
| POST | `/api/search` | Lancer une analyse OSINT |
| GET | `/api/history` | Historique des recherches |
| GET | `/api/history/:id` | Détail d'une recherche |

## ⚙️ Configuration

Variables dans `.env` :

| Variable | Description | Défaut |
|----------|-------------|--------|
| `ANTHROPIC_API_KEY` | Clé API Anthropic | — |
| `SESSION_SECRET` | Secret pour les sessions | dev-secret |
| `PORT` | Port du serveur | 3000 |
| `FREE_SEARCHES_PER_DAY` | Quota plan gratuit | 5 |

## 🚀 Déploiement (Railway / Render / VPS)

1. Pushez sur GitHub
2. Connectez Railway ou Render à votre repo
3. Ajoutez les variables d'environnement
4. Deploy !

Pour un VPS, remplacez SQLite par PostgreSQL avec `pg` + `connect-pg-simple`.

## ⚖️ Éthique & Légalité

Cet outil est à usage éducatif et de sécurité défensive.
Utilisez uniquement dans un cadre légal et avec consentement.
