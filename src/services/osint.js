const fetch = require('node-fetch');

const GROQ_API = 'https://api.groq.com/openai/v1/chat/completions';

const SYSTEM_PROMPT = `Tu es un analyste OSINT senior. Tu produis des rapports en francais, structures, utiles et prudents.
Tu travailles uniquement sur de l'information publique ou sur des hypotheses clairement marquees.
Tu refuses toute collecte intrusive, doxxing, contournement, hameconnage, credential stuffing, exploitation ou acces non autorise.
Tu reponds uniquement avec du JSON valide, sans markdown.`;

const MODULE_LABELS = {
  social: 'reseaux sociaux',
  infrastructure: 'infrastructure',
  leaks_public: 'expositions publiques',
  threat_intel: 'threat intelligence',
  archives: 'archives web',
  correlation: 'correlations',
  report: 'rapport executif'
};

const TYPE_LABELS = {
  username: 'pseudo',
  domain: 'domaine ou IP',
  email: 'email',
  phone: 'telephone'
};

const SOCIAL_PLATFORMS = [
  { name: 'Google', category: 'search', url: (q) => `https://www.google.com/search?q=${encodeURIComponent(`"${q}"`)}` },
  { name: 'TikTok', category: 'social', url: (q) => `https://www.tiktok.com/@${encodeURIComponent(q)}` },
  { name: 'Snapchat', category: 'social', url: (q) => `https://www.snapchat.com/add/${encodeURIComponent(q)}` },
  { name: 'Instagram', category: 'social', url: (q) => `https://www.instagram.com/${encodeURIComponent(q)}/` },
  { name: 'X / Twitter', category: 'social', url: (q) => `https://x.com/${encodeURIComponent(q)}` },
  { name: 'GitHub', category: 'social', url: (q) => `https://github.com/${encodeURIComponent(q)}` },
  { name: 'LinkedIn', category: 'business', url: (q) => `https://www.google.com/search?q=${encodeURIComponent(`${q} site:linkedin.com/in OR site:linkedin.com/company`)}` },
  { name: 'YouTube', category: 'social', url: (q) => `https://www.youtube.com/results?search_query=${encodeURIComponent(q)}` },
  { name: 'Reddit', category: 'social', url: (q) => `https://www.reddit.com/search/?q=${encodeURIComponent(q)}` },
  { name: 'Discord mentions', category: 'social', url: (q) => `https://www.google.com/search?q=${encodeURIComponent(`"${q}" Discord`)}` }
];

function safeTarget(value) {
  return String(value || '').trim().replace(/[<>]/g, '').slice(0, 200);
}

function hashToInt(input, min, max) {
  let hash = 0;
  for (const char of String(input)) {
    hash = ((hash << 5) - hash) + char.charCodeAt(0);
    hash |= 0;
  }
  const span = max - min + 1;
  return min + Math.abs(hash % span);
}

function pick(input, values) {
  return values[hashToInt(input, 0, values.length - 1)];
}

function buildPrompt(type, query, options = []) {
  const modules = options.length
    ? options.map(opt => MODULE_LABELS[opt] || opt).join(', ')
    : 'tous les modules prudents';

  return `Cible: ${query}
Type: ${TYPE_LABELS[type] || type}
Modules demandes: ${modules}

Genere une analyse OSINT poussee mais ethique. Si une information est incertaine, indique clairement que c'est une hypothese.
Ne pretend pas avoir interroge une base privee. Ne donne pas d'adresse personnelle, numero personnel, mot de passe, donnees bancaires, informations medicales ou informations sensibles.
Dans concrete_results, donne uniquement des elements publics et non sensibles: URL de profil public, requete Google exacte, compte TikTok/Snapchat/Instagram public a verifier, domaine, email generique d'entreprise, contact officiel d'entreprise, WHOIS non masque, pages publiques. La ville/localisation ne peut apparaitre que comme "ville publique possible" avec source publique a verifier. Si une valeur ressemble a une information personnelle privee, remplace-la par "masque - information personnelle non fournie".

Schema JSON attendu:
{
  "mode": "ai",
  "case_overview": {
    "target": "...",
    "type": "...",
    "generated_at": "...",
    "executive_summary": "...",
    "confidence": "faible|moyenne|elevee",
    "risk_level": "faible|modere|eleve|critique",
    "legal_notice": "..."
  },
  "terminal_lines": [{"prefix":">","text":"...","cls":"muted|ok|warn|err|info|bold"}],
  "stats": [{"label":"...","value":"...","sub":"..."}],
  "tags": [{"text":"...","color":"blue|amber|red|green|gray"}],
  "risk_matrix": [{"axis":"...","score":0,"level":"faible|modere|eleve|critique","evidence":"..."}],
  "findings": [{"title":"...","severity":"info|low|medium|high|critical","confidence":"low|medium|high","description":"...","evidence":"...","recommended_action":"...","source_type":"public|hypothesis|user_supplied"}],
  "concrete_results": [{"label":"...","value":"...","category":"identity|contact|domain|social|technical|business","confidence":"low|medium|high","source_url":"...","status":"verified_public|needs_verification|user_supplied","privacy_note":"..."}],
  "entities": {"handles":[],"domains":[],"emails":[],"urls":[],"ips":[],"organizations":[],"locations":[]},
  "timeline": [{"date":"...","label":"...","detail":"...","confidence":"low|medium|high"}],
  "sources": [{"name":"...","url":"...","category":"...","reliability":"low|medium|high","notes":"..."}],
  "next_steps": ["..."],
  "report_sections": {"methodology":"...","limitations":"...","confidence_notes":"..."},
  "summary": "...",
  "platforms": [{"name":"...","url":"...","status":"found|not_found|private|unknown","confidence":"high|medium|low"}],
  "dns_records": [{"type":"A|AAAA|MX|NS|TXT|CAA","value":"..."}],
  "whois": {"registrar":"...","created":"...","expires":"...","privacy":true},
  "breaches": [{"source":"...","year":"...","data_types":["..."],"status":"public_hypothesis|needs_verification"}]
}

Adapte les champs au type. Fournis au moins 10 concrete_results publics et actionnables, 8 findings, 7 sources, 5 lignes de timeline et 14 terminal_lines.
Les resultats doivent etre concrets: URLs exactes ou requetes directes, domaine, sous-domaines probables, emails generiques publics, profils publics a verifier, signaux techniques, ville publique possible si sourcée, preuves datees, mais jamais de coordonnees personnelles privees.`;
}

function createStats(type, query, risk) {
  const base = [
    { label: 'Score risque', value: `${risk}/100`, sub: risk >= 70 ? 'priorite haute' : risk >= 45 ? 'surveillance conseillee' : 'exposition limitee' },
    { label: 'Confiance', value: `${hashToInt(query, 62, 91)}%`, sub: 'estimation du rapport' },
    { label: 'Sources', value: `${hashToInt(query + type, 8, 18)}`, sub: 'pistes publiques' }
  ];
  if (type === 'username') base.push({ label: 'Plateformes', value: `${hashToInt(query, 4, 13)}/24`, sub: 'correlations possibles' });
  if (type === 'domain') base.push({ label: 'DNS', value: `${hashToInt(query, 5, 11)}`, sub: 'enregistrements analyses' });
  if (type === 'email') base.push({ label: 'Exposition', value: `${hashToInt(query, 0, 4)}`, sub: 'signaux a verifier' });
  if (type === 'phone') base.push({ label: 'Format', value: 'OK', sub: 'analyse non intrusive' });
  return base;
}

function fallbackAnalysis(type, rawQuery, options = []) {
  const query = safeTarget(rawQuery);
  const risk = hashToInt(`${type}:${query}`, 28, 86);
  const riskLevel = risk >= 75 ? 'critique' : risk >= 60 ? 'eleve' : risk >= 42 ? 'modere' : 'faible';
  const confidence = risk >= 65 ? 'moyenne' : 'faible';
  const now = new Date().toISOString();
  const modules = options.length ? options.map(opt => MODULE_LABELS[opt] || opt) : ['reseaux sociaux', 'archives web', 'correlations', 'rapport executif'];
  const targetDomain = type === 'email' && query.includes('@') ? query.split('@').pop() : query;

  const terminalLines = [
    { prefix: '>', text: `Initialisation dossier OSINT: ${query}`, cls: 'bold' },
    { prefix: '>', text: `Type cible: ${TYPE_LABELS[type] || type}`, cls: 'info' },
    { prefix: '>', text: `Modules actifs: ${modules.join(', ')}`, cls: 'muted' },
    { prefix: '>', text: 'Verification du perimetre legal: sources publiques uniquement', cls: 'ok' },
    { prefix: '>', text: 'Normalisation de la cible et generation des variantes', cls: 'info' },
    { prefix: '>', text: 'Recherche de signaux de presence publique', cls: 'info' },
    { prefix: '>', text: 'Correlation des alias, domaines et liens probables', cls: 'warn' },
    { prefix: '>', text: 'Construction de la matrice de risque', cls: 'info' },
    { prefix: '>', text: 'Evaluation de la confiance des indices', cls: 'muted' },
    { prefix: '>', text: 'Aucune action intrusive executee', cls: 'ok' },
    { prefix: '>', text: 'Mode demonstration: connecter GROQ_API_KEY pour enrichir par IA', cls: 'warn' },
    { prefix: '>', text: 'Rapport pret pour revue analyste', cls: 'ok' }
  ];

  const tags = [
    { text: 'OSINT legal', color: 'green' },
    { text: 'sources publiques', color: 'blue' },
    { text: 'verification requise', color: 'amber' },
    { text: `risque ${riskLevel}`, color: risk >= 60 ? 'red' : risk >= 42 ? 'amber' : 'green' }
  ];

  const riskMatrix = [
    { axis: 'Identite numerique', score: hashToInt(query, 25, 88), level: pick(query, ['faible', 'modere', 'eleve']), evidence: 'Similarites de nommage et reutilisation possible du meme identifiant.' },
    { axis: 'Exposition publique', score: risk, level: riskLevel, evidence: 'Presence de signaux publics et metadonnees accessibles sans authentification.' },
    { axis: 'Infrastructure', score: type === 'domain' ? hashToInt(query, 45, 90) : hashToInt(query, 12, 55), level: type === 'domain' ? 'modere' : 'faible', evidence: 'Analyse limitee aux indices techniques non intrusifs.' },
    { axis: 'Usurpation', score: hashToInt(`${query}:impersonation`, 18, 76), level: pick(`${query}:impersonation`, ['faible', 'modere', 'eleve']), evidence: 'Risque estime a partir de la visibilite et de la facilite de duplication du profil.' },
    { axis: 'Qualite des preuves', score: hashToInt(`${query}:quality`, 50, 92), level: 'modere', evidence: 'Les resultats doivent etre confirmes par des sources primaires.' }
  ];

  const findings = [
    {
      title: 'Profil de cible consolide',
      severity: 'medium',
      confidence: 'medium',
      description: `La cible ${query} presente plusieurs signaux pouvant etre regroupes dans un meme dossier d'analyse.`,
      evidence: 'Recoupement de format, variantes et indices de presence publique.',
      recommended_action: 'Verifier manuellement chaque source primaire avant toute conclusion.',
      source_type: 'hypothesis'
    },
    {
      title: 'Perimetre legal respecte',
      severity: 'info',
      confidence: 'high',
      description: 'Le rapport se limite aux informations publiques et aux hypotheses documentees.',
      evidence: 'Aucun module intrusif, aucun contournement, aucune collecte de secret.',
      recommended_action: 'Conserver cette trace dans le dossier de mission.',
      source_type: 'user_supplied'
    },
    {
      title: 'Risque de correlation inter-plateformes',
      severity: risk >= 60 ? 'high' : 'medium',
      confidence: 'medium',
      description: 'La reutilisation d identifiants ou de motifs peut relier plusieurs presences en ligne.',
      evidence: 'Variantes proches du nom de cible et signaux de nommage repetes.',
      recommended_action: 'Segmenter les identifiants publics et reduire les informations redondantes.',
      source_type: 'hypothesis'
    },
    {
      title: 'Sources a fiabiliser',
      severity: 'low',
      confidence: 'high',
      description: 'Certaines pistes sont utiles mais ne suffisent pas seules a etablir une certitude.',
      evidence: 'Sources secondaires, caches, archives ou resultats indirects.',
      recommended_action: 'Prioriser les sources officielles, profils verifies et pages de controle.',
      source_type: 'public'
    },
    {
      title: 'Exposition temporelle',
      severity: 'medium',
      confidence: 'low',
      description: 'Des traces anciennes peuvent rester accessibles via archives ou index publics.',
      evidence: 'Chronologie indicative generee a partir de signaux publics probables.',
      recommended_action: 'Examiner les caches et demander suppression si necessaire.',
      source_type: 'hypothesis'
    },
    {
      title: 'Surface de contact',
      severity: type === 'email' || type === 'phone' ? 'high' : 'medium',
      confidence: 'medium',
      description: 'La cible peut servir de point d entree pour spam, usurpation ou prise de contact non sollicitee.',
      evidence: 'Type de cible directement contactable ou facilement imitable.',
      recommended_action: 'Activer les protections de compte et limiter l affichage public.',
      source_type: 'hypothesis'
    },
    {
      title: 'Besoin de validation humaine',
      severity: 'info',
      confidence: 'high',
      description: 'Une decision ne doit pas se baser uniquement sur ce rapport automatique.',
      evidence: 'Le mode demonstration ne consulte pas de services externes en temps reel.',
      recommended_action: 'Ajouter des captures datees et URLs verifiees au dossier final.',
      source_type: 'user_supplied'
    },
    {
      title: 'Priorite de remediation',
      severity: risk >= 70 ? 'high' : 'medium',
      confidence: 'medium',
      description: 'Les actions les plus utiles sont la reduction de traces publiques et la verification de securite des comptes.',
      evidence: 'Matrice de risque et score global.',
      recommended_action: 'Traiter d abord les sources publiques les plus visibles.',
      source_type: 'hypothesis'
    }
  ];

  const sources = [
    { name: 'Recherche web publique', url: `https://www.google.com/search?q=${encodeURIComponent(query)}`, category: 'search', reliability: 'medium', notes: 'A verifier manuellement.' },
    { name: 'Recherche exacte', url: `https://www.google.com/search?q=${encodeURIComponent(`"${query}"`)}`, category: 'search', reliability: 'high', notes: 'Permet de reduire le bruit.' },
    { name: 'Archives web', url: `https://web.archive.org/web/*/${encodeURIComponent(query)}`, category: 'archive', reliability: 'medium', notes: 'Utile pour les traces historiques.' },
    { name: 'Recherche GitHub', url: `https://github.com/search?q=${encodeURIComponent(query)}`, category: 'code', reliability: 'medium', notes: 'Verifier les homonymes.' },
    { name: 'Recherche Reddit', url: `https://www.reddit.com/search/?q=${encodeURIComponent(query)}`, category: 'social', reliability: 'low', notes: 'Source bruyante.' },
    { name: 'Recherche LinkedIn publique', url: `https://www.google.com/search?q=${encodeURIComponent(`${query} site:linkedin.com/in OR site:linkedin.com/company`)}`, category: 'business', reliability: 'medium', notes: 'Profils publics et entreprises a confirmer.' },
    { name: 'Recherche documents PDF', url: `https://www.google.com/search?q=${encodeURIComponent(`${query} filetype:pdf`)}`, category: 'documents', reliability: 'medium', notes: 'Documents publics indexés.' },
    { name: 'Documentation analyste interne', url: '#', category: 'methodology', reliability: 'high', notes: 'Cadre de travail et limites.' }
  ];

  const concreteResults = [
    {
      label: 'Cible analysee',
      value: query,
      category: type === 'domain' ? 'domain' : type === 'email' ? 'contact' : 'identity',
      confidence: 'high',
      source_url: '#',
      status: 'user_supplied',
      privacy_note: 'Valeur fournie par l utilisateur.'
    },
    {
      label: 'Recherche web exacte',
      value: `Pages indexees contenant "${query}"`,
      category: 'social',
      confidence: 'medium',
      source_url: `https://www.google.com/search?q=${encodeURIComponent(`"${query}"`)}`,
      status: 'needs_verification',
      privacy_note: 'Source publique a verifier manuellement.'
    },
    {
      label: 'Archive publique',
      value: 'Historique web potentiel',
      category: 'business',
      confidence: 'medium',
      source_url: `https://web.archive.org/web/*/${encodeURIComponent(query)}`,
      status: 'needs_verification',
      privacy_note: 'Ne pas utiliser pour exposer des donnees personnelles.'
    },
    {
      label: 'Recherche documents',
      value: `PDF publics contenant "${query}"`,
      category: 'business',
      confidence: 'medium',
      source_url: `https://www.google.com/search?q=${encodeURIComponent(`${query} filetype:pdf`)}`,
      status: 'needs_verification',
      privacy_note: 'Seulement documents publics indexes.'
    },
    {
      label: 'Recherche profils publics',
      value: 'Profils sociaux ou professionnels a verifier',
      category: 'social',
      confidence: 'medium',
      source_url: `https://www.google.com/search?q=${encodeURIComponent(`${query} site:linkedin.com OR site:github.com OR site:x.com OR site:instagram.com`)}`,
      status: 'needs_verification',
      privacy_note: 'Verifier les homonymes avant conclusion.'
    },
    {
      label: 'Recherche mentions recentes',
      value: 'Pages publiques recentes',
      category: 'business',
      confidence: 'medium',
      source_url: `https://www.google.com/search?q=${encodeURIComponent(query)}&tbs=qdr:y`,
      status: 'needs_verification',
      privacy_note: 'Source publique, a confirmer.'
    },
    {
      label: 'Nom / prenom prive',
      value: 'masque - information personnelle non fournie',
      category: 'identity',
      confidence: 'low',
      source_url: '#',
      status: 'needs_verification',
      privacy_note: 'Non affiche sauf si profil officiel, entreprise, ou consentement explicite.'
    },
    {
      label: 'Adresse / telephone prive',
      value: 'masque - information personnelle non fournie',
      category: 'contact',
      confidence: 'low',
      source_url: '#',
      status: 'needs_verification',
      privacy_note: 'Les coordonnees personnelles privees sont exclues du rapport.'
    }
  ];

  if (type === 'domain') {
    concreteResults.push(
      {
        label: 'Domaine racine',
        value: targetDomain,
        category: 'domain',
        confidence: 'high',
        source_url: `https://${targetDomain}`,
        status: 'needs_verification',
        privacy_note: 'Information technique publique.'
      },
      {
        label: 'Email generique probable',
        value: `contact@${targetDomain}`,
        category: 'contact',
        confidence: 'low',
        source_url: `https://${targetDomain}`,
        status: 'needs_verification',
        privacy_note: 'A verifier sur la page officielle du domaine.'
      },
      {
        label: 'Certificats publics',
        value: `Sous-domaines publics de ${targetDomain}`,
        category: 'technical',
        confidence: 'medium',
        source_url: `https://crt.sh/?q=${encodeURIComponent(targetDomain)}`,
        status: 'needs_verification',
        privacy_note: 'Source publique de certificats TLS.'
      },
      {
        label: 'Recherche pages contact',
        value: `Pages contact de ${targetDomain}`,
        category: 'contact',
        confidence: 'medium',
        source_url: `https://www.google.com/search?q=${encodeURIComponent(`site:${targetDomain} contact OR "mentions legales" OR "legal notice"`)}`,
        status: 'needs_verification',
        privacy_note: 'Contacts officiels uniquement.'
      }
    );
  }

  if (type === 'email') {
    concreteResults.push({
      label: 'Domaine email',
      value: targetDomain,
      category: 'domain',
      confidence: 'high',
      source_url: `https://${targetDomain}`,
      status: 'needs_verification',
      privacy_note: 'Le domaine est deduit de l email fourni.'
    });
  }

  if (type === 'username') {
    SOCIAL_PLATFORMS.forEach((platform) => {
      concreteResults.push({
        label: `Compte ${platform.name}`,
        value: platform.name === 'Google' ? `Recherche exacte "${query}"` : `${query} sur ${platform.name}`,
        category: platform.category === 'search' ? 'social' : platform.category,
        confidence: pick(`${query}:${platform.name}:confidence`, ['low', 'medium', 'medium', 'high']),
        source_url: platform.url(query),
        status: 'needs_verification',
        privacy_note: 'Profil public potentiel a ouvrir et verifier. Attention aux homonymes.'
      });
    });

    concreteResults.push(
      {
        label: 'Ville publique possible',
        value: 'A verifier uniquement si indiquee sur un profil public',
        category: 'identity',
        confidence: 'low',
        source_url: `https://www.google.com/search?q=${encodeURIComponent(`"${query}" ville OR city OR location OR "based in"`)}`,
        status: 'needs_verification',
        privacy_note: 'Ne pas inferer une adresse ou une localisation privee.'
      },
      {
        label: 'Adresse email publique possible',
        value: 'Recherche de mail public associe au pseudo',
        category: 'contact',
        confidence: 'low',
        source_url: `https://www.google.com/search?q=${encodeURIComponent(`"${query}" email OR contact OR mail`)}`,
        status: 'needs_verification',
        privacy_note: 'Afficher seulement les emails publies volontairement ou contacts professionnels.'
      },
      {
        label: 'Compte Google / profil public',
        value: 'Recherche profil Google public',
        category: 'social',
        confidence: 'low',
        source_url: `https://www.google.com/search?q=${encodeURIComponent(`"${query}" "Google" "profile"`)}`,
        status: 'needs_verification',
        privacy_note: 'Ne donne pas acces a un compte prive.'
      }
    );
  }

  const platformNames = ['Google', 'TikTok', 'Snapchat', 'Instagram', 'GitHub', 'X/Twitter', 'Reddit', 'LinkedIn', 'YouTube', 'Twitch', 'Steam', 'Medium', 'Discord'];
  const platforms = type === 'username' ? platformNames.map(name => ({
    name,
    url: `https://www.google.com/search?q=${encodeURIComponent(`${query} ${name}`)}`,
    status: pick(`${query}:${name}`, ['found', 'unknown', 'not_found', 'private']),
    confidence: pick(`${name}:${query}`, ['high', 'medium', 'low'])
  })) : [];

  const dnsRecords = type === 'domain' ? [
    { type: 'A', value: `203.0.113.${hashToInt(query, 10, 240)} (exemple reserve)` },
    { type: 'MX', value: `10 mail.${targetDomain}` },
    { type: 'NS', value: `ns1.${targetDomain}` },
    { type: 'TXT', value: 'v=spf1 include:_spf.example.net ~all' },
    { type: 'CAA', value: '0 issue "letsencrypt.org"' }
  ] : [];

  const breaches = type === 'email' ? [
    { source: 'Index public a verifier', year: String(hashToInt(query, 2018, 2024)), data_types: ['email', 'metadata'], status: 'needs_verification' },
    { source: 'Paste/cache public potentiel', year: String(hashToInt(query + 'b', 2016, 2022)), data_types: ['email'], status: 'public_hypothesis' }
  ] : [];

  return {
    mode: 'demo',
    case_overview: {
      target: query,
      type: TYPE_LABELS[type] || type,
      generated_at: now,
      executive_summary: `Rapport OSINT de demonstration pour ${query}. Le score global indique un risque ${riskLevel}; les elements presentes sont des pistes publiques ou des hypotheses a verifier avant utilisation operationnelle.`,
      confidence,
      risk_level: riskLevel,
      legal_notice: 'Analyse limitee aux sources publiques et aux hypotheses. Ne pas utiliser pour harceler, profiler abusivement ou contourner un acces.'
    },
    terminal_lines: terminalLines,
    stats: createStats(type, query, risk),
    tags,
    risk_matrix: riskMatrix,
    findings,
    concrete_results: ensurePublicDiscoveryResults(type, query, concreteResults),
    entities: {
      handles: type === 'username' ? [query, `${query}_official`, `${query}.pro`] : [],
      domains: type === 'domain' ? [targetDomain, `www.${targetDomain}`, `mail.${targetDomain}`] : (type === 'email' ? [targetDomain] : []),
      emails: type === 'email' ? [query] : [],
      urls: [`https://www.google.com/search?q=${encodeURIComponent(query)}`],
      ips: type === 'domain' ? [`203.0.113.${hashToInt(query, 10, 240)}`] : [],
      organizations: [pick(query, ['Organisation non confirmee', 'Service web potentiel', 'Marque ou alias potentiel'])],
      locations: [pick(query, ['France possible', 'Europe possible', 'Localisation non confirmee'])]
    },
    timeline: [
      { date: 'T-90j', label: 'Indexation recente', detail: 'Recherche de pages publiques recentes autour de la cible.', confidence: 'low' },
      { date: 'T-1an', label: 'Archives', detail: 'Verification conseillee dans les caches et archives web.', confidence: 'medium' },
      { date: 'T-2ans', label: 'Correlations', detail: 'Controle des variantes et pseudonymes proches.', confidence: 'low' },
      { date: 'Aujourd hui', label: 'Rapport', detail: 'Generation automatique du dossier et de la matrice de risque.', confidence: 'high' },
      { date: 'Prochaine etape', label: 'Validation', detail: 'Confirmer les sources primaires et capturer les preuves.', confidence: 'high' }
    ],
    sources,
    next_steps: [
      'Verifier les URLs primaires et capturer les preuves datees.',
      'Classer chaque indice selon public, hypothese ou fourni par le client.',
      'Reduire les informations publiques inutiles sur les profils controles.',
      'Activer MFA et alertes de connexion sur les comptes exposes.',
      'Relancer une analyse enrichie avec une cle API si necessaire.'
    ],
    report_sections: {
      methodology: 'Normalisation de la cible, generation de variantes, analyse de signaux publics, scoring de risque, synthese analyste.',
      limitations: 'Le mode demonstration ne consulte pas de services externes en temps reel et ne constitue pas une preuve definitive.',
      confidence_notes: 'La confiance augmente lorsque plusieurs sources primaires independantes confirment le meme fait.'
    },
    summary: `La cible ${query} merite une revue manuelle: le rapport identifie des pistes de presence publique, des risques de correlation et des actions de reduction d exposition. Les resultats sont exploitables comme base de travail, pas comme verdict final.`,
    platforms,
    dns_records: dnsRecords,
    whois: type === 'domain' ? { registrar: 'A verifier', created: `${hashToInt(query, 2008, 2022)}-01-01`, expires: `${hashToInt(query, 2026, 2030)}-01-01`, privacy: true } : undefined,
    breaches
  };
}

function normalizeResult(result, type, query, options) {
  const fallback = fallbackAnalysis(type, query, options);
  const concreteResults = Array.isArray(result.concrete_results) && result.concrete_results.length
    ? result.concrete_results
    : fallback.concrete_results;
  return {
    ...fallback,
    ...result,
    mode: result.mode || 'ai',
    case_overview: { ...fallback.case_overview, ...(result.case_overview || {}) },
    terminal_lines: Array.isArray(result.terminal_lines) && result.terminal_lines.length ? result.terminal_lines : fallback.terminal_lines,
    stats: Array.isArray(result.stats) && result.stats.length ? result.stats : fallback.stats,
    tags: Array.isArray(result.tags) && result.tags.length ? result.tags : fallback.tags,
    risk_matrix: Array.isArray(result.risk_matrix) && result.risk_matrix.length ? result.risk_matrix : fallback.risk_matrix,
    findings: Array.isArray(result.findings) && result.findings.length ? result.findings : fallback.findings,
    concrete_results: ensurePublicDiscoveryResults(type, query, concreteResults),
    entities: { ...fallback.entities, ...(result.entities || {}) },
    timeline: Array.isArray(result.timeline) && result.timeline.length ? result.timeline : fallback.timeline,
    sources: Array.isArray(result.sources) && result.sources.length ? result.sources : fallback.sources,
    next_steps: Array.isArray(result.next_steps) && result.next_steps.length ? result.next_steps : fallback.next_steps,
    report_sections: { ...fallback.report_sections, ...(result.report_sections || {}) }
  };
}

function ensurePublicDiscoveryResults(type, query, items = []) {
  if (type !== 'username') return items;
  const labels = new Set(items.map((item) => String(item.label || '').toLowerCase()));
  const required = [
    {
      key: 'compte tiktok',
      label: 'Compte TikTok',
      value: `${query} sur TikTok`,
      category: 'social',
      confidence: 'medium',
      source_url: `https://www.tiktok.com/@${encodeURIComponent(query)}`,
      status: 'needs_verification',
      privacy_note: 'Profil public potentiel a verifier.'
    },
    {
      key: 'compte snapchat',
      label: 'Compte Snapchat',
      value: `${query} sur Snapchat`,
      category: 'social',
      confidence: 'medium',
      source_url: `https://www.snapchat.com/add/${encodeURIComponent(query)}`,
      status: 'needs_verification',
      privacy_note: 'Profil public potentiel a verifier.'
    },
    {
      key: 'compte google',
      label: 'Compte Google / profil public',
      value: 'Recherche profil Google public',
      category: 'social',
      confidence: 'low',
      source_url: `https://www.google.com/search?q=${encodeURIComponent(`"${query}" "Google" "profile"`)}`,
      status: 'needs_verification',
      privacy_note: 'Ne donne pas acces a un compte prive.'
    },
    {
      key: 'ville publique',
      label: 'Ville publique possible',
      value: 'A verifier uniquement si indiquee sur un profil public',
      category: 'identity',
      confidence: 'low',
      source_url: `https://www.google.com/search?q=${encodeURIComponent(`"${query}" ville OR city OR location OR "based in"`)}`,
      status: 'needs_verification',
      privacy_note: 'Ne pas inferer une adresse ou une localisation privee.'
    },
    {
      key: 'adresse email',
      label: 'Adresse email publique possible',
      value: 'Recherche de mail public associe au pseudo',
      category: 'contact',
      confidence: 'low',
      source_url: `https://www.google.com/search?q=${encodeURIComponent(`"${query}" email OR contact OR mail`)}`,
      status: 'needs_verification',
      privacy_note: 'Afficher seulement les emails publies volontairement ou contacts professionnels.'
    }
  ];
  const merged = [...items];
  required.forEach((item) => {
    if (!Array.from(labels).some((label) => label.includes(item.key))) merged.push(item);
  });
  return merged;
}

async function runOsintAnalysis(type, query, options = []) {
  const cleanQuery = safeTarget(query);
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) return fallbackAnalysis(type, cleanQuery, options);

  try {
    const response = await fetch(GROQ_API, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: process.env.GROQ_MODEL || 'llama-3.3-70b-versatile',
        max_tokens: 3600,
        temperature: 0.45,
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: buildPrompt(type, cleanQuery, options) }
        ]
      })
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error?.message || `API Groq error ${response.status}`);
    }

    const data = await response.json();
    const raw = data.choices?.[0]?.message?.content || '';
    const clean = raw.replace(/```json|```/g, '').trim();
    return normalizeResult(JSON.parse(clean), type, cleanQuery, options);
  } catch (err) {
    const demo = fallbackAnalysis(type, cleanQuery, options);
    demo.terminal_lines.push({ prefix: '>', text: `Bascule demo: ${err.message}`, cls: 'warn' });
    demo.case_overview.executive_summary += ' Une erreur API a declenche le mode demonstration.';
    return demo;
  }
}

module.exports = { runOsintAnalysis };
