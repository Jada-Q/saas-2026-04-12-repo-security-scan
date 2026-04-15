/**
 * Comprehensive secret detection patterns organized by category.
 * Each pattern includes a regex, classification, and severity level.
 */

export type SecretSeverity = "critical" | "high" | "medium" | "low";

export type SecretType =
  | "api-key"
  | "token"
  | "password"
  | "private-key"
  | "connection-string"
  | "webhook"
  | "email";

export interface SecretPattern {
  id: string;
  name: string;
  pattern: RegExp;
  type: SecretType;
  severity: SecretSeverity;
  category: string;
}

// ─── Cloud Providers ─────────────────────────────────────────────

const cloudPatterns: SecretPattern[] = [
  { id: "aws-access-key", name: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/g, type: "api-key", severity: "critical", category: "Cloud" },
  { id: "aws-secret-key", name: "AWS Secret Key", pattern: /(?:aws_secret_access_key|aws_secret)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi, type: "api-key", severity: "critical", category: "Cloud" },
  { id: "aws-session-token", name: "AWS Session Token", pattern: /(?:aws_session_token)\s*[:=]\s*["']?([A-Za-z0-9/+=]{100,})["']?/gi, type: "token", severity: "critical", category: "Cloud" },
  { id: "gcp-api-key", name: "Google API Key", pattern: /AIza[0-9A-Za-z_-]{35}/g, type: "api-key", severity: "high", category: "Cloud" },
  { id: "gcp-service-account", name: "GCP Service Account", pattern: /"type"\s*:\s*"service_account"/g, type: "api-key", severity: "critical", category: "Cloud" },
  { id: "gcp-oauth-client", name: "GCP OAuth Client Secret", pattern: /[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com/g, type: "api-key", severity: "high", category: "Cloud" },
  { id: "azure-storage-key", name: "Azure Storage Key", pattern: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}/g, type: "api-key", severity: "critical", category: "Cloud" },
  { id: "azure-ad-secret", name: "Azure AD Client Secret", pattern: /(?:azure[_-]?(?:client[_-]?)?secret)\s*[:=]\s*["']([^"']{30,})["']/gi, type: "api-key", severity: "critical", category: "Cloud" },
  { id: "digitalocean-token", name: "DigitalOcean Token", pattern: /dop_v1_[a-f0-9]{64}/g, type: "token", severity: "high", category: "Cloud" },
  { id: "digitalocean-pat", name: "DigitalOcean PAT", pattern: /doo_v1_[a-f0-9]{64}/g, type: "token", severity: "high", category: "Cloud" },
  { id: "cloudflare-api-key", name: "Cloudflare API Key", pattern: /(?:cloudflare[_-]?api[_-]?key)\s*[:=]\s*["']([a-f0-9]{37})["']/gi, type: "api-key", severity: "high", category: "Cloud" },
  { id: "cloudflare-api-token", name: "Cloudflare API Token", pattern: /(?:cf[_-]?api[_-]?token)\s*[:=]\s*["']([A-Za-z0-9_-]{40})["']/gi, type: "token", severity: "high", category: "Cloud" },
  { id: "heroku-api-key", name: "Heroku API Key", pattern: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g, type: "api-key", severity: "medium", category: "Cloud" },
  { id: "vercel-token", name: "Vercel Token", pattern: /(?:vercel[_-]?token|VERCEL_TOKEN)\s*[:=]\s*["']([A-Za-z0-9]{24,})["']/gi, type: "token", severity: "high", category: "Cloud" },
  { id: "netlify-token", name: "Netlify Token", pattern: /(?:netlify[_-]?(?:auth[_-]?)?token)\s*[:=]\s*["']([A-Za-z0-9_-]{40,})["']/gi, type: "token", severity: "high", category: "Cloud" },
  { id: "ibm-cloud-key", name: "IBM Cloud API Key", pattern: /(?:ibm[_-]?(?:cloud[_-]?)?api[_-]?key)\s*[:=]\s*["']([A-Za-z0-9_-]{44})["']/gi, type: "api-key", severity: "high", category: "Cloud" },
  { id: "alibaba-access-key", name: "Alibaba Cloud AccessKey", pattern: /LTAI[A-Za-z0-9]{20}/g, type: "api-key", severity: "critical", category: "Cloud" },
];

// ─── AI / ML Services ────────────────────────────────────────────

const aiPatterns: SecretPattern[] = [
  { id: "openai-key", name: "OpenAI API Key", pattern: /sk-[a-zA-Z0-9]{20,}/g, type: "api-key", severity: "critical", category: "AI" },
  { id: "openai-proj-key", name: "OpenAI Project Key", pattern: /sk-proj-[A-Za-z0-9_-]{80,}/g, type: "api-key", severity: "critical", category: "AI" },
  { id: "anthropic-key", name: "Anthropic API Key", pattern: /sk-ant-[a-zA-Z0-9_-]{80,}/g, type: "api-key", severity: "critical", category: "AI" },
  { id: "huggingface-token", name: "Hugging Face Token", pattern: /hf_[a-zA-Z0-9]{34}/g, type: "token", severity: "high", category: "AI" },
  { id: "replicate-token", name: "Replicate API Token", pattern: /r8_[a-zA-Z0-9]{40}/g, type: "token", severity: "high", category: "AI" },
  { id: "cohere-key", name: "Cohere API Key", pattern: /(?:cohere[_-]?api[_-]?key|CO_API_KEY)\s*[:=]\s*["']([A-Za-z0-9]{40})["']/gi, type: "api-key", severity: "high", category: "AI" },
  { id: "pinecone-key", name: "Pinecone API Key", pattern: /(?:pinecone[_-]?api[_-]?key|PINECONE_API_KEY)\s*[:=]\s*["']([a-f0-9-]{36})["']/gi, type: "api-key", severity: "high", category: "AI" },
  { id: "stability-key", name: "Stability AI Key", pattern: /sk-[A-Za-z0-9]{48,}/g, type: "api-key", severity: "high", category: "AI" },
  { id: "mistral-key", name: "Mistral API Key", pattern: /(?:mistral[_-]?api[_-]?key|MISTRAL_API_KEY)\s*[:=]\s*["']([A-Za-z0-9]{32})["']/gi, type: "api-key", severity: "high", category: "AI" },
  { id: "groq-key", name: "Groq API Key", pattern: /gsk_[a-zA-Z0-9]{52}/g, type: "api-key", severity: "high", category: "AI" },
  { id: "elevenlabs-key", name: "ElevenLabs API Key", pattern: /(?:elevenlabs[_-]?api[_-]?key|ELEVEN_API_KEY)\s*[:=]\s*["']([a-f0-9]{32})["']/gi, type: "api-key", severity: "high", category: "AI" },
];

// ─── Version Control / CI ────────────────────────────────────────

const ciPatterns: SecretPattern[] = [
  { id: "github-pat", name: "GitHub PAT (classic)", pattern: /ghp_[a-zA-Z0-9]{36}/g, type: "token", severity: "critical", category: "CI/VCS" },
  { id: "github-pat-fine", name: "GitHub PAT (fine-grained)", pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g, type: "token", severity: "critical", category: "CI/VCS" },
  { id: "github-oauth", name: "GitHub OAuth Token", pattern: /gho_[a-zA-Z0-9]{36}/g, type: "token", severity: "high", category: "CI/VCS" },
  { id: "github-app-user", name: "GitHub App User Token", pattern: /ghu_[a-zA-Z0-9]{36}/g, type: "token", severity: "high", category: "CI/VCS" },
  { id: "github-app-server", name: "GitHub App Server Token", pattern: /ghs_[a-zA-Z0-9]{36}/g, type: "token", severity: "high", category: "CI/VCS" },
  { id: "github-app-refresh", name: "GitHub App Refresh Token", pattern: /ghr_[a-zA-Z0-9]{36}/g, type: "token", severity: "high", category: "CI/VCS" },
  { id: "gitlab-pat", name: "GitLab PAT", pattern: /glpat-[a-zA-Z0-9_-]{20}/g, type: "token", severity: "critical", category: "CI/VCS" },
  { id: "gitlab-pipeline", name: "GitLab Pipeline Token", pattern: /glptt-[a-f0-9]{40}/g, type: "token", severity: "high", category: "CI/VCS" },
  { id: "bitbucket-app-password", name: "Bitbucket App Password", pattern: /(?:bitbucket[_-]?(?:app[_-]?)?password)\s*[:=]\s*["']([A-Za-z0-9]{18,})["']/gi, type: "password", severity: "high", category: "CI/VCS" },
  { id: "circleci-token", name: "CircleCI Token", pattern: /(?:circle[_-]?ci[_-]?token|CIRCLE_TOKEN)\s*[:=]\s*["']([a-f0-9]{40})["']/gi, type: "token", severity: "high", category: "CI/VCS" },
  { id: "travis-token", name: "Travis CI Token", pattern: /(?:travis[_-]?(?:ci[_-]?)?token)\s*[:=]\s*["']([A-Za-z0-9]{22,})["']/gi, type: "token", severity: "high", category: "CI/VCS" },
  { id: "npm-token", name: "npm Access Token", pattern: /npm_[a-zA-Z0-9]{36}/g, type: "token", severity: "critical", category: "CI/VCS" },
  { id: "pypi-token", name: "PyPI API Token", pattern: /pypi-[A-Za-z0-9_-]{100,}/g, type: "token", severity: "critical", category: "CI/VCS" },
];

// ─── Payment / Finance ───────────────────────────────────────────

const paymentPatterns: SecretPattern[] = [
  { id: "stripe-secret", name: "Stripe Secret Key", pattern: /sk_live_[a-zA-Z0-9]{24,}/g, type: "api-key", severity: "critical", category: "Payment" },
  { id: "stripe-restricted", name: "Stripe Restricted Key", pattern: /rk_live_[a-zA-Z0-9]{24,}/g, type: "api-key", severity: "critical", category: "Payment" },
  { id: "stripe-publishable", name: "Stripe Publishable Key", pattern: /pk_live_[a-zA-Z0-9]{24,}/g, type: "api-key", severity: "low", category: "Payment" },
  { id: "stripe-webhook", name: "Stripe Webhook Secret", pattern: /whsec_[a-zA-Z0-9]{32,}/g, type: "api-key", severity: "high", category: "Payment" },
  { id: "paypal-secret", name: "PayPal Client Secret", pattern: /(?:paypal[_-]?(?:client[_-]?)?secret)\s*[:=]\s*["']([A-Za-z0-9_-]{40,})["']/gi, type: "api-key", severity: "critical", category: "Payment" },
  { id: "square-token", name: "Square Access Token", pattern: /sq0atp-[a-zA-Z0-9_-]{22}/g, type: "token", severity: "critical", category: "Payment" },
  { id: "square-secret", name: "Square Application Secret", pattern: /sq0csp-[a-zA-Z0-9_-]{43}/g, type: "api-key", severity: "critical", category: "Payment" },
  { id: "coinbase-key", name: "Coinbase API Key", pattern: /(?:coinbase[_-]?api[_-]?(?:key|secret))\s*[:=]\s*["']([A-Za-z0-9]{16,})["']/gi, type: "api-key", severity: "high", category: "Payment" },
  { id: "plaid-secret", name: "Plaid Secret", pattern: /(?:plaid[_-]?secret)\s*[:=]\s*["']([a-f0-9]{30,})["']/gi, type: "api-key", severity: "critical", category: "Payment" },
];

// ─── Communication ───────────────────────────────────────────────

const communicationPatterns: SecretPattern[] = [
  { id: "slack-bot-token", name: "Slack Bot Token", pattern: /xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}/g, type: "token", severity: "high", category: "Communication" },
  { id: "slack-user-token", name: "Slack User Token", pattern: /xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[a-f0-9]{32}/g, type: "token", severity: "critical", category: "Communication" },
  { id: "slack-app-token", name: "Slack App Token", pattern: /xapp-[0-9]-[A-Z0-9]{10,}-[0-9]{13}-[a-f0-9]{64}/g, type: "token", severity: "high", category: "Communication" },
  { id: "slack-webhook", name: "Slack Webhook URL", pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/g, type: "webhook", severity: "high", category: "Communication" },
  { id: "discord-bot-token", name: "Discord Bot Token", pattern: /(?:discord[_-]?(?:bot[_-]?)?token)\s*[:=]\s*["']([A-Za-z0-9_-]{59,})["']/gi, type: "token", severity: "high", category: "Communication" },
  { id: "discord-webhook", name: "Discord Webhook URL", pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/g, type: "webhook", severity: "medium", category: "Communication" },
  { id: "telegram-bot-token", name: "Telegram Bot Token", pattern: /[0-9]{8,10}:[a-zA-Z0-9_-]{35}/g, type: "token", severity: "high", category: "Communication" },
  { id: "twilio-sid", name: "Twilio Account SID", pattern: /AC[a-f0-9]{32}/g, type: "api-key", severity: "medium", category: "Communication" },
  { id: "twilio-auth-token", name: "Twilio Auth Token", pattern: /(?:twilio[_-]?auth[_-]?token)\s*[:=]\s*["']([a-f0-9]{32})["']/gi, type: "token", severity: "critical", category: "Communication" },
  { id: "sendgrid-key", name: "SendGrid API Key", pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, type: "api-key", severity: "critical", category: "Communication" },
  { id: "mailgun-key", name: "Mailgun API Key", pattern: /key-[a-f0-9]{32}/g, type: "api-key", severity: "high", category: "Communication" },
  { id: "postmark-token", name: "Postmark Server Token", pattern: /(?:postmark[_-]?(?:server[_-]?)?token)\s*[:=]\s*["']([a-f0-9-]{36})["']/gi, type: "token", severity: "high", category: "Communication" },
  { id: "resend-key", name: "Resend API Key", pattern: /re_[a-zA-Z0-9]{30,}/g, type: "api-key", severity: "high", category: "Communication" },
];

// ─── BaaS / Database ─────────────────────────────────────────────

const baasPatterns: SecretPattern[] = [
  { id: "supabase-service-role", name: "Supabase Service Role Key", pattern: /(?:supabase[_-]?service[_-]?role[_-]?key|SUPABASE_SERVICE_ROLE_KEY)\s*[:=]\s*["']?(eyJ[A-Za-z0-9_-]{100,})["']?/gi, type: "api-key", severity: "critical", category: "BaaS" },
  { id: "supabase-anon-key", name: "Supabase Anon Key", pattern: /(?:supabase[_-]?(?:anon[_-]?)?key|NEXT_PUBLIC_SUPABASE_ANON_KEY)\s*[:=]\s*["']?(eyJ[A-Za-z0-9_-]{100,})["']?/gi, type: "api-key", severity: "low", category: "BaaS" },
  { id: "supabase-url", name: "Supabase Project URL", pattern: /https:\/\/[a-z]{20,}\.supabase\.co/g, type: "api-key", severity: "low", category: "BaaS" },
  { id: "firebase-api-key", name: "Firebase API Key", pattern: /(?:firebase[_-]?api[_-]?key|FIREBASE_API_KEY)\s*[:=]\s*["']?(AIza[0-9A-Za-z_-]{35})["']?/gi, type: "api-key", severity: "medium", category: "BaaS" },
  { id: "firebase-admin-sdk", name: "Firebase Admin SDK", pattern: /"type"\s*:\s*"service_account"[\s\S]*?"project_id"\s*:\s*"[^"]+"/g, type: "api-key", severity: "critical", category: "BaaS" },
  { id: "mongodb-connection", name: "MongoDB Connection String", pattern: /mongodb(?:\+srv)?:\/\/[^:\s]+:[^@\s]+@[^\s"']+/g, type: "connection-string", severity: "critical", category: "BaaS" },
  { id: "postgres-connection", name: "PostgreSQL Connection String", pattern: /postgres(?:ql)?:\/\/[^:\s]+:[^@\s]+@[^\s"']+/g, type: "connection-string", severity: "critical", category: "BaaS" },
  { id: "mysql-connection", name: "MySQL Connection String", pattern: /mysql:\/\/[^:\s]+:[^@\s]+@[^\s"']+/g, type: "connection-string", severity: "critical", category: "BaaS" },
  { id: "redis-url", name: "Redis URL", pattern: /redis(?:s)?:\/\/[^:\s]*:[^@\s]+@[^\s"']+/g, type: "connection-string", severity: "critical", category: "BaaS" },
  { id: "neon-connection", name: "Neon Database URL", pattern: /postgres(?:ql)?:\/\/[^:\s]+:[^@\s]+@[^.\s]+\.neon\.tech[^\s"']*/g, type: "connection-string", severity: "critical", category: "BaaS" },
  { id: "planetscale-token", name: "PlanetScale Token", pattern: /pscale_tkn_[a-zA-Z0-9_-]{43}/g, type: "token", severity: "critical", category: "BaaS" },
  { id: "planetscale-password", name: "PlanetScale Password", pattern: /pscale_pw_[a-zA-Z0-9_-]{43}/g, type: "password", severity: "critical", category: "BaaS" },
  { id: "turso-token", name: "Turso Auth Token", pattern: /(?:turso[_-]?(?:auth[_-]?)?token|TURSO_AUTH_TOKEN)\s*[:=]\s*["']([A-Za-z0-9._-]{100,})["']/gi, type: "token", severity: "high", category: "BaaS" },
  { id: "convex-deploy-key", name: "Convex Deploy Key", pattern: /(?:CONVEX_DEPLOY_KEY)\s*[:=]\s*["']([a-z0-9|]+)["']/gi, type: "api-key", severity: "high", category: "BaaS" },
  { id: "upstash-redis-token", name: "Upstash Redis Token", pattern: /(?:UPSTASH_REDIS_REST_TOKEN)\s*[:=]\s*["']([A-Za-z0-9=]+)["']/gi, type: "token", severity: "high", category: "BaaS" },
];

// ─── Auth / Identity ─────────────────────────────────────────────

const authPatterns: SecretPattern[] = [
  { id: "auth0-secret", name: "Auth0 Client Secret", pattern: /(?:auth0[_-]?(?:client[_-]?)?secret)\s*[:=]\s*["']([A-Za-z0-9_-]{32,})["']/gi, type: "api-key", severity: "critical", category: "Auth" },
  { id: "clerk-secret", name: "Clerk Secret Key", pattern: /sk_live_[a-zA-Z0-9]{40,}/g, type: "api-key", severity: "critical", category: "Auth" },
  { id: "clerk-test-secret", name: "Clerk Test Secret Key", pattern: /sk_test_[a-zA-Z0-9]{40,}/g, type: "api-key", severity: "medium", category: "Auth" },
  { id: "supabase-jwt-secret", name: "Supabase JWT Secret", pattern: /(?:JWT_SECRET|SUPABASE_JWT_SECRET)\s*[:=]\s*["']([A-Za-z0-9+/=]{40,})["']/gi, type: "api-key", severity: "critical", category: "Auth" },
  { id: "okta-token", name: "Okta API Token", pattern: /(?:okta[_-]?(?:api[_-]?)?token)\s*[:=]\s*["']([A-Za-z0-9_-]{42})["']/gi, type: "token", severity: "critical", category: "Auth" },
  { id: "nextauth-secret", name: "NextAuth Secret", pattern: /(?:NEXTAUTH_SECRET|AUTH_SECRET)\s*[:=]\s*["']([A-Za-z0-9+/=]{20,})["']/gi, type: "api-key", severity: "high", category: "Auth" },
  { id: "jwt-private-key", name: "JWT Private Key (inline)", pattern: /-----BEGIN (?:RSA )?PRIVATE KEY-----/g, type: "private-key", severity: "critical", category: "Auth" },
  { id: "oauth-client-secret", name: "OAuth Client Secret", pattern: /(?:client[_-]?secret)\s*[:=]\s*["']([A-Za-z0-9_-]{20,})["']/gi, type: "api-key", severity: "high", category: "Auth" },
];

// ─── Monitoring / Logging ────────────────────────────────────────

const monitoringPatterns: SecretPattern[] = [
  { id: "sentry-dsn", name: "Sentry DSN", pattern: /https:\/\/[a-f0-9]{32}@(?:o[0-9]+\.)?(?:[a-z]+\.)?sentry\.io\/[0-9]+/g, type: "api-key", severity: "medium", category: "Monitoring" },
  { id: "datadog-api-key", name: "Datadog API Key", pattern: /(?:datadog[_-]?api[_-]?key|DD_API_KEY)\s*[:=]\s*["']([a-f0-9]{32})["']/gi, type: "api-key", severity: "high", category: "Monitoring" },
  { id: "newrelic-key", name: "New Relic License Key", pattern: /(?:new[_-]?relic[_-]?(?:license[_-]?)?key)\s*[:=]\s*["']([a-f0-9]{40}(?:NRAL)?)["']/gi, type: "api-key", severity: "high", category: "Monitoring" },
  { id: "logtail-token", name: "Logtail/Better Stack Token", pattern: /(?:logtail[_-]?(?:source[_-]?)?token|BETTERSTACK_SOURCE_TOKEN)\s*[:=]\s*["']([A-Za-z0-9]{20,})["']/gi, type: "token", severity: "medium", category: "Monitoring" },
  { id: "bugsnag-key", name: "Bugsnag API Key", pattern: /(?:bugsnag[_-]?api[_-]?key)\s*[:=]\s*["']([a-f0-9]{32})["']/gi, type: "api-key", severity: "medium", category: "Monitoring" },
  { id: "rollbar-token", name: "Rollbar Access Token", pattern: /(?:rollbar[_-]?(?:access[_-]?)?token)\s*[:=]\s*["']([a-f0-9]{32})["']/gi, type: "token", severity: "medium", category: "Monitoring" },
  { id: "posthog-key", name: "PostHog API Key", pattern: /phc_[a-zA-Z0-9]{40,}/g, type: "api-key", severity: "low", category: "Monitoring" },
  { id: "mixpanel-token", name: "Mixpanel Project Token", pattern: /(?:mixpanel[_-]?(?:project[_-]?)?token)\s*[:=]\s*["']([a-f0-9]{32})["']/gi, type: "token", severity: "low", category: "Monitoring" },
];

// ─── SaaS / APIs ─────────────────────────────────────────────────

const saasPatterns: SecretPattern[] = [
  { id: "shopify-access-token", name: "Shopify Access Token", pattern: /shpat_[a-fA-F0-9]{32}/g, type: "token", severity: "critical", category: "SaaS" },
  { id: "shopify-shared-secret", name: "Shopify Shared Secret", pattern: /shpss_[a-fA-F0-9]{32}/g, type: "api-key", severity: "critical", category: "SaaS" },
  { id: "algolia-admin-key", name: "Algolia Admin API Key", pattern: /(?:algolia[_-]?admin[_-]?(?:api[_-]?)?key)\s*[:=]\s*["']([a-f0-9]{32})["']/gi, type: "api-key", severity: "high", category: "SaaS" },
  { id: "algolia-search-key", name: "Algolia Search API Key", pattern: /(?:algolia[_-]?(?:search[_-]?)?(?:api[_-]?)?key|NEXT_PUBLIC_ALGOLIA)\s*[:=]\s*["']([a-f0-9]{32})["']/gi, type: "api-key", severity: "low", category: "SaaS" },
  { id: "mapbox-token", name: "Mapbox Access Token", pattern: /pk\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}/g, type: "token", severity: "medium", category: "SaaS" },
  { id: "mapbox-secret", name: "Mapbox Secret Token", pattern: /sk\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}/g, type: "token", severity: "high", category: "SaaS" },
  { id: "google-maps-key", name: "Google Maps API Key", pattern: /(?:google[_-]?maps[_-]?(?:api[_-]?)?key|NEXT_PUBLIC_GOOGLE_MAPS)\s*[:=]\s*["']?(AIza[0-9A-Za-z_-]{35})["']?/gi, type: "api-key", severity: "medium", category: "SaaS" },
  { id: "notion-token", name: "Notion Integration Token", pattern: /secret_[a-zA-Z0-9]{43}/g, type: "token", severity: "high", category: "SaaS" },
  { id: "linear-api-key", name: "Linear API Key", pattern: /lin_api_[a-zA-Z0-9]{40}/g, type: "api-key", severity: "high", category: "SaaS" },
  { id: "airtable-key", name: "Airtable API Key", pattern: /(?:airtable[_-]?(?:api[_-]?)?key|AIRTABLE_API_KEY)\s*[:=]\s*["'](key[a-zA-Z0-9]{14})["']/gi, type: "api-key", severity: "high", category: "SaaS" },
  { id: "airtable-pat", name: "Airtable PAT", pattern: /pat[a-zA-Z0-9]{14}\.[a-f0-9]{64}/g, type: "token", severity: "high", category: "SaaS" },
  { id: "zendesk-token", name: "Zendesk API Token", pattern: /(?:zendesk[_-]?(?:api[_-]?)?token)\s*[:=]\s*["']([A-Za-z0-9]{40})["']/gi, type: "token", severity: "high", category: "SaaS" },
  { id: "openweather-key", name: "OpenWeatherMap API Key", pattern: /(?:openweather[_-]?(?:map[_-]?)?(?:api[_-]?)?key)\s*[:=]\s*["']([a-f0-9]{32})["']/gi, type: "api-key", severity: "low", category: "SaaS" },
  { id: "rapidapi-key", name: "RapidAPI Key", pattern: /(?:rapidapi[_-]?key|X-RapidAPI-Key)\s*[:=]\s*["']([a-f0-9]{50})["']/gi, type: "api-key", severity: "medium", category: "SaaS" },
];

// ─── Private Keys / Certificates ─────────────────────────────────

const privateKeyPatterns: SecretPattern[] = [
  { id: "rsa-private-key", name: "RSA Private Key", pattern: /-----BEGIN RSA PRIVATE KEY-----/g, type: "private-key", severity: "critical", category: "Private Keys" },
  { id: "ssh-private-key", name: "SSH Private Key", pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g, type: "private-key", severity: "critical", category: "Private Keys" },
  { id: "ec-private-key", name: "EC Private Key", pattern: /-----BEGIN EC PRIVATE KEY-----/g, type: "private-key", severity: "critical", category: "Private Keys" },
  { id: "pkcs8-private-key", name: "PKCS8 Private Key", pattern: /-----BEGIN PRIVATE KEY-----/g, type: "private-key", severity: "critical", category: "Private Keys" },
  { id: "pgp-private-key", name: "PGP Private Key", pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g, type: "private-key", severity: "critical", category: "Private Keys" },
  { id: "x509-certificate", name: "X.509 Certificate (with key)", pattern: /-----BEGIN CERTIFICATE-----[\s\S]*-----BEGIN (?:RSA )?PRIVATE KEY-----/g, type: "private-key", severity: "critical", category: "Private Keys" },
];

// ─── Generic / Heuristic ─────────────────────────────────────────

const genericPatterns: SecretPattern[] = [
  { id: "generic-api-key", name: "Generic API Key", pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*["']([^"']{20,})["']/gi, type: "api-key", severity: "medium", category: "Generic" },
  { id: "generic-secret", name: "Generic Secret", pattern: /(?:secret|secret[_-]?key)\s*[:=]\s*["']([^"']{20,})["']/gi, type: "api-key", severity: "medium", category: "Generic" },
  { id: "generic-token", name: "Generic Token", pattern: /(?:access[_-]?token|auth[_-]?token)\s*[:=]\s*["']([^"']{20,})["']/gi, type: "token", severity: "medium", category: "Generic" },
  { id: "generic-password", name: "Generic Password", pattern: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{8,})["']/gi, type: "password", severity: "high", category: "Generic" },
  { id: "basic-auth-url", name: "Basic Auth in URL", pattern: /https?:\/\/[^:\s]+:[^@\s]+@[^\s"']+/g, type: "password", severity: "high", category: "Generic" },
  { id: "bearer-token-hardcoded", name: "Hardcoded Bearer Token", pattern: /["']Bearer\s+[A-Za-z0-9_-]{20,}["']/g, type: "token", severity: "high", category: "Generic" },
  { id: "authorization-header", name: "Hardcoded Authorization", pattern: /[Aa]uthorization["']?\s*[:=]\s*["'](?:Basic|Bearer)\s+[A-Za-z0-9+/=_-]{20,}["']/g, type: "token", severity: "high", category: "Generic" },
];

// ─── All Patterns Combined ───────────────────────────────────────

export const SECRET_PATTERNS: SecretPattern[] = [
  ...cloudPatterns,
  ...aiPatterns,
  ...ciPatterns,
  ...paymentPatterns,
  ...communicationPatterns,
  ...baasPatterns,
  ...authPatterns,
  ...monitoringPatterns,
  ...saasPatterns,
  ...privateKeyPatterns,
  ...genericPatterns,
];

/** Get unique categories from all patterns */
export function getPatternCategories(): string[] {
  return [...new Set(SECRET_PATTERNS.map((p) => p.category))];
}

/** Get pattern count by category */
export function getPatternStats(): Record<string, number> {
  const stats: Record<string, number> = {};
  for (const p of SECRET_PATTERNS) {
    stats[p.category] = (stats[p.category] ?? 0) + 1;
  }
  return stats;
}
