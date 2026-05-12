require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const multer     = require('multer');
const fs         = require('fs');
const path       = require('path');
const crypto     = require('crypto');
const XLSX       = require('xlsx');
const { google } = require('googleapis');
const { createClient } = require('@supabase/supabase-js');
const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcrypt');
const rateLimit  = require('express-rate-limit');

const app  = express();
const PORT = process.env.PORT || 3001;

// ── Supabase ──────────────────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '10mb' }));

app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, max: 500, standardHeaders: true, legacyHeaders: false }));

// Serve index.html for all non-API routes
app.use(express.static(__dirname));

// ── File upload ───────────────────────────────────────────────────────────────
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads', { recursive: true });

const upload = multer({
  dest: 'uploads/',
  fileFilter: (req, file, cb) => {
    if (/\.(xlsx|xls|csv)$/i.test(file.originalname)) cb(null, true);
    else cb(new Error('Only Excel (.xlsx, .xls) or CSV files are allowed'));
  },
  limits: { fileSize: 20 * 1024 * 1024 },
});

// ── Encryption ────────────────────────────────────────────────────────────────
const _ENC_KEY = crypto.createHash('sha256')
  .update(process.env.ENCRYPTION_KEY || process.env.JWT_SECRET || 'marketing-dev-key')
  .digest();

function encrypt(plaintext) {
  const iv     = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', _ENC_KEY, iv);
  const enc    = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag    = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64');
}

function decrypt(ciphertext) {
  const buf     = Buffer.from(ciphertext, 'base64');
  const iv      = buf.subarray(0, 12);
  const tag     = buf.subarray(12, 28);
  const enc     = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', _ENC_KEY, iv);
  decipher.setAuthTag(tag);
  return decipher.update(enc).toString('utf8') + decipher.final('utf8');
}

// ── Auth ──────────────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

function authenticate(req, res, next) {
  const auth  = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const adminEmail    = process.env.ADMIN_EMAIL    || 'admin@example.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'changeme';

    if (email.toLowerCase() !== adminEmail.toLowerCase())
      return res.status(401).json({ error: 'Invalid credentials' });

    const valid = adminPassword.startsWith('$2b$')
      ? await bcrypt.compare(password, adminPassword)
      : password === adminPassword;

    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, email });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Settings helpers ──────────────────────────────────────────────────────────
const appUrl = () => process.env.APP_URL || `http://localhost:${PORT}`;
const gmailRedirectUri = () => `${appUrl()}/api/gmail/callback`;

async function getSettings() {
  const { data } = await supabase.from('settings').select('*').limit(1).single();
  return data || {};
}

async function upsertSettings(update) {
  const existing = await getSettings();
  update.updated_at = new Date().toISOString();
  if (existing.id) {
    await supabase.from('settings').update(update).eq('id', existing.id);
  } else {
    await supabase.from('settings').insert(update);
  }
}

// ── Settings endpoints ────────────────────────────────────────────────────────

app.get('/api/settings', authenticate, async (req, res) => {
  try {
    const s = await getSettings();
    res.json({
      apollo_connected: !!s.apollo_key_enc,
      gmail_connected:  !!s.gmail_connected,
      gmail_email:      s.gmail_email || null,
      from_name:        s.from_name   || '',
      app_url:          s.app_url     || appUrl(),
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/settings', authenticate, async (req, res) => {
  try {
    const { apollo_key, from_name, app_url } = req.body;
    const update = {};
    if (apollo_key)           update.apollo_key_enc = encrypt(apollo_key);
    if (from_name  !== undefined) update.from_name  = from_name;
    if (app_url    !== undefined) update.app_url     = app_url;
    await upsertSettings(update);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Gmail OAuth ───────────────────────────────────────────────────────────────

function makeOAuth2Client() {
  return new google.auth.OAuth2(
    process.env.GMAIL_CLIENT_ID,
    process.env.GMAIL_CLIENT_SECRET,
    gmailRedirectUri()
  );
}

// GET /api/gmail/auth — redirect user to Google consent screen
// The frontend navigates to this URL directly (not via fetch)
app.get('/api/gmail/auth', (req, res) => {
  const oauth2 = makeOAuth2Client();
  const url = oauth2.generateAuthUrl({
    access_type: 'offline',
    scope: [
      'https://www.googleapis.com/auth/gmail.send',
      'https://www.googleapis.com/auth/gmail.readonly',
    ],
    prompt: 'consent',
  });
  res.redirect(url);
});

// GET /api/gmail/callback — Google redirects here after consent
app.get('/api/gmail/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.redirect(`/?toast=gmail_error&msg=${encodeURIComponent(error)}`);

  try {
    const oauth2 = makeOAuth2Client();
    const { tokens } = await oauth2.getToken(code);
    if (!tokens.refresh_token)
      return res.redirect('/?toast=gmail_no_refresh&msg=No+refresh+token+returned.+Try+revoking+access+at+myaccount.google.com+then+reconnecting.');

    oauth2.setCredentials(tokens);
    const gmail   = google.gmail({ version: 'v1', auth: oauth2 });
    const profile = await gmail.users.getProfile({ userId: 'me' });

    await upsertSettings({
      gmail_refresh_enc: encrypt(tokens.refresh_token),
      gmail_connected:   true,
      gmail_email:       profile.data.emailAddress,
    });

    res.redirect(`/?toast=gmail_connected&email=${encodeURIComponent(profile.data.emailAddress)}`);
  } catch (err) {
    console.error('Gmail OAuth callback error:', err.message);
    res.redirect(`/?toast=gmail_error&msg=${encodeURIComponent(err.message)}`);
  }
});

app.post('/api/gmail/disconnect', authenticate, async (req, res) => {
  try {
    await upsertSettings({ gmail_refresh_enc: null, gmail_connected: false, gmail_email: null });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Apollo enrichment ─────────────────────────────────────────────────────────

const ICP_TITLES = [
  'CFO', 'Chief Financial Officer', 'Finance Director', 'VP Finance', 'VP of Finance',
  'Head of Finance', 'Financial Controller', 'Head of Treasury', 'Treasury Manager',
  'Finance Manager', 'Group Finance Director', 'VP Accounting', 'Director of Finance',
  'Group Treasurer', 'Assistant CFO',
];

async function apolloSearch(apiKey, companyName, companyDomain) {
  const body = {
    api_key:         apiKey,
    q_organization_name: companyName,
    person_titles:   ICP_TITLES,
    page:            1,
    per_page:        3,
  };
  if (companyDomain) {
    body.q_organization_domains = [companyDomain.replace(/^https?:\/\/(www\.)?/, '').replace(/\/$/, '')];
  }

  const resp = await fetch('https://api.apollo.io/api/v1/people/search', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' },
    body:    JSON.stringify(body),
    signal:  AbortSignal.timeout(15000),
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Apollo ${resp.status}: ${text.slice(0, 200)}`);
  }

  const data = await resp.json();
  return (data.people || []).filter(p => p.email);
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ── Lists ─────────────────────────────────────────────────────────────────────

function parseExcelOrCsv(filePath, originalName) {
  const workbook = XLSX.readFile(filePath);
  const sheet    = workbook.Sheets[workbook.SheetNames[0]];
  const rows     = XLSX.utils.sheet_to_json(sheet, { defval: '' });

  return rows.map(row => {
    const get = (...names) => {
      for (const n of names) {
        const key = Object.keys(row).find(k => k.toLowerCase().trim() === n.toLowerCase());
        if (key && String(row[key]).trim()) return String(row[key]).trim();
      }
      return '';
    };
    return {
      company_name:   get('company', 'company name', 'business', 'business name', 'organisation', 'organization', 'name'),
      company_domain: get('domain', 'website', 'url', 'web', 'company domain', 'company url'),
    };
  }).filter(r => r.company_name);
}

app.post('/api/lists/upload', authenticate, upload.single('file'), async (req, res) => {
  const file = req.file;
  try {
    const listName = (req.body.list_name || '').trim() ||
      path.basename(file.originalname, path.extname(file.originalname));

    const companies = parseExcelOrCsv(file.path, file.originalname);
    fs.unlinkSync(file.path);

    if (!companies.length)
      return res.status(400).json({ error: 'No companies found. Make sure the file has a "Company" or "Company Name" column.' });

    const { data: list, error } = await supabase.from('lists').insert({
      name:      listName,
      filename:  file.originalname,
      row_count: companies.length,
      status:    'pending',
    }).select().single();

    if (error) throw new Error(error.message);

    await supabase.from('contacts').insert(
      companies.map(c => ({
        list_id:        list.id,
        company_name:   c.company_name,
        company_domain: c.company_domain || null,
        enriched:       false,
      }))
    );

    res.json({ success: true, list_id: list.id, companies: companies.length });
  } catch (err) {
    if (file?.path && fs.existsSync(file.path)) fs.unlinkSync(file.path);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/lists', authenticate, async (req, res) => {
  try {
    const { data } = await supabase.from('lists').select('*').order('created_at', { ascending: false });
    res.json(data || []);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/lists/:id', authenticate, async (req, res) => {
  try {
    await supabase.from('lists').delete().eq('id', req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/lists/:id/contacts', authenticate, async (req, res) => {
  try {
    const { data } = await supabase.from('contacts')
      .select('*')
      .eq('list_id', req.params.id)
      .order('company_name');
    res.json(data || []);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/lists/:id/enrich — Apollo pass for every unenriched company stub
app.post('/api/lists/:id/enrich', authenticate, async (req, res) => {
  try {
    const s      = await getSettings();
    const apiKey = s.apollo_key_enc ? decrypt(s.apollo_key_enc) : null;
    if (!apiKey) return res.status(400).json({ error: 'Apollo API key not configured — go to Settings.' });

    const { data: stubs } = await supabase.from('contacts')
      .select('*')
      .eq('list_id', req.params.id)
      .eq('enriched', false)
      .is('email', null);

    if (!stubs?.length)
      return res.json({ success: true, found: 0, message: 'All companies are already enriched.' });

    await supabase.from('lists').update({ status: 'enriching' }).eq('id', req.params.id);
    res.json({ success: true, total: stubs.length, message: `Enriching ${stubs.length} companies in background…` });

    // Run async — respond first so the client isn't waiting
    (async () => {
      let found = 0;
      for (const stub of stubs) {
        try {
          const people = await apolloSearch(apiKey, stub.company_name, stub.company_domain);
          await supabase.from('contacts').delete().eq('id', stub.id);

          if (people.length) {
            await supabase.from('contacts').insert(people.map(p => ({
              list_id:        stub.list_id,
              company_name:   p.organization?.name || stub.company_name,
              company_domain: stub.company_domain  || null,
              first_name:     p.first_name  || '',
              last_name:      p.last_name   || '',
              email:          p.email,
              title:          p.title       || '',
              linkedin_url:   p.linkedin_url || null,
              enriched:       true,
            })));
            found += people.length;
          } else {
            // No contacts found — insert a placeholder so we don't retry
            await supabase.from('contacts').insert({
              list_id:      stub.list_id,
              company_name: stub.company_name,
              company_domain: stub.company_domain || null,
              enriched:     true,
            });
          }
        } catch (err) {
          console.error(`Apollo error for "${stub.company_name}":`, err.message);
        }

        await sleep(1200); // ~50 req/min — safe for free and paid Apollo tiers
      }

      const { data: allContacts } = await supabase.from('contacts')
        .select('id, email')
        .eq('list_id', req.params.id);

      await supabase.from('lists').update({
        status:         'ready',
        enriched_count: (allContacts || []).filter(c => c.email).length,
      }).eq('id', req.params.id);

      console.log(`Enrichment done for list ${req.params.id}: ${found} contacts found`);
    })();

  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Campaigns ─────────────────────────────────────────────────────────────────

app.get('/api/campaigns', authenticate, async (req, res) => {
  try {
    const { data } = await supabase.from('campaigns').select('*').order('created_at', { ascending: false });
    res.json(data || []);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/campaigns', authenticate, async (req, res) => {
  try {
    const { name, subject, body_html, from_name } = req.body;
    if (!name || !subject || !body_html)
      return res.status(400).json({ error: 'name, subject, and body_html are required' });
    const { data, error } = await supabase.from('campaigns')
      .insert({ name, subject, body_html, from_name: from_name || null })
      .select().single();
    if (error) throw new Error(error.message);
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/campaigns/:id', authenticate, async (req, res) => {
  try {
    const { name, subject, body_html, from_name } = req.body;
    await supabase.from('campaigns')
      .update({ name, subject, body_html, from_name })
      .eq('id', req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/campaigns/:id', authenticate, async (req, res) => {
  try {
    await supabase.from('campaigns').delete().eq('id', req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/campaigns/:id/stats', authenticate, async (req, res) => {
  try {
    const { data: sends } = await supabase.from('sends')
      .select('status, sent_at, opened_at, clicked_at')
      .eq('campaign_id', req.params.id);

    const total   = sends?.length   || 0;
    const sent    = sends?.filter(s => s.sent_at).length    || 0;
    const opened  = sends?.filter(s => s.opened_at).length  || 0;
    const clicked = sends?.filter(s => s.clicked_at).length || 0;
    const failed  = sends?.filter(s => s.status === 'failed').length || 0;

    res.json({
      total, sent, opened, clicked, failed,
      open_rate:  sent > 0 ? Math.round(opened  / sent * 100) : 0,
      click_rate: sent > 0 ? Math.round(clicked / sent * 100) : 0,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/campaigns/:id/send — queue sends to a list
app.post('/api/campaigns/:id/send', authenticate, async (req, res) => {
  try {
    const { list_id } = req.body;
    if (!list_id) return res.status(400).json({ error: 'list_id required' });

    const s       = await getSettings();
    const refresh = s.gmail_refresh_enc ? decrypt(s.gmail_refresh_enc) : null;
    if (!refresh) return res.status(400).json({ error: 'Gmail not connected — go to Settings.' });

    const { data: campaign } = await supabase.from('campaigns').select('*').eq('id', req.params.id).single();
    if (!campaign) return res.status(404).json({ error: 'Campaign not found' });

    // Only contacts with emails, not opted out
    const { data: contacts } = await supabase.from('contacts')
      .select('*')
      .eq('list_id', list_id)
      .eq('opted_out', false)
      .not('email', 'is', null);

    if (!contacts?.length) return res.status(400).json({ error: 'No contacts with emails in this list.' });

    // Exclude contacts already sent to in this campaign
    const { data: alreadySent } = await supabase.from('sends')
      .select('contact_id')
      .eq('campaign_id', req.params.id);
    const sentIds  = new Set((alreadySent || []).map(r => r.contact_id));
    const toSend   = contacts.filter(c => !sentIds.has(c.id));

    if (!toSend.length) return res.status(400).json({ error: 'All contacts in this list have already been sent to for this campaign.' });

    // Create pending records
    const { data: sendRecords } = await supabase.from('sends')
      .insert(toSend.map(c => ({ campaign_id: req.params.id, contact_id: c.id, status: 'pending' })))
      .select();

    await supabase.from('campaigns').update({ status: 'sending' }).eq('id', req.params.id);
    res.json({ success: true, queued: toSend.length });

    // Background send loop
    (async () => {
      const oauth2 = makeOAuth2Client();
      oauth2.setCredentials({ refresh_token: refresh });
      const gmail    = google.gmail({ version: 'v1', auth: oauth2 });
      const fromName = campaign.from_name || s.from_name || 'Marketing Team';
      const baseUrl  = s.app_url || appUrl();

      let sentCount = 0;
      for (const record of sendRecords) {
        const contact = toSend.find(c => c.id === record.contact_id);
        if (!contact) continue;

        try {
          const subject  = fillTemplate(campaign.subject,   contact);
          const bodyHtml = fillTemplate(campaign.body_html, contact);

          const fullHtml = bodyHtml + `
<div style="margin-top:40px;padding-top:16px;border-top:1px solid #e5e7eb;font-size:11px;color:#9ca3af">
  You are receiving this email because your company matches our outreach criteria.<br>
  <a href="${baseUrl}/api/track/unsubscribe/${contact.id}" style="color:#9ca3af">Unsubscribe</a>
</div>
<img src="${baseUrl}/api/track/open/${record.id}" width="1" height="1" alt="" style="display:none"/>`;

          const raw = buildRawEmail({
            from:            `${fromName} <${s.gmail_email}>`,
            to:              contact.email,
            subject,
            html:            fullHtml,
            listUnsubscribe: `<${baseUrl}/api/track/unsubscribe/${contact.id}>`,
          });

          const result = await gmail.users.messages.send({ userId: 'me', requestBody: { raw } });

          await supabase.from('sends').update({
            status:         'sent',
            sent_at:        new Date().toISOString(),
            gmail_thread_id: result.data.threadId || null,
          }).eq('id', record.id);

          sentCount++;
        } catch (err) {
          console.error(`Send failed to ${contact.email}:`, err.message);
          await supabase.from('sends').update({
            status:    'failed',
            error_msg: err.message.slice(0, 500),
          }).eq('id', record.id);
        }

        await sleep(1500); // ~40 emails/min — well under Gmail's 500/day limit
      }

      await supabase.from('campaigns').update({
        status:     'sent',
        sent_count: sentCount,
      }).eq('id', req.params.id);

      console.log(`Campaign "${campaign.name}" complete: ${sentCount}/${sendRecords.length} sent`);
    })();

  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Template helpers ──────────────────────────────────────────────────────────

function fillTemplate(template, contact) {
  return template
    .replace(/\{\{first_name\}\}/gi, contact.first_name || 'there')
    .replace(/\{\{last_name\}\}/gi,  contact.last_name  || '')
    .replace(/\{\{full_name\}\}/gi,  [contact.first_name, contact.last_name].filter(Boolean).join(' ') || 'there')
    .replace(/\{\{company\}\}/gi,    contact.company_name || 'your company')
    .replace(/\{\{title\}\}/gi,      contact.title || '');
}

function buildRawEmail({ from, to, subject, html, listUnsubscribe }) {
  const lines = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    `MIME-Version: 1.0`,
    `Content-Type: text/html; charset=utf-8`,
  ];
  if (listUnsubscribe) {
    lines.push(`List-Unsubscribe: ${listUnsubscribe}`);
    lines.push(`List-Unsubscribe-Post: List-Unsubscribe=One-Click`);
  }
  lines.push('', html);
  return Buffer.from(lines.join('\r\n')).toString('base64url');
}

// ── Tracking (no auth — called by email clients) ──────────────────────────────

// 1×1 transparent GIF
const PIXEL = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');

app.get('/api/track/open/:sendId', async (req, res) => {
  try {
    const { data: s } = await supabase.from('sends').select('opened_at').eq('id', req.params.sendId).single();
    if (s && !s.opened_at) {
      await supabase.from('sends').update({ opened_at: new Date().toISOString(), status: 'opened' }).eq('id', req.params.sendId);
    }
  } catch { /* non-fatal */ }
  res.setHeader('Content-Type', 'image/gif');
  res.setHeader('Cache-Control', 'no-store, no-cache');
  res.send(PIXEL);
});

app.get('/api/track/click/:sendId', async (req, res) => {
  const { url } = req.query;
  try {
    const { data: s } = await supabase.from('sends').select('clicked_at').eq('id', req.params.sendId).single();
    if (s && !s.clicked_at) {
      await supabase.from('sends').update({ clicked_at: new Date().toISOString(), status: 'clicked' }).eq('id', req.params.sendId);
    }
  } catch { /* non-fatal */ }
  const dest = url && (url.startsWith('http://') || url.startsWith('https://')) ? url : '/';
  res.redirect(dest);
});

app.get('/api/track/unsubscribe/:contactId', async (req, res) => {
  try {
    await supabase.from('contacts').update({ opted_out: true }).eq('id', req.params.contactId);
  } catch { /* non-fatal */ }
  res.setHeader('Content-Type', 'text/html');
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Unsubscribed</title></head>
<body style="font-family:system-ui,sans-serif;text-align:center;padding:80px 20px;background:#f9fafb">
  <div style="max-width:400px;margin:0 auto">
    <div style="font-size:40px;margin-bottom:16px">✅</div>
    <h2 style="color:#111;margin-bottom:8px">You've been unsubscribed</h2>
    <p style="color:#6b7280">You'll no longer receive emails from us.</p>
  </div>
</body></html>`);
});

// ── Stats summary ─────────────────────────────────────────────────────────────

app.get('/api/stats', authenticate, async (req, res) => {
  try {
    const [lists, contacts, campaigns, sends] = await Promise.all([
      supabase.from('lists').select('id', { count: 'exact', head: true }),
      supabase.from('contacts').select('id, email, opted_out', { count: 'exact' }),
      supabase.from('campaigns').select('id', { count: 'exact', head: true }),
      supabase.from('sends').select('status, opened_at'),
    ]);

    const allContacts  = contacts.data || [];
    const allSends     = sends.data    || [];
    const totalSent    = allSends.filter(s => s.status !== 'pending' && s.status !== 'failed').length;
    const totalOpened  = allSends.filter(s => s.opened_at).length;

    res.json({
      total_lists:     lists.count        || 0,
      total_contacts:  allContacts.filter(c => c.email).length,
      opted_out:       allContacts.filter(c => c.opted_out).length,
      total_campaigns: campaigns.count    || 0,
      total_sent:      totalSent,
      total_opened:    totalOpened,
      open_rate:       totalSent > 0 ? Math.round(totalOpened / totalSent * 100) : 0,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Serve frontend ────────────────────────────────────────────────────────────

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`✅ Marketing Agent running → http://localhost:${PORT}`);
  if (!process.env.GMAIL_CLIENT_ID) console.warn('⚠️  GMAIL_CLIENT_ID not set — Gmail sending will not work');
  if (!process.env.SUPABASE_URL)    console.warn('⚠️  SUPABASE_URL not set');
});
