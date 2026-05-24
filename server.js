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
const cron       = require('node-cron');

const app  = express();
const PORT = process.env.PORT || 3001;

// ── Startup validation ────────────────────────────────────────────────────────
const REQUIRED_VARS = ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'JWT_SECRET', 'ENCRYPTION_KEY'];
const _missing = REQUIRED_VARS.filter(v => !process.env[v]);
if (_missing.length) {
  console.error(`FATAL: Missing required environment variables: ${_missing.join(', ')}`);
  process.exit(1);
}

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

// ── File upload ───────────────────────────────────────────────────────────────
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const upload = multer({
  dest: UPLOADS_DIR,
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
  const { data, error } = await supabase.from('settings').select('*').limit(1).single();
  // PGRST116 = "no rows returned" — expected on fresh install, not an error
  if (error && error.code !== 'PGRST116') throw new Error('Settings read failed: ' + error.message);
  return data || {};
}

async function upsertSettings(update) {
  const existing = await getSettings();
  update.updated_at = new Date().toISOString();
  if (existing.id) {
    const { error } = await supabase.from('settings').update(update).eq('id', existing.id);
    if (error) throw new Error('Settings update failed: ' + error.message);
  } else {
    const { error } = await supabase.from('settings').insert(update);
    if (error) throw new Error('Settings insert failed: ' + error.message);
  }
}

// ── Settings endpoints ────────────────────────────────────────────────────────

app.get('/api/settings', authenticate, async (req, res) => {
  try {
    const s = await getSettings();
    res.json({
      apollo_connected:        !!s.apollo_key_enc,
      gmail_connected:         !!s.gmail_connected,
      gmail_email:             s.gmail_email || null,
      from_name:               s.from_name   || '',
      app_url:                 s.app_url     || appUrl(),
      scheduled_campaign_id:   s.scheduled_campaign_id  || null,
      scheduled_list_id:       s.scheduled_list_id      || null,
      scheduled_send_enabled:  s.scheduled_send_enabled || false,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/settings', authenticate, async (req, res) => {
  try {
    const { apollo_key, from_name, app_url, scheduled_campaign_id, scheduled_list_id, scheduled_send_enabled } = req.body;
    const update = {};
    if (apollo_key)                        update.apollo_key_enc          = encrypt(apollo_key);
    if (from_name  !== undefined)          update.from_name               = from_name;
    if (app_url    !== undefined)          update.app_url                 = app_url;
    if (scheduled_campaign_id !== undefined) update.scheduled_campaign_id = scheduled_campaign_id;
    if (scheduled_list_id     !== undefined) update.scheduled_list_id     = scheduled_list_id;
    if (scheduled_send_enabled !== undefined) update.scheduled_send_enabled = scheduled_send_enabled;
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
  'COO', 'Chief Operating Officer', 'Head of Operations', 'VP Operations',
  'VP of Operations', 'Director of Operations', 'Operations Director',
];

async function apolloSearchByName(apiKey, companyName, withTitles) {
  const body = { q_organization_name: companyName, page: 1, per_page: 1 };
  if (withTitles) body.person_titles = ICP_TITLES;

  const resp = await fetch('https://api.apollo.io/api/v1/mixed_people/api_search', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache', 'X-Api-Key': apiKey },
    body:    JSON.stringify(body),
    signal:  AbortSignal.timeout(15000),
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Apollo ${resp.status}: ${text.slice(0, 200)}`);
  }

  const data = await resp.json();
  return (data.people || []).filter(p => p.has_email);
}

async function apolloReveal(apiKey, candidates) {
  const resp = await fetch('https://api.apollo.io/api/v1/people/bulk_match', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache', 'X-Api-Key': apiKey },
    body:    JSON.stringify({ reveal_personal_emails: true, details: candidates.map(p => ({ id: p.id })) }),
    signal:  AbortSignal.timeout(15000),
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Apollo reveal ${resp.status}: ${text.slice(0, 200)}`);
  }

  const data = await resp.json();
  return (data.matches || []).filter(p => p.email);
}

async function apolloSearch(apiKey, companyName) {
  // Try ICP title filter first, fall back to any contact with email
  let candidates = await apolloSearchByName(apiKey, companyName, true);
  if (!candidates.length) candidates = await apolloSearchByName(apiKey, companyName, false);

  console.log('[Apollo debug]', companyName, '→ candidates:', candidates.length);
  if (!candidates.length) return [];

  return apolloReveal(apiKey, candidates);
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
      psps:           get('psps at checkout', 'psps', 'payment processors', 'processors', 'psp'),
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

    const { error: contactsError } = await supabase.from('contacts').insert(
      companies.map(c => ({
        list_id:        list.id,
        company_name:   c.company_name,
        company_domain: c.company_domain || null,
        psps:           c.psps || null,
        enriched:       false,
      }))
    );
    if (contactsError) throw new Error('Failed to insert contacts: ' + contactsError.message);

    res.json({ success: true, list_id: list.id, companies: companies.length });
  } catch (err) {
    if (file?.path && fs.existsSync(file.path)) fs.unlinkSync(file.path);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/lists/:id/export', authenticate, async (req, res) => {
  try {
    const { data: list } = await supabase.from('lists').select('name').eq('id', req.params.id).single();
    const { data: contacts } = await supabase.from('contacts')
      .select('company_name, company_domain, psps, first_name, last_name, email, title, linkedin_url')
      .eq('list_id', req.params.id)
      .not('email', 'is', null)
      .order('company_name');

    if (!contacts?.length) return res.status(404).json({ error: 'No enriched contacts found' });

    const headers = ['Company', 'Domain', 'PSPs', 'First Name', 'Last Name', 'Email', 'Title', 'LinkedIn'];
    const rows = contacts.map(c => [
      c.company_name, c.company_domain, c.psps, c.first_name, c.last_name, c.email, c.title, c.linkedin_url
    ].map(v => `"${(v || '').replace(/"/g, '""')}"`).join(','));

    const csv = [headers.join(','), ...rows].join('\r\n');
    const filename = (list?.name || 'contacts').replace(/[^a-z0-9]/gi, '_') + '_enriched.csv';

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csv);
  } catch (err) { res.status(500).json({ error: err.message }); }
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
    const { data: listCheck } = await supabase.from('lists').select('status').eq('id', req.params.id).single();
    if (listCheck?.status === 'enriching')
      return res.status(400).json({ error: 'Enrichment already in progress for this list.' });

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
          const people = await apolloSearch(apiKey, stub.company_name);
          await supabase.from('contacts').delete().eq('id', stub.id);

          if (people.length) {
            await supabase.from('contacts').insert(people.map(p => ({
              list_id:        stub.list_id,
              company_name:   p.organization?.name || stub.company_name,
              company_domain: stub.company_domain  || null,
              psps:           stub.psps            || null,
              first_name:     p.first_name  || '',
              last_name:      p.last_name   || '',
              email:          p.email,
              title:          p.title       || '',
              linkedin_url:   p.linkedin_url || null,
              enriched:       true,
            })));
            found += people.length;
          } else {
            await supabase.from('contacts').insert({
              list_id:        stub.list_id,
              company_name:   stub.company_name,
              company_domain: stub.company_domain || null,
              enriched:       true,
            });
          }
        } catch (err) {
          console.error(`Apollo error for "${stub.company_name}":`, err.message);
        }

        await sleep(1200);
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
    const { error } = await supabase.from('campaigns')
      .update({ name, subject, body_html, from_name })
      .eq('id', req.params.id);
    if (error) throw new Error(error.message);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/campaigns/:id', authenticate, async (req, res) => {
  try {
    const { error } = await supabase.from('campaigns').delete().eq('id', req.params.id);
    if (error) throw new Error(error.message);
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
    const toSend   = contacts.filter(c => !sentIds.has(c.id)).slice(0, 40);

    if (!toSend.length) return res.status(400).json({ error: 'All contacts in this list have already been sent to for this campaign.' });

    // Create pending records
    const { data: sendRecords, error: srError } = await supabase.from('sends')
      .insert(toSend.map(c => ({ campaign_id: req.params.id, contact_id: c.id, status: 'pending' })))
      .select();
    if (srError) throw new Error('Failed to queue sends: ' + srError.message);
    if (!sendRecords?.length) throw new Error('No send records were created');

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
          const bodyHtml = fillTemplate(campaign.body_html, contact, true);

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
        status:     sentCount === 0 ? 'failed' : 'sent',
        sent_count: sentCount,
      }).eq('id', req.params.id);

      console.log(`Campaign "${campaign.name}" complete: ${sentCount}/${sendRecords.length} sent`);
    })();

  } catch (err) { res.status(500).json({ error: err.message }); }
});

// POST /api/campaigns/:id/test — send a preview to a given email using the first real contact
app.post('/api/campaigns/:id/test', authenticate, async (req, res) => {
  try {
    const { to_email, list_id } = req.body;
    if (!to_email) return res.status(400).json({ error: 'to_email required' });

    const s       = await getSettings();
    const refresh = s.gmail_refresh_enc ? decrypt(s.gmail_refresh_enc) : null;
    if (!refresh) return res.status(400).json({ error: 'Gmail not connected.' });

    const { data: campaign } = await supabase.from('campaigns').select('*').eq('id', req.params.id).single();
    if (!campaign) return res.status(404).json({ error: 'Campaign not found' });

    // Use first real contact for variable substitution, or dummy if no list given
    let contact = { first_name: 'Jane', last_name: 'Smith', company_name: 'Acme Ltd', title: 'CFO', psps: 'Stripe, Klarna, PayPal' };
    if (list_id) {
      const { data: contacts } = await supabase.from('contacts').select('*').eq('list_id', list_id).not('email', 'is', null).limit(1);
      if (contacts?.length) contact = contacts[0];
    }

    const fromName = campaign.from_name || s.from_name || 'Marketing Team';
    const baseUrl  = s.app_url || appUrl();
    const subject  = fillTemplate(campaign.subject,   contact);
    const bodyHtml = fillTemplate(campaign.body_html, contact, true);

    const fullHtml = bodyHtml + `
<div style="margin-top:40px;padding-top:16px;border-top:1px solid #e5e7eb;font-size:11px;color:#9ca3af">
  [TEST EMAIL] — This is a preview. Variables filled from: ${contact.company_name}<br>
  <a href="${baseUrl}/api/track/unsubscribe/${contact.id || 'test'}" style="color:#9ca3af">Unsubscribe</a>
</div>`;

    const oauth2 = makeOAuth2Client();
    oauth2.setCredentials({ refresh_token: refresh });
    const gmail = google.gmail({ version: 'v1', auth: oauth2 });

    const raw = buildRawEmail({ from: `${fromName} <${s.gmail_email}>`, to: to_email, subject: `[TEST] ${subject}`, html: fullHtml });
    await gmail.users.messages.send({ userId: 'me', requestBody: { raw } });

    res.json({ success: true, message: `Test sent to ${to_email} using data from ${contact.company_name}` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Template helpers ──────────────────────────────────────────────────────────

function fillTemplate(template, contact, toHtml = false) {
  let out = template
    .replace(/\{\{first_name\}\}/gi, contact.first_name || 'there')
    .replace(/\{\{last_name\}\}/gi,  contact.last_name  || '')
    .replace(/\{\{full_name\}\}/gi,  [contact.first_name, contact.last_name].filter(Boolean).join(' ') || 'there')
    .replace(/\{\{company\}\}/gi,    contact.company_name || 'your company')
    .replace(/\{\{title\}\}/gi,      contact.title || '')
    .replace(/\{\{psps\}\}/gi,       contact.psps || 'your payment processors');
  if (toHtml) out = out.replace(/\r\n|\r|\n/g, '<br>');
  return out;
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
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ── Start ─────────────────────────────────────────────────────────────────────

// ── Scheduled daily send — 9am Irish time ────────────────────────────────────

async function runScheduledSend() {
  console.log('[Scheduled] Running daily send at 9am Irish time…');
  try {
    const s = await getSettings();
    if (!s.scheduled_send_enabled)      return console.log('[Scheduled] Disabled — skipping');
    if (!s.scheduled_campaign_id)       return console.log('[Scheduled] No campaign configured');
    if (!s.scheduled_list_id)           return console.log('[Scheduled] No list configured');
    const refresh = s.gmail_refresh_enc ? decrypt(s.gmail_refresh_enc) : null;
    if (!refresh)                        return console.log('[Scheduled] Gmail not connected');

    const { data: campaign } = await supabase.from('campaigns').select('*').eq('id', s.scheduled_campaign_id).single();
    if (!campaign) return console.log('[Scheduled] Campaign not found');

    const { data: allContacts } = await supabase.from('contacts')
      .select('*').eq('list_id', s.scheduled_list_id).eq('opted_out', false).not('email', 'is', null);
    if (!allContacts?.length) return console.log('[Scheduled] No contacts in list');

    const { data: alreadySent } = await supabase.from('sends').select('contact_id').eq('campaign_id', s.scheduled_campaign_id);
    const sentIds = new Set((alreadySent || []).map(r => r.contact_id));
    const toSend  = allContacts.filter(c => !sentIds.has(c.id)).slice(0, 40);

    if (!toSend.length) return console.log('[Scheduled] All contacts already sent to');

    const { data: sendRecords } = await supabase.from('sends')
      .insert(toSend.map(c => ({ campaign_id: s.scheduled_campaign_id, contact_id: c.id, status: 'pending' })))
      .select();

    const oauth2 = makeOAuth2Client();
    oauth2.setCredentials({ refresh_token: refresh });
    const gmail    = google.gmail({ version: 'v1', auth: oauth2 });
    const fromName = campaign.from_name || s.from_name || 'Mide';
    const baseUrl  = s.app_url || appUrl();

    let sentCount = 0;
    for (const record of sendRecords) {
      const contact = toSend.find(c => c.id === record.contact_id);
      if (!contact) continue;
      try {
        const subject  = fillTemplate(campaign.subject,   contact);
        const bodyHtml = fillTemplate(campaign.body_html, contact, true);
        const fullHtml = bodyHtml + `
<div style="margin-top:40px;padding-top:16px;border-top:1px solid #e5e7eb;font-size:11px;color:#9ca3af">
  You are receiving this email because your company matches our outreach criteria.<br>
  <a href="${baseUrl}/api/track/unsubscribe/${contact.id}" style="color:#9ca3af">Unsubscribe</a>
</div>
<img src="${baseUrl}/api/track/open/${record.id}" width="1" height="1" alt="" style="display:none"/>`;
        const raw = buildRawEmail({
          from: `${fromName} <${s.gmail_email}>`, to: contact.email,
          subject, html: fullHtml,
          listUnsubscribe: `<${baseUrl}/api/track/unsubscribe/${contact.id}>`,
        });
        await gmail.users.messages.send({ userId: 'me', requestBody: { raw } });
        await supabase.from('sends').update({ status: 'sent', sent_at: new Date().toISOString() }).eq('id', record.id);
        sentCount++;
      } catch (err) {
        console.error(`[Scheduled] Send failed to ${contact.email}:`, err.message);
        await supabase.from('sends').update({ status: 'failed', error_msg: err.message.slice(0, 500) }).eq('id', record.id);
      }
      await sleep(1500);
    }
    console.log(`[Scheduled] Done — ${sentCount}/${toSend.length} sent`);
  } catch (err) {
    console.error('[Scheduled] Error:', err.message);
  }
}

cron.schedule('20 8 * * *', runScheduledSend, { timezone: 'Europe/Dublin' });

// Catch-up guard — runs every 10 minutes, triggers send if 8:20am was missed today
let lastSendDate = null;
cron.schedule('*/10 * * * *', async () => {
  try {
    const now = new Date(new Date().toLocaleString('en-US', { timeZone: 'Europe/Dublin' }));
    const hour = now.getHours();
    const min  = now.getMinutes();
    const today = now.toISOString().slice(0, 10);

    // Only attempt between 8:20am and 9:00am Irish time
    if (hour < 8 || (hour === 8 && min < 20) || hour >= 9) return;

    // Only run once per day
    if (lastSendDate === today) return;

    // Check if any sends went out today already
    const todayStart = new Date(now); todayStart.setHours(0, 0, 0, 0);
    const { data: todaySends } = await supabase.from('sends').select('id').gte('sent_at', todayStart.toISOString()).limit(1);
    if (todaySends?.length) { lastSendDate = today; return; }

    console.log('[Catch-up] No sends detected today — triggering scheduled send now');
    lastSendDate = today;
    await runScheduledSend();
  } catch (err) {
    console.error('[Catch-up] Error:', err.message);
  }
});

async function runDailyReport() {
  console.log('[Report] Generating daily report…');
  try {
    const s = await getSettings();
    if (!s.scheduled_send_enabled) return;
    const refresh = s.gmail_refresh_enc ? decrypt(s.gmail_refresh_enc) : null;
    if (!refresh || !s.gmail_email) return;

    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);

    const { data: todaySends } = await supabase.from('sends')
      .select('status, opened_at, clicked_at, contact_id, campaign_id')
      .gte('sent_at', todayStart.toISOString());

    const sent    = (todaySends || []).filter(r => r.status === 'sent' || r.status === 'opened' || r.status === 'clicked');
    const failed  = (todaySends || []).filter(r => r.status === 'failed');
    const opened  = sent.filter(r => r.opened_at);
    const clicked = sent.filter(r => r.clicked_at);

    const { data: allContacts } = await supabase.from('contacts')
      .select('id').eq('list_id', s.scheduled_list_id).not('email', 'is', null);
    const { data: allSent } = await supabase.from('sends')
      .select('contact_id').eq('campaign_id', s.scheduled_campaign_id);
    const sentIds    = new Set((allSent || []).map(r => r.contact_id));
    const remaining  = (allContacts || []).filter(c => !sentIds.has(c.id)).length;
    const daysLeft   = remaining > 0 ? Math.ceil(remaining / 20) : 0;

    const openRate  = sent.length ? Math.round((opened.length  / sent.length) * 100) : 0;
    const clickRate = sent.length ? Math.round((clicked.length / sent.length) * 100) : 0;

    const reportHtml = `
<div style="font-family:system-ui,sans-serif;max-width:520px;padding:24px;background:#f9fafb;border-radius:8px">
  <h2 style="margin:0 0 4px;font-size:18px;color:#111">Daily Send Report</h2>
  <p style="margin:0 0 20px;color:#6b7280;font-size:13px">${new Date().toLocaleDateString('en-IE', { weekday:'long', year:'numeric', month:'long', day:'numeric' })}</p>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px">
    <div style="background:#fff;border-radius:6px;padding:16px;border:1px solid #e5e7eb">
      <div style="font-size:28px;font-weight:700;color:#111">${sent.length}</div>
      <div style="font-size:12px;color:#6b7280">Emails Sent Today</div>
    </div>
    <div style="background:#fff;border-radius:6px;padding:16px;border:1px solid #e5e7eb">
      <div style="font-size:28px;font-weight:700;color:#111">${failed.length}</div>
      <div style="font-size:12px;color:#6b7280">Failed</div>
    </div>
    <div style="background:#fff;border-radius:6px;padding:16px;border:1px solid #e5e7eb">
      <div style="font-size:28px;font-weight:700;color:${openRate >= 20 ? '#16a34a' : openRate >= 10 ? '#d97706' : '#dc2626'}">${openRate}%</div>
      <div style="font-size:12px;color:#6b7280">Open Rate</div>
    </div>
    <div style="background:#fff;border-radius:6px;padding:16px;border:1px solid #e5e7eb">
      <div style="font-size:28px;font-weight:700;color:#111">${clickRate}%</div>
      <div style="font-size:12px;color:#6b7280">Click Rate (demo link)</div>
    </div>
  </div>

  <div style="background:#fff;border-radius:6px;padding:16px;border:1px solid #e5e7eb;margin-bottom:12px">
    <div style="font-size:13px;color:#111"><strong>${remaining}</strong> contacts remaining in list</div>
    <div style="font-size:13px;color:#6b7280;margin-top:4px">~${daysLeft} days at 20/day to complete the list</div>
  </div>

  <div style="font-size:11px;color:#9ca3af;margin-top:16px">
    ${openRate >= 20 ? '✅ Strong open rate — email is landing well.' : openRate >= 10 ? '⚠️ Average open rate — consider tweaking the subject line.' : sent.length > 0 ? '🔴 Low open rate — emails may be hitting spam. Check your DNS records (SPF/DKIM).' : 'ℹ️ No emails sent today.'}
  </div>
</div>`;

    const oauth2 = makeOAuth2Client();
    oauth2.setCredentials({ refresh_token: refresh });
    const gmail = google.gmail({ version: 'v1', auth: oauth2 });
    const raw = buildRawEmail({
      from: `Shodipo Outreach <${s.gmail_email}>`,
      to:   s.gmail_email,
      subject: `📊 Daily Send Report — ${sent.length} sent, ${openRate}% open rate`,
      html:  reportHtml,
    });
    await gmail.users.messages.send({ userId: 'me', requestBody: { raw } });
    console.log(`[Report] Sent to ${s.gmail_email}`);
  } catch (err) {
    console.error('[Report] Error:', err.message);
  }
}

cron.schedule('0 18 * * *', runDailyReport, { timezone: 'Europe/Dublin' });

app.listen(PORT, () => {
  console.log(`✅ Marketing Agent running → http://localhost:${PORT}`);
  if (!process.env.GMAIL_CLIENT_ID) console.warn('⚠️  GMAIL_CLIENT_ID not set — Gmail sending will not work');
  if (!process.env.SUPABASE_URL)    console.warn('⚠️  SUPABASE_URL not set');
});
