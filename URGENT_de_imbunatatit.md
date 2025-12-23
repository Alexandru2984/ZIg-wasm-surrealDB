Perfect. Îți las un plan în pași, ordonat de la cele mai grele / cu cel mai mare impact spre cele mai ușoare. E gândit să-l poți urma ca backlog (și să bifezi).

Faza 0 — “Safety net” înainte de refactor (greu-ish, dar îți salvează nervii)

Freeze pe API contract

Notează endpoint-urile + request/response JSON (și coduri HTTP) într-un docs/api.md.

Scop: după refactor, să știi sigur că n-ai stricat comportamentul.

Adaugă un “smoke test” script

Un script (bash sau Zig) care face: signup → verify → login → me.

Scop: după fiecare milestone, rulezi scriptul și vezi instant dacă e ok.

Faza 1 — Cel mai greu & cel mai important: scoate sh -c curl din DB layer (P0)
Obiectiv

DB query să nu mai pornească procese și să nu mai treacă prin shell.

Pașii

Creează un modul nou: db/http_client.zig

Responsabil doar de HTTP POST către SurrealDB.

Input: sql: []const u8

Output: status, body (limită de ex. 1–4MB), plus error.

Implementare cu std.http.Client

Fă request:

URL: http(s)://host/sql

headers:

Content-Type: text/plain (sau cum cere Surreal)

Authorization: Basic <base64(user:pass)> (NU în argv, NU în logs)

Setează timeouts (connect/read) dacă API-ul din versiunea ta permite. Dacă nu, pune măcar limite de body + limită de retries.

Body read “bounded”

Nu citi nelimitat.

readAllAlloc(allocator, max_bytes) sau buclă care oprește la limită.

Partea de erori

Dacă status != 200/2xx:

log status + body (dar trunchiat)

întoarce error typed (nu doar string).

Înlocuiește db/surreal.zig query()

surreal.query() devine wrapper peste noul http_client.

Ștergi complet std.process.Child.run și sh -c.

Adaugă retry doar aici

Retry/backoff la nivel DB (doar pentru erori de rețea / 5xx), nu pentru 4xx.

Backoff: 200ms → 500ms → 1s (max 3 încercări).

✅ La final: ai eliminat injection via shell, ai redus overhead-ul masiv, și ai control real pe timeouts/body.

Faza 2 — Memory safety reală: allocator per-request cu Arena (P0)
Obiectiv

Zero leaks accidentale + cleanup garantat.

Pașii

În handler (la început), creezi arena

var arena = std.heap.ArenaAllocator.init(gpa);

defer arena.deinit();

const a = arena.allocator();

Regula:

Tot ce ține de request (JSON parse, strings, db query body, template, etc.) folosește a.

Schimbă semnăturile helperelor

parseJsonField(allocator, ...) rămâne, dar îi dai a.

Orice funcție care întoarce “owned” pe request → să folosească arena.

Elimină multe free() manuale.

Boundary clar

Singurele lucruri care NU trebuie să fie în arena:

cache global, config global, resurse long-lived.

În rest: arena.

✅ La final: e aproape imposibil să “uiți” să eliberezi.

Faza 3 — SurrealQL injection hardening (P0)
Obiectiv

Niciun input user nu ajunge “raw” în query.

Pașii

Interzice string interpolation direct

Nu mai face "... {s} ..." cu input user.

Creează un singur entrypoint pentru escaping

db.escape(value) și îl folosești obligatoriu.

În code review: dacă vezi {s} cu input user → bug.

Normalizează + validează înainte de escape

ex: email -> lower + trim

nume -> trim + length cap

parolă -> nu o bagi niciodată în query (doar hash)

Dacă Surreal suportă parametri/bind

Folosește asta în loc de interpolation.

Dacă nu: construiește query-uri doar cu string-uri escapate.

✅ La final: nu te mai bazezi pe “poate merge”.

Faza 4 — Hash storage format “migrabil” (P1, dar important)
Obiectiv

Să poți schimba parametrii Argon2 fără să rupi autentificarea.

Pașii

Definește un format

ex: $argon2id$m=65536,t=3,p=4$<salt_hex>$<hash_hex>

Scrie encode_hash() și decode_hash()

decode_hash() parsează parametrii și salt/hash.

La login:

parsezi, rulezi Argon2 cu parametrii din string, compari.

Opțional: “rehash on login”

Dacă parametrii vechi < parametrii noi:

după login reușit, regenerezi hash și updatezi în DB.

✅ La final: upgrade fără durere.

Faza 5 — Static file serving corect (P1)
Obiectiv

Să nu poată citi fișiere din afara public/.

Pașii

Decode URL path

Normalize path

split pe /

ignoră .

pentru .. -> pop, dar dacă pop când e gol => reject

Interzice absolute paths

dacă începe cu / după decode => tratează ca relative strict.

Join cu root și verifică prefix

root = realpath(public)

file = realpath(root + relative) (dacă există)

dacă file nu începe cu root => reject 403

MIME types + caching

set Content-Type corect

cache static: Cache-Control: public, max-age=...

Faza 6 — Rate limiting & auth hardening (P1)
Obiectiv

Blochezi brute-force și spam.

Pașii

Implementare simplă în memorie

HashMap(ip -> counters + window_start)

per endpoint: login/forgot/verify

Algoritm

sliding window 60s sau fixed window

ex: max 10 requests / min / IP

Răspuns

429 Too Many Requests

Retry-After: ...

Persistență (opțional)

dacă ai mai multe instanțe: Redis. Dacă nu, în mem e ok.

Faza 7 — Logging & observability minim (P2, dar te ajută mult)

Request ID

generezi random hex 8–16 bytes

îl pui în logs și în response header X-Request-ID

Log format

JSON logs: {ts, level, req_id, ip, method, path, status, ms}

Metrics endpoint

/metrics (chiar și text simplu)

counters: requests_total, errors_total, db_latency_ms_bucket

Faza 8 — Health/Ready (P2)

/health: return 200 mereu dacă procesul e up

/ready: verifică DB query simplu + config essential