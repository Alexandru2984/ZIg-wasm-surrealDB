Mai jos ai un plan de refactor „production-ish” pentru proiectul tău Zig (cu focus pe memory safety, uptime și structură clară). Îl poți aplica incremental, fără să-ți pice serverul în cap.

0) Principiile (ca să știi de ce facem schimbările)

Ținta e să obții:

ownership explicit (cine alocă / cine eliberează / cât trăiește memoria)

fără global mutable state

boundary-uri clare: app vs lib, transport vs business logic, db vs model

fără „borrowed slices” care devin invalide (mai ales din JSON)

timeouts/retry/logging pentru “online” (nu doar “merge local”)

1) Re-aranjează proiectul în straturi

Structura recomandată:

src/

main.zig – doar bootstrap + wiring

app.zig – AppState + start/stop + orchestrare

config/ – Config loader + typed access

http/ – router, handlers, request/response helpers

domain/ – tipuri business (User, Post, EmailJob etc.)

services/ – auth service, email service, post service

db/

db.zig – interfață/contract (Repo)

surreal_repo.zig – implementare

(mai târziu) pg_repo.zig

util/ – json helpers, validation, logging helpers

Regula: http nu știe detalii despre DB, doar cheamă services. services vorbesc cu db printr-o interfață.

2) Elimină global state (config + orice altceva)
Problema:

Globals = non-thread-safe + tricky lifetime + greu de testat.

Ținta:

Ai un singur AppState care ține:

allocator(e)

config

db repo

email client

logger

orice cache

Exemplu conceptual:

AppState.init(allocator) !AppState

deinit() eliberează TOT în ordine.

Câștig:

memory ownership clar

testare ușoară

“server online” fără surprize când crești

3) Standardizează strategia de allocatori (asta îți dă “memory safe” în practică)

În Zig, “memory safe” = ownership + discipline + detectare la test.

Recomandare “production-ish”:

pentru server runtime:

GeneralPurposeAllocator (GPA) ca allocator principal

pentru fiecare request: un ArenaAllocator (request-scoped)

pentru test/debug:

activează std.heap.GeneralPurposeAllocator(.{ .safety = true })

rulează zig test + -Drelease-safe=false în debug ca să prindă leaks/UB

Regula de aur:

Datele care trebuie să trăiască doar cât request-ul → alocate în arena și nu se eliberează individual.

Datele care trebuie să trăiască mai mult (config/app cache/db objects) → alocate cu allocatorul “app”.

4) Repară zona cea mai periculoasă: JSON ownership / lifetime

Ai zis (și eu am văzut tiparul) unde apar cele mai nasoale buguri:

parsezi JSON

iei []const u8 din el

faci deinit()

păstrezi slices care devin invalide

Refactor recomandat: 2 moduri (alegi unul și îl aplici consistent)
Mod A (cel mai simplu, robust): “Parse → Copy → Deinit”

Parsezi JSON în request arena (sau temp)

Extragi stringuri/fields și le copiezi în arena sau în allocatorul de care ai nevoie

Deinit parse imediat

Câștig: nu mai ai “dangling slice”.

Mod B (mai performant, mai strict): “DOM lives as long as you need it”

Ții obiectul parsed (și buffer-ul sursă) viu până termini cu el

Interzis să returnezi slices în afara scope-ului lui

Recomandare: pentru server, Mod A e aproape mereu mai safe și suficient.

5) Config: fă-l un obiect imutabil după init

Refactor din:

var config: ?HashMap = null global
în:

Config struct cu map + allocator

Config.init(allocator, path)

Config.deinit()

Extra pentru “production-ish”

whitelist de chei (dacă lipsește ceva critic → fail fast la boot)

funcții typed: getBoolStrict, getIntStrict, getEnum

log friendly: să nu printezi secrete (mask)

6) DB layer: definește un “Repo contract” ca să poți schimba SurrealDB ușor

Ținta ta e să poți:

rămâne online acum cu Surreal

dar să nu fii blocat când migrezi la Postgres

Ce faci:

db/db.zig definește interfața (set de funcții) pe care services o folosesc:

createUser()

getUserByEmail()

createPost()

listPosts()

db/surreal_repo.zig implementează contractul

Regula: services nu “știe” SurrealDB, doar “Repo”.

7) HTTP handlers: request-scoped arena + input validation clară

În fiecare handler:

creezi ArenaAllocator din allocator principal

parse request body în arena

validezi (validation.zig)

chemi service

construiești răspunsul (ideal tot în arena)

arena deinit la final

Asta e unul dintre cele mai simple moduri să ai server Zig “ok-ish” fără leaks.

8) Auth: fă-l “safe enough” pentru producție (minimul absolut)

Dacă ai login/parole:

nu stoca parole în clar

folosește un KDF:

Argon2id e recomandarea modernă (în general)

constant-time compare la verificare

rate limiting basic pe login (per IP / user)

session tokens:

tokens random (CSPRNG)

expirare

Dacă proiectul e doar intern, măcar:

hashing + salt + expiring sessions

9) Email: timeouts, retries, queue (chiar simplă)

Ca să fie “online” fără nervi:

set timeout la request SMTP/API

retry cu backoff:

ex: 1s, 2s, 5s, 10s (max 5 încercări)

log pentru fiecare fail + reason

ideal: coadă simplă (in-memory) și worker thread

dacă pică email providerul → serverul nu moare, doar marchează job fail

10) Logging și observabilitate (minim viabil)

logger unificat (nu std.debug.print peste tot)

nivele: info/warn/error

request id în log (random sau increment)

log “startup config summary” (fără secrete)

health endpoint /health:

ok dacă db conectat + app state valid

11) Graceful shutdown + resiliență

Pentru uptime:

catch SIGTERM/SIGINT

oprești acceptarea de conexiuni noi

lași request-urile în curs să termine (cu timeout)

deinit() curat (db client, email worker, etc.)

12) Teste + “safety gates”

Ținta e să prinzi:

leaks

use-after-free

invalid lifetime din JSON

regresii

Minime:

zig test pentru:

config parser

validation

json helper (mai ales!)

db mock tests pentru services

Gate de release:

rulezi testele cu allocator safety activ

rulezi un load test mic (10-100 req/s) și verifici că nu crește RAM continuu