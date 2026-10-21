# Vaultly

> Your passwords. Your vault. Your control.

(Chrome Password Vault)

Estensione Chrome (Manifest V3) per importare, archiviare, consultare ed esportare **le proprie** credenziali in un archivio personale. I dati sono **cifrati sul dispositivo** (AES-256-GCM) prima di essere inviati a Supabase: il database non vede mai password, username, URL o note in chiaro.

Stack: TypeScript strict · React 18 · Vite 5 · Supabase (Auth + PostgreSQL + RLS) · Web Crypto API · Vitest · ESLint · Prettier.

> **Perdere la master password significa perdere i dati.** Non esiste recupero: la password non viene mai memorizzata né inviata al server.

---

## 1. Funzionalità

- Registrazione, accesso e disconnessione (Supabase Auth).
- Creazione del vault con master password; sblocco; blocco manuale e automatico (inattività configurabile).
- Importazione guidata da CSV (formato Chrome) con anteprima, validazione, righe non valide, rilevamento duplicati e scelta della gestione (salta / sostituisci / tieni entrambi, anche riga per riga), conferma esplicita e riepilogo.
- Elenco, ricerca (sito, dominio, username), dettaglio, aggiunta, modifica, eliminazione.
- Password nascosta di default; mostra/nascondi e copia solo su azione esplicita (la copia svuota gli appunti dopo 30 s, se la pagina è ancora aperta).
- Date di creazione/modifica e ultima sincronizzazione.
- Sincronizzazione con concorrenza ottimistica (campo `revision`), gestione dei conflitti (tieni la mia / usa quella del server), retry con backoff per errori di rete, operazioni idempotenti.
- Backup **cifrato** (file JSON scelto dall'utente) e ripristino; esportazione CSV in chiaro come funzione separata con avvisi e conferma.

## 2. Architettura di sicurezza

### Cifratura (formato v1)

| Elemento | Scelta |
| --- | --- |
| Cifratura | AES-256-GCM (Web Crypto), tag a 128 bit |
| Derivazione chiave | PBKDF2-HMAC-SHA256 dalla master password (normalizzata NFKC), iterazioni configurabili (default **600.000**, min 100.000, max 10.000.000) |
| Salt | 16 byte casuali, **uno per vault** |
| IV | 12 byte casuali, **nuovo per ogni cifratura** |
| AAD | `cpv:<versione>:<user_id>:<id_record>`: lega il ciphertext al proprietario e alla riga (il server non può scambiare righe tra record/utenti senza che la decifratura fallisca) |
| Chiave | `CryptoKey` **non estraibile**, solo in memoria della pagina |
| Verifica password | un "verifier" cifrato con la chiave derivata (in tabella `vaults`) distingue password errata da dati corrotti |
| Versionamento | `encryption_version` in ogni riga e in `vaults`; versioni sconosciute vengono rifiutate |

Se la decifratura fallisce (password errata, ciphertext/IV/AAD alterati) l'operazione lancia un errore generico: **non viene mai mostrato alcun dato parziale**.

La master password, e la chiave da essa derivata, **non lasciano mai il client**. La password di accesso a Supabase non è usata per la cifratura (sono due segreti distinti; l'interfaccia lo ricorda).

### Ciclo di vita della chiave e limiti della cancellazione della memoria

La chiave vive solo nella pagina (popup o scheda delle opzioni). `lock()` (manuale, automatico o al logout) elimina ogni riferimento alla chiave e svuota la cache delle credenziali in chiaro. **Limite importante:** JavaScript non permette di azzerare esplicitamente la memoria. I riferimenti diventano irraggiungibili, ma il garbage collector decide quando i byte vengono realmente liberati; la stringa della master password digitata e le password decifrate possono restare in memoria fino alla raccolta o alla chiusura della pagina. Chiudere il popup/la scheda distrugge il contesto. Contro malware con accesso al processo del browser questo design non offre protezione.

Poiché la chiave non è persistita (nemmeno in `chrome.storage`), **a ogni apertura del popup serve la master password**. È un compromesso deliberato a favore della sicurezza.

### Dati lasciati in chiaro su Supabase (implicazioni di privacy)

| Dato | Dove | Perché / implicazione |
| --- | --- | --- |
| Email dell'account | `auth.users` | Necessaria per l'autenticazione. |
| `user_id`, `id` record | tabelle | Chiavi tecniche e isolamento RLS. |
| `created_at`, `updated_at`, `revision` | `credentials` | Sincronizzazione/conflitti. Rivelano *quando* modifichi e *quante* volte. |
| Dimensione del ciphertext, numero di righe | `credentials` | Rivela approssimativamente il numero di credenziali e la lunghezza dei dati. |
| Parametri KDF (iterazioni, salt), verifier cifrato | `vaults` | Pubblici per definizione, non contengono segreti. Un attaccante che ottenga il DB può tentare un brute-force offline sulla master password: **scegli una master password lunga e unica**. |

Nome del sito, URL, username, password e note sono **tutti** dentro il blob cifrato. Per questo il rilevamento dei duplicati avviene sul client dopo la decifratura (un hash lato server rivelerebbe uguaglianze tra password/siti).

### Autenticazione, autorizzazione, RLS

- Supabase Auth con chiave **pubblica** (anon/publishable). La `service_role` non è mai usata né inclusa nel bundle (c'è un test che lo verifica).
- RLS **abilitata e forzata** su `vaults` e `credentials`, con una policy distinta per `select/insert/update/delete`, tutte `to authenticated` e vincolate a `user_id = auth.uid()`. Nessuna policy permissiva (`true`); l'accesso `anon` è revocato.
- Un trigger rende immutabili `user_id`, `id`, `created_at` e gestisce `updated_at` e `revision` lato server. Vincoli `CHECK` validano lunghezze/formati anche a livello di database.
- La sessione Supabase è salvata in `chrome.storage.session` (solo memoria, azzerata alla chiusura del browser), con rinnovo automatico del token; alla scadenza o al logout il vault viene bloccato e le credenziali in memoria vengono eliminate.

### Interfaccia ed estensione

- Permessi richiesti: **solo `storage`**. Nessun `host_permissions`, nessun content script: l'estensione non legge mai le pagine visitate.
- CSP: `script-src 'self'; object-src 'none'; connect-src https://*.supabase.co; …`. Nessuno script remoto, nessuna CDN a runtime.
- Nessun `console.*` fuori da `src/utils/logger.ts` (regola ESLint `no-console` + test): il logger accetta solo un contesto fisso e un codice.
- Nessuna credenziale in URL, titoli, notifiche o messaggi di errore. UI navigabile da tastiera, con label, `aria-live` e `role="alert"`.

## 3. Importazione dal gestore password di Chrome

Chrome non permette a un'estensione ordinaria di leggere le password salvate, e questo progetto **non** tenta scraping, lettura dei file interni del profilo o aggiramenti. Il flusso è esplicito:

1. In Chrome apri `chrome://password-manager/settings` → **Esporta password** (richiede l'autenticazione del sistema operativo). Chrome crea un CSV con intestazioni `name,url,username,password,note` (le versioni precedenti omettono `note`; sono riconosciuti anche alcuni alias, es. `login_uri`, `title`, ed è rilevato il delimitatore `,` `;` o tab).
2. Nell'estensione: **Import** → scegli il file → anteprima (le password non sono mostrate) → righe non valide → duplicati → scelta → conferma.
3. I record sono cifrati localmente e inviati a Supabase a blocchi di 100 (idempotenti: se l'operazione si interrompe, rilanciare lo stesso file salta ciò che è già stato salvato).
4. Il file non viene mai inviato a servizi esterni né salvato in storage persistente; i record in chiaro vengono rimossi dallo stato dell'interfaccia a importazione conclusa.
5. **Elimina il CSV originale in modo sicuro**: contiene tutte le password in chiaro.

Limiti: 10 MB / 50.000 righe per file.

## 4. Backup, ripristino e rischi

- **Backup cifrato** (`Impostazioni → Download encrypted backup`): file `password-vault-backup-AAAA-MM-GG.cpvbackup.json`. Formato `cpv-backup` v1: intestazione in chiaro (`format`, `version`, `kdf`, `iterations`, `salt`, `iv`, `createdAt`) e payload cifrato con AES-256-GCM, chiave derivata con PBKDF2 da una **passphrase di backup** scelta al momento (può coincidere con la master password ma non è obbligatorio). Gli id non sono esportati: il backup è ripristinabile in qualsiasi account.
- **Ripristino** (`Impostazioni → Restore from backup…`): scegli il file, inserisci la passphrase; i record passano per lo stesso flusso di anteprima/duplicati/conferma dell'import CSV.
- Il salvataggio avviene solo tramite il normale download del browser, mai in percorsi automatici.
- **Rischi:** senza la master password il vault è irrecuperabile; senza la passphrase di backup il backup è irrecuperabile. Conserva le passphrase in un luogo sicuro separato dal file. L'**esportazione CSV in chiaro** è disponibile nella "Danger zone" con checkbox e conferma: usala solo se strettamente necessario ed elimina il file subito dopo. I valori che iniziano con `= + - @` non sono alterati (per non corrompere le password): non aprire il CSV in un foglio di calcolo.
- Più dispositivi: usa lo stesso account e la **stessa master password**; i parametri KDF/salt sono letti da `vaults`. Non c'è condivisione di chiavi tra utenti.

## 5. Configurazione di Supabase

1. Crea un progetto su <https://supabase.com> (piano gratuito sufficiente).
2. **Schema**: apri *SQL Editor*, incolla ed esegui `supabase/migrations/20241001000000_init_vault.sql` (idempotente). In alternativa, con la CLI: `supabase link --project-ref <ref>` e `supabase db push`.
3. **Auth**: *Authentication → Providers → Email* abilitato. Per uso personale consigli: disattiva "Allow new users to sign up" dopo aver creato il tuo account (*Authentication → Sign In / Providers*), così nessun altro potrà registrarsi. Se mantieni la conferma email, conferma prima di accedere. Imposta *Password requirements* adeguati e, se vuoi, MFA.
4. **Chiavi**: *Project Settings → API*: copia **Project URL** e la chiave **anon / publishable**. **Non** usare mai `service_role` / `secret`.
5. Copia `.env.example` in `.env` e compila:
   ```
   VITE_SUPABASE_URL=https://<ref>.supabase.co
   VITE_SUPABASE_ANON_KEY=<chiave pubblica anon/publishable>
   ```
   `.env` è ignorato da git. Se usi un Supabase self-hosted (dominio diverso da `*.supabase.co`) aggiorna `connect-src` nella CSP di `public/manifest.json`.
6. **Verifica RLS (manuale)**: esegui `supabase/tests/rls_isolation.sql` nello SQL Editor: crea due utenti fittizi, controlla l'isolamento e fa rollback. Deve terminare con `RLS isolation checks passed`.

## 6. Build e caricamento in Chrome

```bash
npm install
cp .env.example .env     # poi compila i valori
npm run build            # genera dist/
```

1. Apri `chrome://extensions`, attiva **Modalità sviluppatore**.
2. **Carica estensione non pacchettizzata** → seleziona la cartella `dist/`.
3. Alla prima installazione si apre la pagina a schermo intero: crea l'account, poi il vault (master password), poi importa o aggiungi credenziali. Il popup dell'icona offre la stessa app.

Dopo ogni modifica al codice o a `.env`: `npm run build` e premi *Ricarica* in `chrome://extensions`. `npm run dev` ricompila in watch mode.

## 7. Qualità e test

```bash
npm run lint          # ESLint (no-console, no any)
npm run typecheck     # tsc strict
npm run format:check  # Prettier
npm run build
npm test              # Vitest
npm run verify        # lint + typecheck + build + test
```

I test (`tests/`) sono tutti **automatici e senza rete**: usano Web Crypto reale, un finto server in memoria che emula RLS/revisioni e un finto client Supabase che registra i payload. Coprono cifratura/decifratura, password errate, manomissione di ciphertext/IV, unicità degli IV, import CSV (valido, malformato, Unicode, delimitatori), duplicati, conflitti di sincronizzazione, isolamento tra utenti, sessione/autenticazione, blocco/sblocco/auto-lock, backup e ripristino, assenza di password in chiaro nei payload, permessi del manifest, analisi statica delle migration (RLS, assenza di policy permissive), assenza di `console.*`, di `service_role` e di codice remoto nel bundle.

**Controlli manuali (richiedono un progetto Supabase reale):**
- esecuzione della migration e `supabase/tests/rls_isolation.sql` (RLS effettiva sul database);
- registrazione/accesso/refresh token reali e comportamento con conferma email;
- caricamento dell'estensione in Chrome e prova del flusso completo (import CSV reale, copia negli appunti, auto-lock, due dispositivi con conflitto);
- verifica in *Table Editor* che le righe contengano solo `ciphertext`/`iv`.

## 8. Limiti noti

- Nessun cambio della master password (richiederebbe la ri-cifratura di tutti i record): per ora si crea un nuovo vault con un backup cifrato e un ripristino.
- Nessuna coda offline persistente: in assenza di rete le operazioni sono ritentate (3 tentativi, backoff esponenziale) e poi falliscono con un messaggio chiaro; i dati non salvati non sono conservati su disco.
- L'eliminazione è definitiva (con controllo di revisione per non cancellare modifiche altrui); non c'è cestino.
- La pulizia degli appunti è "best effort" e funziona solo finché la pagina resta aperta.
- Nessun auto-compilamento nei siti (volutamente: nessun accesso ai contenuti delle pagine).

## 9. Struttura

```
public/manifest.json       Manifest V3 (permesso: storage)
src/background/            service worker minimale
src/popup, src/options/    punti d'ingresso React
src/ui/, src/components/   App, schermate e componenti
src/services/crypto/       KDF, AES-GCM, vault, record cifrati
src/services/supabase/     client, auth, store (RLS-aware), mapping errori
src/services/sync/         sincronizzazione, conflitti, retry
src/services/import/       CSV, formato Chrome, duplicati, importer
src/services/export/       backup cifrato, CSV in chiaro
src/services/vault/        sessione/blocco automatico
supabase/migrations/       schema SQL + RLS
supabase/tests/            controllo RLS manuale
tests/                     test Vitest (+ helpers/)
```
