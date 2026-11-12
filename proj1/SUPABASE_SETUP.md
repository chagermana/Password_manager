# Supabase cloud sync setup

The browser app syncs one encrypted vault per Supabase Auth user. Its Supabase email/password login is separate from the vault master password. The master password is used only in the browser to unlock/decrypt the vault.

## 1. Create the Supabase project

Create a Supabase project, then open **SQL Editor** and run the contents of [`supabase-schema.sql`](./supabase-schema.sql). This creates the `vaults` table and owner-only Row Level Security policies. The app needs the Supabase Data API enabled for the `public` schema.

## 2. Configure email sign-in

In Supabase Authentication settings, enable email/password sign-in. For a real deployment, configure email delivery and email confirmation. For local development, add the local app URL (for example `http://localhost:8000`) to the allowed redirect/site URLs.

## 3. Add the browser client values

In the Supabase project settings, copy the **Project URL** and **publishable key**. In `index.html`, replace these two placeholders:

```js
const SUPABASE_URL='https://YOUR_PROJECT_ID.supabase.co';
const SUPABASE_PUBLISHABLE_KEY='YOUR_SUPABASE_PUBLISHABLE_KEY';
```

The publishable key is designed for browser use; keep Row Level Security enabled. Never put a `service_role` or secret key in this page.

## 4. Run and sign in

Serve the `proj1` folder from localhost (for example, `python -m http.server 8000`), open `http://localhost:8000`, create a cloud account, confirm the email if prompted, then sign in. Enter the vault master password to load or create the encrypted vault. Changes sync after saves, deletions, imports, or password resets.

To sync an existing local vault, sign in to the cloud account in the same browser and unlock with that vault's master password. If the cloud account has no vault yet, the local vault is uploaded. On a second device, sign in to the same cloud account and unlock with the same master password.

## Storage and security notes

- Supabase stores the encrypted vault object (`kvs`, salt, and encrypted password check). It does not receive the master password or decrypted account passwords.
- The database policy scopes reads and writes to the authenticated user's `auth.uid()`.
- Keep an encrypted export backup. A lost master password cannot be reset by Supabase because the server does not have the decryption key.
- The current app uses a demo PBKDF2 configuration and simple last-write-wins syncing. Before production use, review the key-derivation settings, add conflict handling, and test the RLS policies with separate user accounts.
