# Protocol by Saiman // PROTOCOL 594

```
===============================================================================
DIRECTIVE: PROTOCOL 594 // TOP SECRET // NO-LOG EPHEMERAL TRANSMISSION NETWORK
===============================================================================
```

**Protocol by Saiman** is a classified, zero-log, ephemeral real-time communication platform engineered to comply with the **Protocol 594** standard. All transmissions exist solely in volatile React client memory. Zero messages are stored in PostgreSQL, IndexedDB, or localStorage.

---

## Security Architecture & Core Invariants

1. **Silent Anonymous Authentication**:
   - The terminal establishes background anonymous sessions using Supabase Auth (`signInAnonymously()`).
   - No login, signup, or password reset interfaces.

2. **Access Control & Server-Side Hashing**:
   - **Open Rooms**: Accessible via Room UUID + Callsign.
   - **Password-Protected Rooms**: Server-side verification via PostgreSQL RPC (`verify_and_join_classified_room`) using `pgcrypto` Blowfish bcrypt hashing.
   - **Zero Plaintext Storage**: Ciphers are never exposed to the client, never included in URLs, and never written to localStorage.
   - **Uniform Generic Errors**: Any failure returns `"Access Denied: Invalid Room ID or Security Cipher."`

3. **Volatile Realtime Protocol**:
   - Private Realtime channel `room:<roomId>` requiring anonymous session authentication.
   - Realtime presence tracking for active operators (`user_id`, `display_name`, `online_at`).
   - Real-time purge countdown timer with automated session destruction on 24h expiration.
   - Emergency **Burn Notice** button for instant in-memory buffer flush and disconnection.

---

## Repository Structure (< 15 files)

```
.
├── .github/workflows/deploy.yml   # GitHub Actions static export & deployment
├── src/
│   ├── app/
│   │   ├── globals.css            # Dark tactical styling, scanlines, and grid
│   │   ├── layout.tsx             # Protocol 594 tactical layout wrapper
│   │   ├── page.tsx               # Terminal Hub (Room Creation & Authentication)
│   │   └── room/
│   │       └── page.tsx           # Ephemeral Room Deck (HUD, LED signal, Burn Notice)
│   └── lib/
│       └── supabase.ts            # Supabase anonymous auth & client initialization
├── supabase/
│   └── schema.sql                 # Complete database schema, RLS, and RPC functions
├── tests/
│   └── protocol.test.ts           # Vitest suite covering all 13 verification criteria
├── .env.local                     # Local Supabase credentials
├── .gitignore                     # Git ignore rules
├── next.config.mjs                # Static export configuration (output: 'export')
├── package.json                   # Dependencies and scripts
├── postcss.config.js              # PostCSS configuration
├── tailwind.config.js             # Tactical defense color palette & animations
├── tsconfig.json                  # TypeScript compiler settings
└── README.md                      # Directive documentation
```

---

## Setup & Deployment

### 1. Database Configuration
1. Open the **SQL Editor** in your Supabase dashboard.
2. Execute the entire contents of [`supabase/schema.sql`](file:///c:/Users/s23sa/OneDrive/Documents/Antigravity/Protocol/supabase/schema.sql).
3. Navigate to **Authentication > Providers > Anonymous** and toggle **Enable Anonymous sign-ins** to **ON**.

### 2. Environment Variables
In `.env.local` (and repository GitHub Secrets for deployment):
```env
NEXT_PUBLIC_SUPABASE_URL=https://viatqaalfsyurgcyofah.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 3. Local Development
```bash
npm install
npm run dev
```

### 4. Automated Testing
Run the comprehensive 13-case test suite:
```bash
npm run test
```

### 5. Static Build & Export
```bash
npm run build
```
Generates a zero-backend static web app in `./out` ready for deployment to GitHub Pages.

---

## Protocol 594 Compliance Verification Matrix

| # | Test Case | Status | Invariant Enforced |
|---|---|---|---|
| 1 | Create an open room | PASSED | UUID generated, 24h expiration, null password hash |
| 2 | Join open room with only room ID & name | PASSED | Joins without cipher requirement |
| 3 | Create password-protected room | PASSED | Validates >= 8 chars, hashed with pgcrypto |
| 4 | Join protected room with correct password | PASSED | Server RPC verifies hash and admits operator |
| 5 | Reject wrong password | PASSED | Uniform error: "Access Denied: Invalid Room ID or Security Cipher." |
| 6 | Reject join without password | PASSED | Uniform error: "Access Denied: Invalid Room ID or Security Cipher." |
| 7 | Confirm password never visible in URL | PASSED | URL strictly uses `?id=<uuid>` format |
| 8 | Confirm password never stored in localStorage | PASSED | In-memory only; zero sensitive keys in storage |
| 9 | Confirm direct membership insert bypass prevented | PASSED | Row Level Security restricts direct inserts |
| 10 | Confirm non-members cannot subscribe to Realtime | PASSED | Private channel RLS policy blocks non-members |
| 11 | Confirm broadcast exchange between 2 users | PASSED | Ephemeral broadcast payload `{ id, senderName, text, sentAt }` |
| 12 | Confirm expired rooms cannot be joined | PASSED | Rooms where `expires_at <= now` rejected by RPC |
| 13 | Confirm chat messages not saved in DB | PASSED | Zero messages table; zero persistent DB writes |
