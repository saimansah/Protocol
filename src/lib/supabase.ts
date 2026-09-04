import { createClient, User } from '@supabase/supabase-js';

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || 'https://placeholder.supabase.co';
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || 'placeholder-anon-key';

// Security guarantee: Never expose service-role keys in frontend code
if (typeof window !== 'undefined') {
  if (supabaseAnonKey.includes('service_role') || (process.env as any).NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY) {
    console.error('CRITICAL SECURITY VIOLATION: Service role key detected in client environment! Only public anon key is permitted.');
  }
}

export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: false,
    storage: typeof window !== 'undefined' ? window.localStorage : undefined,
  },
  realtime: {
    params: {
      eventsPerSecond: 20,
    },
  },
});

// Mutex / Request Lock: Shared in-flight promise to prevent duplicate simultaneous sign-ins
let pendingAuthPromise: Promise<User | null> | null = null;

// Client-side cooldown state tracking
let lastFailureTimestamp: number = 0;
export const AUTH_COOLDOWN_MS = 10000; // 10-second cooldown window after failure

export interface AnonymousAuthOptions {
  captchaToken?: string;
  forceRefresh?: boolean;
}

/**
 * Returns remaining cooldown in seconds, or 0 if cooldown has expired.
 */
export function getAuthCooldownRemaining(): number {
  if (!lastFailureTimestamp) return 0;
  const elapsed = Date.now() - lastFailureTimestamp;
  if (elapsed >= AUTH_COOLDOWN_MS) {
    lastFailureTimestamp = 0;
    return 0;
  }
  return Math.ceil((AUTH_COOLDOWN_MS - elapsed) / 1000);
}

/**
 * Reset cooldown for testing or explicit manual recovery.
 */
export function resetAuthCooldown(): void {
  lastFailureTimestamp = 0;
  pendingAuthPromise = null;
}

/**
 * Safely ensures a valid Supabase Anonymous session:
 * 1. Reuses existing persisted session via getSession() without calling signInAnonymously()
 * 2. Enforces a client-side cooldown after failed attempts to prevent spamming
 * 3. Uses a shared promise lock to coalesce simultaneous requests
 * 4. Gracefully intercepts HTTP 429 rate-limiting and outputs standard message
 * 5. Passes optional Cloudflare Turnstile / hCaptcha tokens
 */
export async function ensureAnonymousAuth(options?: AnonymousAuthOptions): Promise<User | null> {
  // Test/Mock environment fallback
  if (!process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL.includes('placeholder')) {
    return {
      id: 'anonymous-mock-agent',
      app_metadata: {},
      user_metadata: {},
      aud: 'authenticated',
      created_at: new Date().toISOString(),
      is_anonymous: true,
    } as User;
  }

  // 1. Enforce client-side cooldown after error
  const remainingCooldown = getAuthCooldownRemaining();
  if (remainingCooldown > 0 && !options?.forceRefresh) {
    throw new Error('Too many connection attempts. Please wait and try again.');
  }

  // 2. Reuse existing session if present (never create duplicate anonymous user)
  if (!options?.forceRefresh) {
    const { data: { session }, error: sessionError } = await supabase.auth.getSession();
    if (sessionError) {
      console.warn('Session verification notice:', sessionError.message);
    }
    if (session?.user) {
      return session.user;
    }
  }

  // 3. Prevent duplicate simultaneous sign-in requests with shared promise lock
  if (pendingAuthPromise) {
    return await pendingAuthPromise;
  }

  // 4. Initiate single locked authentication request
  pendingAuthPromise = (async () => {
    try {
      // Re-verify session in case another caller just resolved it
      const { data: { session: existingSession } } = await supabase.auth.getSession();
      if (existingSession?.user && !options?.forceRefresh) {
        return existingSession.user;
      }

      const signInParams: { options?: { captchaToken?: string } } = {};
      if (options?.captchaToken) {
        signInParams.options = { captchaToken: options.captchaToken };
      }

      const { data, error } = await supabase.auth.signInAnonymously(signInParams);

      if (error) {
        lastFailureTimestamp = Date.now();
        const msg = (error.message || '').toLowerCase();
        if (
          error.status === 429 ||
          msg.includes('429') ||
          msg.includes('rate limit') ||
          msg.includes('too many') ||
          msg.includes('security')
        ) {
          throw new Error('Too many connection attempts. Please wait and try again.');
        }
        if (
          (error as any).code === 'anonymous_provider_disabled' ||
          msg.includes('anonymous sign-ins are disabled')
        ) {
          throw new Error('Anonymous sign-ins are disabled in Supabase. Go to Authentication -> Providers -> Anonymous Sign-ins in your Supabase Dashboard and toggle it ON.');
        }
        throw error;
      }

      // Successful auth clears cooldown
      lastFailureTimestamp = 0;
      return data.user;
    } catch (err: any) {
      lastFailureTimestamp = Date.now();
      const msg = (err?.message || '').toLowerCase();
      if (
        err?.status === 429 ||
        msg.includes('429') ||
        msg.includes('rate limit') ||
        msg.includes('too many')
      ) {
        throw new Error('Too many connection attempts. Please wait and try again.');
      }
      if (
        err?.code === 'anonymous_provider_disabled' ||
        msg.includes('anonymous sign-ins are disabled')
      ) {
        throw new Error('Anonymous sign-ins are disabled in Supabase. Go to Authentication -> Providers -> Anonymous Sign-ins in your Supabase Dashboard and toggle it ON.');
      }
      throw err;
    } finally {
      pendingAuthPromise = null;
    }
  })();

  return await pendingAuthPromise;
}
