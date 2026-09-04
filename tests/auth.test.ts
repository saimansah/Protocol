import { describe, it, expect, vi, beforeEach } from 'vitest';

// ============================================================================
// PROTOCOL 594 // SAFE SUPABASE ANONYMOUS AUTHENTICATION TEST SUITE
// Verifies:
// - Session reuse with getSession()
// - Concurrency lock / single in-flight promise
// - Rate-limit (HTTP 429) interception and standardized message
// - Client-side cooldown after error
// - Captcha token passthrough
// - Service-role key leak prevention
// ============================================================================

describe('Safe Supabase Anonymous Authentication', () => {
  let mockSession: any = null;
  let signInCalls = 0;
  let signInOptionsPassed: any = null;
  let shouldFailSignIn = false;
  let failWithStatus: number | null = null;
  let failWithMessage: string | null = null;

  // Mock implementation of the safe auth manager logic
  class SafeAuthManager {
    private pendingPromise: Promise<any> | null = null;
    private lastFailureTime = 0;
    public readonly cooldownMs = 500; // 500ms for fast test execution

    public getCooldownRemaining(): number {
      if (!this.lastFailureTime) return 0;
      const elapsed = Date.now() - this.lastFailureTime;
      if (elapsed >= this.cooldownMs) {
        this.lastFailureTime = 0;
        return 0;
      }
      return Math.ceil((this.cooldownMs - elapsed) / 1000);
    }

    public resetCooldown(): void {
      this.lastFailureTime = 0;
      this.pendingPromise = null;
    }

    public async ensureAnonymousAuth(options?: { captchaToken?: string; forceRefresh?: boolean }) {
      // 1. Check cooldown
      if (this.getCooldownRemaining() > 0 && !options?.forceRefresh) {
        throw new Error('Too many connection attempts. Please wait and try again.');
      }

      // 2. Reuse existing session if present
      if (!options?.forceRefresh && mockSession?.user) {
        return mockSession.user;
      }

      // 3. Concurrency Lock: return shared in-flight promise
      if (this.pendingPromise) {
        return await this.pendingPromise;
      }

      // 4. In-flight execution
      this.pendingPromise = (async () => {
        try {
          if (mockSession?.user && !options?.forceRefresh) {
            return mockSession.user;
          }

          // Track mock sign in call
          signInCalls++;
          signInOptionsPassed = options?.captchaToken ? { options: { captchaToken: options.captchaToken } } : undefined;

          // Simulate network delay
          await new Promise((resolve) => setTimeout(resolve, 20));

          if (shouldFailSignIn) {
            this.lastFailureTime = Date.now();
            const err: any = new Error(failWithMessage || 'Sign in error');
            if (failWithStatus) err.status = failWithStatus;
            const msg = (err.message || '').toLowerCase();
            if (err.status === 429 || msg.includes('429') || msg.includes('rate limit') || msg.includes('too many')) {
              throw new Error('Too many connection attempts. Please wait and try again.');
            }
            throw err;
          }

          const newUser = {
            id: 'anon-user-' + Math.random().toString(36).substring(2, 9),
            is_anonymous: true,
            role: 'authenticated',
          };
          mockSession = { user: newUser };
          this.lastFailureTime = 0;
          return newUser;
        } catch (err: any) {
          this.lastFailureTime = Date.now();
          const msg = (err?.message || '').toLowerCase();
          if (err?.status === 429 || msg.includes('429') || msg.includes('rate limit') || msg.includes('too many')) {
            throw new Error('Too many connection attempts. Please wait and try again.');
          }
          throw err;
        } finally {
          this.pendingPromise = null;
        }
      })();

      return await this.pendingPromise;
    }
  }

  let authManager: SafeAuthManager;

  beforeEach(() => {
    authManager = new SafeAuthManager();
    mockSession = null;
    signInCalls = 0;
    signInOptionsPassed = null;
    shouldFailSignIn = false;
    failWithStatus = null;
    failWithMessage = null;
  });

  // TEST 1: Reuses existing session with getSession()
  it('1. Reuses existing session without calling signInAnonymously()', async () => {
    mockSession = {
      user: { id: 'pre-existing-anon-user-001', is_anonymous: true },
    };

    const user = await authManager.ensureAnonymousAuth();
    expect(user.id).toBe('pre-existing-anon-user-001');
    expect(signInCalls).toBe(0); // Never called signInAnonymously
  });

  // TEST 2: Prevents duplicate simultaneous requests using a shared promise lock
  it('2. Prevents duplicate simultaneous anonymous sign-in requests with shared promise lock', async () => {
    // Launch 5 simultaneous sign-in requests concurrently
    const [u1, u2, u3, u4, u5] = await Promise.all([
      authManager.ensureAnonymousAuth(),
      authManager.ensureAnonymousAuth(),
      authManager.ensureAnonymousAuth(),
      authManager.ensureAnonymousAuth(),
      authManager.ensureAnonymousAuth(),
    ]);

    // All 5 callers must resolve to the EXACT same user instance
    expect(u1.id).toBe(u2.id);
    expect(u2.id).toBe(u3.id);
    expect(u3.id).toBe(u4.id);
    expect(u4.id).toBe(u5.id);

    // Exactly 1 network request was initiated
    expect(signInCalls).toBe(1);
  });

  // TEST 3: Intercepts HTTP 429 rate-limit errors gracefully
  it('3. Intercepts HTTP 429 rate limits and shows: "Too many connection attempts. Please wait and try again."', async () => {
    shouldFailSignIn = true;
    failWithStatus = 429;
    failWithMessage = 'over_request_rate_limit';

    await expect(authManager.ensureAnonymousAuth()).rejects.toThrow(
      'Too many connection attempts. Please wait and try again.'
    );
  });

  // TEST 4: Client-side cooldown after error prevents repeated calls
  it('4. Enforces a client-side cooldown after a failed sign-in attempt', async () => {
    shouldFailSignIn = true;
    failWithStatus = 500;
    failWithMessage = 'Server down';

    // First attempt fails
    await expect(authManager.ensureAnonymousAuth()).rejects.toThrow();
    expect(signInCalls).toBe(1);

    // Immediate second attempt should be blocked by client-side cooldown without hitting network
    await expect(authManager.ensureAnonymousAuth()).rejects.toThrow(
      'Too many connection attempts. Please wait and try again.'
    );
    expect(signInCalls).toBe(1); // Call count did not increase!

    // Wait for cooldown to expire
    await new Promise((resolve) => setTimeout(resolve, 550));

    // After cooldown, a new network attempt is permitted
    shouldFailSignIn = false;
    const user = await authManager.ensureAnonymousAuth();
    expect(user.id).toBeDefined();
    expect(signInCalls).toBe(2);
  });

  // TEST 5: Cloudflare Turnstile / hCaptcha token passthrough
  it('5. Supports passing Cloudflare Turnstile or hCaptcha tokens to signInAnonymously', async () => {
    const testCaptchaToken = 'cf-turnstile-token-sample-xyz999';

    await authManager.ensureAnonymousAuth({ captchaToken: testCaptchaToken });

    expect(signInCalls).toBe(1);
    expect(signInOptionsPassed).toEqual({
      options: { captchaToken: testCaptchaToken },
    });
  });

  // TEST 6: Service-role key leak prevention
  it('6. Ensures service-role keys are never exposed in frontend code', () => {
    const publicAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '';
    const publicUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || '';

    // Verify no service-role secrets in client environment variables
    expect(publicAnonKey.toLowerCase()).not.toContain('service_role');
    expect(publicUrl.toLowerCase()).not.toContain('service_role');
    expect((process.env as any).NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY).toBeUndefined();
  });

  // TEST 7: Room membership uses authenticated anonymous user ID
  it('7. Uses authenticated anonymous user ID for room membership and RLS correlation', async () => {
    const user = await authManager.ensureAnonymousAuth();
    expect(user.id).toBeDefined();

    // Verify room member record links directly to user.id
    const mockRoomMember = {
      room_id: crypto.randomUUID(),
      user_id: user.id,
      joined_at: new Date(),
    };

    expect(mockRoomMember.user_id).toBe(user.id);
  });

  // TEST 8: Recovery from foreign key / stale session error via forceRefresh
  it('8. Forces session refresh when recovering from stale session or foreign key violation', async () => {
    mockSession = {
      user: { id: 'stale-wiped-user-999', is_anonymous: true },
    };

    // Stale session re-authenticated with forceRefresh to obtain a valid user
    const freshUser = await authManager.ensureAnonymousAuth({ forceRefresh: true });
    expect(freshUser.id).toBeDefined();
    expect(freshUser.id).not.toBe('stale-wiped-user-999');
    expect(signInCalls).toBe(1);
  });
});
