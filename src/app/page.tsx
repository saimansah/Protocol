'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { supabase, ensureAnonymousAuth, getAuthCooldownRemaining } from '@/lib/supabase';
import { CaptchaWidget } from '@/lib/captcha';
import { Shield, Lock, ArrowRight, ShieldAlert, Clock, Eye, EyeOff } from 'lucide-react';

export default function Home() {
  const router = useRouter();
  const [mode, setMode] = useState<'join' | 'create'>('join');
  const [displayName, setDisplayName] = useState('');

  // Join Room State
  const [joinRoomId, setJoinRoomId] = useState('');
  const [joinPassword, setJoinPassword] = useState('');
  const [joinRequiresPass, setJoinRequiresPass] = useState(false);
  const [showJoinPassword, setShowJoinPassword] = useState(false);

  // Create Room State
  const [customRoomCode, setCustomRoomCode] = useState('');
  const [createType, setCreateType] = useState<'open' | 'password'>('open');
  const [createPassword, setCreatePassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showCreatePassword, setShowCreatePassword] = useState(false);

  // Global Auth / Request State
  const [loading, setLoading] = useState(false);
  const [authStatus, setAuthStatus] = useState<'connecting' | 'connected' | 'error'>('connecting');
  const [error, setError] = useState<string | null>(null);
  const [cooldown, setCooldown] = useState<number>(0);
  const [captchaToken, setCaptchaToken] = useState<string | undefined>(undefined);

  // Initialize Anonymous Session once on mount
  useEffect(() => {
    let isMounted = true;

    ensureAnonymousAuth()
      .then(() => {
        if (isMounted) {
          setAuthStatus('connected');
          setError(null);
        }
      })
      .catch((err) => {
        if (!isMounted) return;
        console.error('Anonymous auth init error:', err);
        setAuthStatus('error');
        if (err?.message?.includes('Too many connection attempts')) {
          setError('Too many connection attempts. Please wait and try again.');
          setCooldown(getAuthCooldownRemaining());
        } else if (err?.message) {
          setError(err.message);
        } else {
          setError('Terminal authentication offline. Verify network connection.');
        }
      });

    const cachedName = sessionStorage.getItem('protocol_callsign');
    if (cachedName) {
      setDisplayName(cachedName);
    } else {
      const defaultCallsign = `USER-${Math.floor(100 + Math.random() * 900)}`;
      setDisplayName(defaultCallsign);
    }

    return () => {
      isMounted = false;
    };
  }, []);

  // Cooldown countdown timer
  useEffect(() => {
    if (cooldown <= 0) return;
    const interval = setInterval(() => {
      const remaining = getAuthCooldownRemaining();
      setCooldown(remaining);
      if (remaining <= 0) {
        clearInterval(interval);
        if (error === 'Too many connection attempts. Please wait and try again.') {
          setError(null);
        }
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [cooldown, error]);

  function extractCleanRoomId(input: string): string {
    const trimmed = input.trim();
    if (trimmed.includes('?id=')) {
      const parts = trimmed.split('?id=');
      return parts[1].split('&')[0].replace(/[^0-9a-zA-Z-]/g, '').slice(0, 36);
    }
    if (trimmed.includes('/room/')) {
      const parts = trimmed.split('/room/');
      return parts[1].replace(/[^0-9a-zA-Z-]/g, '').slice(0, 36);
    }
    return trimmed.replace(/[^0-9a-zA-Z-]/g, '').slice(0, 36);
  }

  async function handleJoin(e: React.FormEvent) {
    e.preventDefault();
    if (cooldown > 0) {
      return setError('Too many connection attempts. Please wait and try again.');
    }

    const cleanRoomId = extractCleanRoomId(joinRoomId);
    if (!cleanRoomId) {
      return setError('Please enter a 10-digit Room Code or link.');
    }

    const finalName = displayName.trim() || `USER-${Math.floor(100 + Math.random() * 900)}`;

    setLoading(true);
    setError(null);

    try {
      await ensureAnonymousAuth({ captchaToken });
      sessionStorage.setItem('protocol_callsign', finalName);

      const { data: spec, error: specErr } = await supabase.rpc('get_room_entry_spec', {
        p_room_id: cleanRoomId,
      });

      if (specErr || !spec || !spec.exists) {
        throw new Error('Access Denied: Invalid Room Code or Security Cipher.');
      }

      if (spec.access_type === 'password' && !joinRequiresPass) {
        setJoinRequiresPass(true);
        setLoading(false);
        return;
      }

      if (joinRequiresPass && (!joinPassword || joinPassword.trim().length === 0)) {
        throw new Error('Please enter the Security Cipher to access this room.');
      }

      let { data, error: joinErr } = await supabase.rpc('verify_and_join_classified_room', {
        p_room_id: cleanRoomId,
        p_password: joinRequiresPass ? joinPassword : null,
      });

      // Self-healing recovery: If foreign key violation or stale session occurs, clear session and retry
      if (
        joinErr &&
        (joinErr.message?.includes('foreign key constraint') ||
          joinErr.message?.includes('room_members_user_id_fkey') ||
          joinErr.message?.includes('violates foreign key'))
      ) {
        console.warn('Foreign key constraint violation detected on join. Refreshing auth session and retrying...');
        await supabase.auth.signOut();
        await ensureAnonymousAuth({ forceRefresh: true });

        const retryResult = await supabase.rpc('verify_and_join_classified_room', {
          p_room_id: cleanRoomId,
          p_password: joinRequiresPass ? joinPassword : null,
        });
        data = retryResult.data;
        joinErr = retryResult.error;
      }

      if (joinErr || !data?.success) {
        throw new Error('Access Denied: Invalid Room Code or Security Cipher.');
      }

      const targetDestination = data?.code || data?.room_id || cleanRoomId;
      if (typeof window !== 'undefined') {
        sessionStorage.setItem(`protocol_unlocked_${targetDestination}`, 'true');
        if (data?.code) sessionStorage.setItem(`protocol_unlocked_${data.code}`, 'true');
        if (data?.room_id) sessionStorage.setItem(`protocol_unlocked_${data.room_id}`, 'true');
        sessionStorage.setItem(`protocol_unlocked_${cleanRoomId}`, 'true');

        if (data?.channel_secret) {
          sessionStorage.setItem(`protocol_secret_${targetDestination}`, data.channel_secret);
          if (data?.code) sessionStorage.setItem(`protocol_secret_${data.code}`, data.channel_secret);
          if (data?.room_id) sessionStorage.setItem(`protocol_secret_${data.room_id}`, data.channel_secret);
        }
        if (joinPassword) {
          sessionStorage.setItem(`protocol_pass_${targetDestination}`, joinPassword);
          if (data?.code) sessionStorage.setItem(`protocol_pass_${data.code}`, joinPassword);
          if (data?.room_id) sessionStorage.setItem(`protocol_pass_${data.room_id}`, joinPassword);
        }
      }
      router.push(`/room/?id=${targetDestination}`);
    } catch (err: any) {
      if (err?.message?.includes('Too many connection attempts')) {
        setError('Too many connection attempts. Please wait and try again.');
        setCooldown(getAuthCooldownRemaining());
      } else {
        setError(err.message || 'Access Denied: Invalid Room Code or Security Cipher.');
      }
    } finally {
      setLoading(false);
    }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (cooldown > 0) {
      return setError('Too many connection attempts. Please wait and try again.');
    }

    const finalName = displayName.trim() || `USER-${Math.floor(100 + Math.random() * 900)}`;

    // Validate custom room code if provided
    const cleanCustomCode = customRoomCode.trim();
    if (cleanCustomCode) {
      if (!/^\d{1,10}$/.test(cleanCustomCode)) {
        return setError('Room code must be a number with up to 10 digits.');
      }
    }

    if (createType === 'password') {
      if (createPassword.length < 8) {
        return setError('Security Cipher must contain at least 8 characters.');
      }
      if (createPassword !== confirmPassword) {
        return setError('Security Ciphers do not match.');
      }
    }

    setLoading(true);
    setError(null);

    try {
      await ensureAnonymousAuth({ captchaToken });
      sessionStorage.setItem('protocol_callsign', finalName);

      let { data, error: rpcErr } = await supabase.rpc('create_classified_room', {
        p_access_type: createType,
        p_password: createType === 'password' ? createPassword : null,
        p_room_code: cleanCustomCode || null,
      });

      // Self-healing recovery: If foreign key violation or stale session occurs, clear session and retry
      if (
        rpcErr &&
        (rpcErr.message?.includes('foreign key constraint') ||
          rpcErr.message?.includes('rooms_created_by_fkey') ||
          rpcErr.message?.includes('violates foreign key'))
      ) {
        console.warn('Foreign key constraint violation detected (stale auth token). Refreshing auth session and retrying...');
        await supabase.auth.signOut();
        await ensureAnonymousAuth({ forceRefresh: true });

        const retryResult = await supabase.rpc('create_classified_room', {
          p_access_type: createType,
          p_password: createType === 'password' ? createPassword : null,
          p_room_code: cleanCustomCode || null,
        });
        data = retryResult.data;
        rpcErr = retryResult.error;
      }

      if (rpcErr || (!data?.code && !data?.room_id)) {
        throw new Error(rpcErr?.message || 'Room creation failed.');
      }

      const targetDestination = data?.code || data?.room_id;
      if (typeof window !== 'undefined') {
        sessionStorage.setItem(`protocol_unlocked_${targetDestination}`, 'true');
        if (data?.code) sessionStorage.setItem(`protocol_unlocked_${data.code}`, 'true');
        if (data?.room_id) sessionStorage.setItem(`protocol_unlocked_${data.room_id}`, 'true');
        if (cleanCustomCode) sessionStorage.setItem(`protocol_unlocked_${cleanCustomCode}`, 'true');

        if (data?.channel_secret) {
          sessionStorage.setItem(`protocol_secret_${targetDestination}`, data.channel_secret);
          if (data?.code) sessionStorage.setItem(`protocol_secret_${data.code}`, data.channel_secret);
          if (data?.room_id) sessionStorage.setItem(`protocol_secret_${data.room_id}`, data.channel_secret);
        }
        if (createPassword) {
          sessionStorage.setItem(`protocol_pass_${targetDestination}`, createPassword);
          if (data?.code) sessionStorage.setItem(`protocol_pass_${data.code}`, createPassword);
          if (data?.room_id) sessionStorage.setItem(`protocol_pass_${data.room_id}`, createPassword);
        }
      }
      router.push(`/room/?id=${targetDestination}`);
    } catch (err: any) {
      if (err?.message?.includes('Too many connection attempts')) {
        setError('Too many connection attempts. Please wait and try again.');
        setCooldown(getAuthCooldownRemaining());
      } else {
        setError(err.message || 'Operation failed.');
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="min-h-screen flex items-center justify-center p-4 relative font-mono">
      {/* Background Grid */}
      <div className="bg-grid" />

      {/* Centered Join Card — ipchat.in style */}
      <div className="relative z-10 w-full max-w-[420px] bg-[#131620] border border-[#2e3448] rounded-2xl p-8 sm:p-9 shadow-[0_0_60px_rgba(0,229,255,0.06),0_24px_48px_rgba(0,0,0,0.5)] animate-fade-in">
        
        {/* Logo with Protocol by Saiman */}
        <div className="flex items-center justify-between mb-1">
          <div className="flex items-center font-syne text-2xl font-extrabold tracking-wider">
            <span className="text-slate-600 font-normal">[</span>
            <span className="text-white">PROTO</span>
            <span className="text-[#00e5ff]">COL</span>
            <span className="text-slate-600 font-normal">]</span>
            <span className="text-xs text-[#00e5ff] font-bold font-syne tracking-normal ml-2 py-0.5 px-2 rounded-full bg-[#00e5ff]/10 border border-[#00e5ff]/30">by Saiman</span>
          </div>
          <span className="text-[10px] text-cyan-400 font-mono tracking-widest bg-cyan-950/40 border border-cyan-500/30 px-2 py-0.5 rounded">
            594
          </span>
        </div>

        {/* Subtitle */}
        <p className="text-slate-400 text-xs mb-6">
          Protocol by Saiman — {mode === 'join' ? 'Enter a 10-digit room code to join' : 'Choose a 10-digit room code or auto-generate'}
        </p>

        {/* Mode Selector Tabs */}
        <div className="flex rounded-lg bg-[#0d0f14] p-1 border border-[#252a3a] mb-6">
          <button
            type="button"
            onClick={() => {
              setMode('join');
              setError(null);
            }}
            className={`flex-1 py-2 text-xs font-bold font-syne uppercase rounded-md transition-all ${mode === 'join'
              ? 'bg-[#1a1e2b] text-[#00e5ff] shadow-sm'
              : 'text-slate-500 hover:text-slate-300'
              }`}
          >
            Join Room
          </button>
          <button
            type="button"
            onClick={() => {
              setMode('create');
              setError(null);
            }}
            className={`flex-1 py-2 text-xs font-bold font-syne uppercase rounded-md transition-all ${mode === 'create'
              ? 'bg-[#1a1e2b] text-[#00e5ff] shadow-sm'
              : 'text-slate-500 hover:text-slate-300'
              }`}
          >
            Create Room
          </button>
        </div>

        {/* Error / Cooldown Banner */}
        {error && (
          <div className="mb-5 p-3 rounded-lg bg-red-950/40 border border-red-500/40 text-red-300 text-xs flex items-start justify-between gap-2">
            <div className="flex items-start gap-2">
              <ShieldAlert className="w-4 h-4 flex-shrink-0 text-red-400 mt-0.5" />
              <span>{error}</span>
            </div>
            {cooldown > 0 && (
              <div className="flex items-center gap-1 text-[11px] font-mono text-amber-400 bg-amber-950/50 px-2 py-0.5 rounded border border-amber-500/30 whitespace-nowrap">
                <Clock className="w-3 h-3 animate-spin" />
                <span>{cooldown}s</span>
              </div>
            )}
          </div>
        )}

        {/* Form */}
        <form onSubmit={mode === 'join' ? handleJoin : handleCreate} className="space-y-4">

          {/* USERNAME / CALLSIGN */}
          <div className="flex flex-col gap-1.5">
            <label className="text-[10px] font-bold text-slate-400 tracking-wider uppercase">
              Username
            </label>
            <input
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. alice or USER-118"
              maxLength={25}
              autoComplete="off"
              className="bg-[#0d0f14] border border-[#2e3448] focus:border-[#00e5ff] rounded-lg px-3.5 py-2.5 text-sm text-white placeholder-slate-600 outline-none transition-all focus:ring-2 focus:ring-[#00e5ff]/20 font-mono"
            />
          </div>

          {/* JOIN MODE INPUTS */}
          {mode === 'join' && (
            <>
              <div className="flex flex-col gap-1.5">
                <label className="text-[10px] font-bold text-slate-400 tracking-wider uppercase">
                  Room Code (10-Digit Number or Link)
                </label>
                <input
                  type="text"
                  value={joinRoomId}
                  onChange={(e) => {
                    setJoinRoomId(e.target.value);
                    setJoinRequiresPass(false);
                  }}
                  placeholder="e.g. 8472910482"
                  autoComplete="off"
                  className="bg-[#0d0f14] border border-[#2e3448] focus:border-[#00e5ff] rounded-lg px-3.5 py-2.5 text-sm text-white placeholder-slate-600 outline-none transition-all focus:ring-2 focus:ring-[#00e5ff]/20 font-mono"
                />
                <span className="text-[11px] text-slate-500 leading-tight">
                  Anyone who enters the same room code will share this room
                </span>
              </div>

              {joinRequiresPass && (
                <div className="flex flex-col gap-1.5 animate-fade-in">
                  <label className="text-[10px] font-bold text-amber-400 tracking-wider uppercase flex items-center gap-1">
                    <Lock className="w-3 h-3" /> Security Cipher Required
                  </label>
                  <div className="relative">
                    <input
                      type={showJoinPassword ? 'text' : 'password'}
                      value={joinPassword}
                      onChange={(e) => setJoinPassword(e.target.value)}
                      placeholder="Enter room password"
                      autoFocus
                      className="w-full bg-[#0d0f14] border border-amber-500/50 focus:border-amber-400 rounded-lg px-3.5 py-2.5 text-sm text-white placeholder-slate-600 outline-none pr-10 font-mono"
                    />
                    <button
                      type="button"
                      onClick={() => setShowJoinPassword(!showJoinPassword)}
                      className="absolute right-3 top-3 text-slate-500 hover:text-slate-300"
                    >
                      {showJoinPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
              )}
            </>
          )}

          {/* CREATE MODE INPUTS */}
          {mode === 'create' && (
            <>
              {/* USER DECIDED 10-DIGIT ROOM CODE */}
              <div className="flex flex-col gap-1.5">
                <label className="text-[10px] font-bold text-slate-400 tracking-wider uppercase flex items-center justify-between">
                  <span>Room Code (Optional)</span>
                  <span className="text-[10px] text-cyan-400/80 font-mono">max 10 digits</span>
                </label>
                <input
                  type="text"
                  value={customRoomCode}
                  onChange={(e) => setCustomRoomCode(e.target.value.replace(/\D/g, '').slice(0, 10))}
                  placeholder="e.g. 8472910482 (or leave empty to auto-generate)"
                  maxLength={10}
                  autoComplete="off"
                  className="bg-[#0d0f14] border border-[#2e3448] focus:border-[#00e5ff] rounded-lg px-3.5 py-2.5 text-sm text-white placeholder-slate-600 outline-none transition-all focus:ring-2 focus:ring-[#00e5ff]/20 font-mono tracking-wider"
                />
                <span className="text-[11px] text-slate-500 leading-tight">
                  Choose a custom 10-digit number, or leave blank to auto-generate
                </span>
              </div>

              <div className="flex flex-col gap-1.5">
                <label className="text-[10px] font-bold text-slate-400 tracking-wider uppercase">
                  Room Security
                </label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setCreateType('open')}
                    className={`py-2 px-3 text-xs font-semibold rounded-lg border transition-all text-center ${createType === 'open'
                      ? 'border-[#00e5ff] bg-[#00e5ff]/10 text-[#00e5ff]'
                      : 'border-[#2e3448] text-slate-400 hover:border-slate-600'
                      }`}
                  >
                    Open
                  </button>
                  <button
                    type="button"
                    onClick={() => setCreateType('password')}
                    className={`py-2 px-3 text-xs font-semibold rounded-lg border transition-all text-center ${createType === 'password'
                      ? 'border-[#00e5ff] bg-[#00e5ff]/10 text-[#00e5ff]'
                      : 'border-[#2e3448] text-slate-400 hover:border-slate-600'
                      }`}
                  >
                    Password Protected
                  </button>
                </div>
              </div>

              {createType === 'password' && (
                <div className="space-y-3 pt-1 animate-fade-in">
                  <div className="flex flex-col gap-1.5">
                    <label className="text-[10px] font-bold text-slate-400 tracking-wider uppercase">
                      Cipher Password (≥ 8 chars)
                    </label>
                    <div className="relative">
                      <input
                        type={showCreatePassword ? 'text' : 'password'}
                        value={createPassword}
                        onChange={(e) => setCreatePassword(e.target.value)}
                        placeholder="Enter password"
                        className="w-full bg-[#0d0f14] border border-[#2e3448] focus:border-[#00e5ff] rounded-lg px-3.5 py-2.5 text-sm text-white placeholder-slate-600 outline-none pr-10 font-mono"
                      />
                      <button
                        type="button"
                        onClick={() => setShowCreatePassword(!showCreatePassword)}
                        className="absolute right-3 top-3 text-slate-500 hover:text-slate-300"
                      >
                        {showCreatePassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  <div className="flex flex-col gap-1.5">
                    <label className="text-[10px] font-bold text-slate-400 tracking-wider uppercase">
                      Confirm Password
                    </label>
                    <input
                      type={showCreatePassword ? 'text' : 'password'}
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      placeholder="Confirm password"
                      className="bg-[#0d0f14] border border-[#2e3448] focus:border-[#00e5ff] rounded-lg px-3.5 py-2.5 text-sm text-white placeholder-slate-600 outline-none font-mono"
                    />
                  </div>
                </div>
              )}
            </>
          )}

          {/* Optional Captcha */}
          <CaptchaWidget
            onVerify={(tok) => setCaptchaToken(tok)}
            onExpire={() => setCaptchaToken(undefined)}
          />

          {/* SUBMIT BUTTON */}
          <button
            type="submit"
            disabled={loading || cooldown > 0}
            className="w-full mt-4 py-3 bg-[#00e5ff] hover:bg-[#33ecff] text-[#05080c] font-bold font-syne tracking-wider text-sm rounded-lg flex items-center justify-center gap-2 shadow-[0_0_24px_rgba(0,229,255,0.25)] transition-all hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
          >
            <span>
              {loading
                ? 'CONNECTING...'
                : cooldown > 0
                  ? `COOLDOWN (${cooldown}s)`
                  : mode === 'join'
                    ? (joinRequiresPass ? 'VERIFY & ENTER' : 'CONNECT')
                    : 'CREATE ROOM'}
            </span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        {/* Footer info & Copyright Claim */}
        <div className="mt-6 pt-4 border-t border-[#252a3a] flex flex-col gap-2.5 text-[11px] text-slate-500">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span
                className={`w-2 h-2 rounded-full ${authStatus === 'connected'
                  ? 'bg-[#39ff8a] shadow-[0_0_8px_#39ff8a]'
                  : authStatus === 'connecting'
                    ? 'bg-amber-400 animate-pulse'
                    : 'bg-red-500'
                  }`}
              />
              <span className="text-[10px] tracking-wider uppercase text-slate-400">
                {authStatus === 'connected'
                  ? 'Network Ready'
                  : authStatus === 'connecting'
                    ? 'Connecting...'
                    : 'Offline'}
              </span>
            </div>

            <span className="text-[10px] text-slate-600 tracking-wider uppercase">
              24h Auto-Purge
            </span>
          </div>

          <div className="text-center pt-2 text-[10px] text-slate-500 font-mono border-t border-slate-800/40">
            Copyright and rights claimed by Saiman 2026-2029
          </div>
        </div>
      </div>
    </main>
  );
}
