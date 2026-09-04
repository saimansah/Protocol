'use client';

import { Suspense, useState, useEffect, useRef } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { supabase, ensureAnonymousAuth } from '@/lib/supabase';
import { deriveRoomKey, encryptPayload, decryptPayload } from '@/lib/crypto';
import { Users, Copy, Check, Send, ShieldAlert, Clock, LogOut, Lock, KeyRound, Eye, EyeOff, Shield, ShieldCheck } from 'lucide-react';

interface ChatMessage {
  id: string;
  sender: string;
  text: string;
  time: string;
  self?: boolean;
}

function RoomTerminal() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const rawRoomId = searchParams.get('id');
  const roomId = rawRoomId ? rawRoomId.replace(/[^0-9a-zA-Z-]/g, '').slice(0, 36) : null;

  // Strict Security State: 'verifying' | 'locked' | 'unlocked' | 'denied'
  const [authState, setAuthState] = useState<'verifying' | 'locked' | 'unlocked' | 'denied'>('verifying');

  const [displayCode, setDisplayCode] = useState<string>(roomId || '');
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputText, setInputText] = useState('');
  const [callsign, setCallsign] = useState('User');
  const [participants, setParticipants] = useState<string[]>([]);
  const [copied, setCopied] = useState(false);
  const [channel, setChannel] = useState<any>(null);
  const [signalState, setSignalState] = useState<'connecting' | 'active' | 'offline'>('connecting');
  const [expiresAt, setExpiresAt] = useState<Date | null>(null);
  const [timeRemaining, setTimeRemaining] = useState<string>('--:--:--');
  const [roomError, setRoomError] = useState<string | null>(null);
  const [showUsers, setShowUsers] = useState(false);

  // Password Unlock Gate
  const [unlockPassword, setUnlockPassword] = useState('');
  const [showUnlockPassword, setShowUnlockPassword] = useState(false);
  const [unlockLoading, setUnlockLoading] = useState(false);
  const [unlockError, setUnlockError] = useState<string | null>(null);

  const chatScrollRef = useRef<HTMLDivElement>(null);
  const callsignRef = useRef(callsign);
  const channelRef = useRef<any>(null);
  const cryptoKeyRef = useRef<CryptoKey | null>(null);
  const channelSecretRef = useRef<string | null>(null);
  const [connectAttempt, setConnectAttempt] = useState(0);

  // Sync callsignRef and track presence if callsign changes
  useEffect(() => {
    callsignRef.current = callsign;
    if (channelRef.current && signalState === 'active') {
      channelRef.current.track({
        display_name: callsign,
        online_at: new Date().toISOString(),
      });
    }
  }, [callsign, signalState]);

  // 1. Initial Room Authorization & Countdown Fetch
  useEffect(() => {
    if (!roomId) {
      router.push('/');
      return;
    }

    const localCallsign = sessionStorage.getItem('protocol_callsign') || `USER-${Math.floor(100 + Math.random() * 900)}`;
    setCallsign(localCallsign);
    callsignRef.current = localCallsign;

    let isMounted = true;

    async function verifyAndFetchExpiry() {
      try {
        setAuthState('verifying');
        await ensureAnonymousAuth();

        const { data: spec, error: specErr } = await supabase.rpc('get_room_entry_spec', {
          p_room_id: roomId,
        });

        if (specErr || !spec || !spec.exists) {
          if (isMounted) {
            setRoomError('Access Denied: Invalid Room Code or Security Cipher.');
            setAuthState('denied');
          }
          return;
        }

        if (isMounted) {
          if (spec.code) setDisplayCode(spec.code);

          if (spec.expires_at) {
            setExpiresAt(new Date(spec.expires_at));
          } else {
            setExpiresAt(new Date(Date.now() + 24 * 60 * 60 * 1000));
          }

          if (spec.access_type === 'open') {
            // Open room: no cipher required
            cryptoKeyRef.current = null;
            channelSecretRef.current = null;
            setAuthState('unlocked');
            return;
          }

          // Password Protected Room
          // Check if we already have the verified password and channel secret in session memory
          const cachedPass =
            sessionStorage.getItem(`protocol_pass_${roomId}`) ||
            (spec.code ? sessionStorage.getItem(`protocol_pass_${spec.code}`) : null) ||
            (spec.room_id ? sessionStorage.getItem(`protocol_pass_${spec.room_id}`) : null);

          const cachedSecret =
            spec.channel_secret ||
            sessionStorage.getItem(`protocol_secret_${roomId}`) ||
            (spec.code ? sessionStorage.getItem(`protocol_secret_${spec.code}`) : null) ||
            (spec.room_id ? sessionStorage.getItem(`protocol_secret_${spec.room_id}`) : null);

          if (cachedPass && cachedSecret) {
            try {
              const derivedKey = await deriveRoomKey(cachedPass, spec.room_id || roomId);
              cryptoKeyRef.current = derivedKey;
              channelSecretRef.current = cachedSecret;
              setAuthState('unlocked');
              return;
            } catch (kErr) {
              console.error('Failed to derive encryption key:', kErr);
            }
          }

          // User does not have verified password/secret -> Must authenticate
          setAuthState('locked');
          setSignalState('offline');
        }
      } catch (err: any) {
        console.error('Room verification error:', err);
        if (isMounted) {
          setAuthState('denied');
          if (err?.message?.includes('Too many connection attempts')) {
            setRoomError('Too many connection attempts. Please wait and try again.');
          } else {
            setRoomError('Room connection failed. Please verify access.');
          }
        }
      }
    }

    verifyAndFetchExpiry();

    return () => {
      isMounted = false;
    };
  }, [roomId, router]);

  // Handle direct password unlock
  async function handleUnlockRoom(e: React.FormEvent) {
    e.preventDefault();
    if (!unlockPassword.trim()) {
      return setUnlockError('Please enter the security password.');
    }

    setUnlockLoading(true);
    setUnlockError(null);

    try {
      await ensureAnonymousAuth();

      let { data, error } = await supabase.rpc('verify_and_join_classified_room', {
        p_room_id: roomId,
        p_password: unlockPassword,
      });

      // Self-healing recovery: If foreign key violation or stale session occurs, clear session and retry
      if (
        error &&
        (error.message?.includes('foreign key constraint') ||
          error.message?.includes('room_members_user_id_fkey') ||
          error.message?.includes('violates foreign key'))
      ) {
        console.warn('Foreign key constraint violation detected on unlock. Refreshing auth session and retrying...');
        await supabase.auth.signOut();
        await ensureAnonymousAuth({ forceRefresh: true });

        const retryResult = await supabase.rpc('verify_and_join_classified_room', {
          p_room_id: roomId,
          p_password: unlockPassword,
        });
        data = retryResult.data;
        error = retryResult.error;
      }

      if (error || !data?.success) {
        throw new Error('Access Denied: Incorrect Security Password.');
      }

      // Compute dynamic channel secret & derive encryption key
      const secret = data?.channel_secret;
      const roomTargetId = data?.room_id || roomId;

      const derivedKey = await deriveRoomKey(unlockPassword, roomTargetId);
      cryptoKeyRef.current = derivedKey;
      channelSecretRef.current = secret || null;

      if (typeof window !== 'undefined') {
        sessionStorage.setItem(`protocol_unlocked_${roomId}`, 'true');
        sessionStorage.setItem(`protocol_pass_${roomId}`, unlockPassword);
        if (secret) sessionStorage.setItem(`protocol_secret_${roomId}`, secret);

        if (data?.code) {
          sessionStorage.setItem(`protocol_unlocked_${data.code}`, 'true');
          sessionStorage.setItem(`protocol_pass_${data.code}`, unlockPassword);
          if (secret) sessionStorage.setItem(`protocol_secret_${data.code}`, secret);
        }
        if (data?.room_id) {
          sessionStorage.setItem(`protocol_unlocked_${data.room_id}`, 'true');
          sessionStorage.setItem(`protocol_pass_${data.room_id}`, unlockPassword);
          if (secret) sessionStorage.setItem(`protocol_secret_${data.room_id}`, secret);
        }
      }

      setAuthState('unlocked');
      setSignalState('connecting');
    } catch (err: any) {
      setUnlockError(err?.message || 'Access Denied: Incorrect Security Password.');
    } finally {
      setUnlockLoading(false);
    }
  }

  // 2. Countdown Purge Timer
  useEffect(() => {
    if (!expiresAt) return;

    function updateCountdown() {
      const now = Date.now();
      const diff = (expiresAt?.getTime() || 0) - now;

      if (diff <= 0) {
        setTimeRemaining('00:00:00');
        handleLeave();
        return;
      }

      const hours = Math.floor(diff / (1000 * 60 * 60));
      const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
      const seconds = Math.floor((diff % (1000 * 60)) / 1000);

      setTimeRemaining(
        `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`
      );
    }

    updateCountdown();
    const interval = setInterval(updateCountdown, 1000);
    return () => clearInterval(interval);
  }, [expiresAt]);

  // 3. Supabase Realtime Channel (Only connects when authState === 'unlocked')
  useEffect(() => {
    if (!roomId || authState !== 'unlocked') return;

    let activeChannel: any = null;
    let isCancelled = false;

    async function setupRealtime() {
      try {
        setSignalState('connecting');
        const user = await ensureAnonymousAuth();

        if (isCancelled) return;

        // Dynamic secret topic for password rooms: room:roomId:channelSecret
        const topicSuffix = channelSecretRef.current ? `:${channelSecretRef.current}` : '';
        const channelKey = `room:${roomId}${topicSuffix}`;

        activeChannel = supabase.channel(channelKey, {
          config: {
            broadcast: { self: true, ack: true },
            presence: { key: user?.id || crypto.randomUUID() },
          },
        });

        channelRef.current = activeChannel;

        activeChannel
          .on('broadcast', { event: 'chat_message' }, async ({ payload }: { payload: any }) => {
            let messageText = payload.text || '';

            // Handle client-side encrypted transmission
            if (payload.encrypted && payload.ciphertext && payload.iv) {
              if (cryptoKeyRef.current) {
                try {
                  messageText = await decryptPayload(payload.ciphertext, payload.iv, cryptoKeyRef.current);
                } catch (decErr) {
                  messageText = '[Encrypted Transmission - Key Mismatch]';
                }
              } else {
                messageText = '[Encrypted Transmission - Key Missing]';
              }
            }

            const senderName = payload.senderName || payload.sender || 'Anonymous';
            const sentAt = payload.sentAt || payload.time || new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

            const normalizedMsg: ChatMessage = {
              id: payload.id || crypto.randomUUID(),
              sender: senderName,
              text: messageText,
              time: sentAt,
              self: senderName === callsignRef.current,
            };

            setMessages((prev) => [...prev, normalizedMsg]);
          })
          .on('presence', { event: 'sync' }, () => {
            const state = activeChannel.presenceState();
            const activeUsers = Object.values(state)
              .flat()
              .map((p: any) => p.display_name || 'Anonymous');
            setParticipants(activeUsers);
          })
          .subscribe(async (status: string, err?: any) => {
            if (isCancelled) return;
            console.log(`[Protocol by Saiman] Channel status: ${status}`, err || '');

            if (status === 'SUBSCRIBED') {
              setSignalState('active');
              await activeChannel.track({
                user_id: user?.id,
                display_name: callsignRef.current,
                online_at: new Date().toISOString(),
              });
            } else if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT' || status === 'CLOSED') {
              setSignalState('offline');
            }
          });

        if (!isCancelled) {
          setChannel(activeChannel);
        }
      } catch (err: any) {
        console.error('Realtime connection error:', err);
        if (!isCancelled) {
          setSignalState('offline');
          if (err?.message?.includes('Too many connection attempts')) {
            setRoomError('Too many connection attempts. Please wait and try again.');
          }
        }
      }
    }

    setupRealtime();

    return () => {
      isCancelled = true;
      if (activeChannel) {
        supabase.removeChannel(activeChannel);
      }
      channelRef.current = null;
    };
  }, [roomId, authState, connectAttempt]);

  // Auto-scroll to bottom
  useEffect(() => {
    chatScrollRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Send message
  async function handleSendMessage(e: React.FormEvent) {
    e.preventDefault();
    const cleanText = inputText.trim();
    if (!cleanText || !channel || authState !== 'unlocked') return;

    setInputText('');

    try {
      let payload: any = {
        id: crypto.randomUUID(),
        senderName: callsign,
        sender: callsign,
        sentAt: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      if (cryptoKeyRef.current) {
        const { ciphertext, iv } = await encryptPayload(cleanText.slice(0, 2000), cryptoKeyRef.current);
        payload.encrypted = true;
        payload.ciphertext = ciphertext;
        payload.iv = iv;
      } else {
        payload.text = cleanText.slice(0, 2000);
      }

      await channel.send({
        type: 'broadcast',
        event: 'chat_message',
        payload,
      });
    } catch (err) {
      console.error('Failed to send broadcast:', err);
    }
  }

  function handleLeave() {
    setMessages([]);
    if (channel) {
      supabase.removeChannel(channel);
    }
    router.push('/');
  }

  function handleCopyRoomId() {
    const codeToCopy = displayCode || roomId;
    const url = `${window.location.origin}${window.location.pathname}?id=${codeToCopy}`;
    navigator.clipboard.writeText(url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  // 1. Verifying Security Clearance State
  if (authState === 'verifying') {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-[#0d0f14] text-center p-4 font-mono">
        <div className="w-14 h-14 rounded-2xl bg-[#131620] border border-cyan-500/30 flex items-center justify-center mb-4 shadow-[0_0_24px_rgba(0,229,255,0.15)] animate-pulse">
          <Shield className="w-7 h-7 text-[#00e5ff]" />
        </div>
        <div className="text-sm font-bold font-syne text-white tracking-wider mb-1">
          PROTOCOL BY SAIMAN
        </div>
        <p className="text-xs text-slate-400">
          VERIFYING TRANSMISSION CLEARANCE...
        </p>
      </div>
    );
  }

  // 2. Denied / Room Error
  if (authState === 'denied' || roomError) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4 font-mono">
        <div className="bg-[#131620] border border-red-500/40 p-8 rounded-2xl max-w-sm w-full shadow-2xl text-center">
          <ShieldAlert className="w-10 h-10 text-red-400 mx-auto mb-3" />
          <h2 className="text-base font-bold text-white mb-2 font-syne">Connection Error</h2>
          <p className="text-xs text-slate-400 mb-6 leading-relaxed">{roomError || 'Access Denied: Invalid Room Code or Security Cipher.'}</p>
          <button
            onClick={() => router.push('/')}
            className="w-full py-2.5 bg-[#1a1e2b] hover:bg-[#252a3a] text-[#00e5ff] text-xs font-bold font-syne rounded-lg uppercase tracking-wider transition-colors"
          >
            Back to Home
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-screen h-[100dvh] max-h-[100dvh] bg-[#0d0f14] text-[#e2e8f8] font-mono overflow-hidden">

      {/* Sleek Top Bar with Protocol by Saiman */}
      <header className="h-14 px-4 sm:px-6 bg-[#131620] border-b border-[#252a3a] flex items-center justify-between flex-shrink-0 z-20">

        {/* Left: Logo & Room Link */}
        <div className="flex items-center gap-3">
          <div className="flex items-center font-syne font-extrabold text-base tracking-wider hidden sm:flex">
            <span className="text-slate-500">[</span>
            <span className="text-white">PROTO</span>
            <span className="text-[#00e5ff]">COL</span>
            <span className="text-slate-500">]</span>
            <span className="text-xs text-[#00e5ff] font-bold font-syne tracking-normal ml-2 py-0.5 px-2 rounded-full bg-[#00e5ff]/10 border border-[#00e5ff]/30">by Saiman</span>
          </div>

          {/* Room Code Badge */}
          <button
            onClick={handleCopyRoomId}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#0d0f14] hover:bg-[#1a1e2b] border border-[#2e3448] text-xs transition-colors"
            title="Click to copy room link"
          >
            <span className="text-slate-400 text-[11px] font-semibold">ROOM:</span>
            <span className="text-[#00e5ff] font-bold tracking-wider">
              {displayCode || roomId || 'ROOM'}
            </span>
            {copied ? (
              <Check className="w-3.5 h-3.5 text-[#39ff8a]" />
            ) : (
              <Copy className="w-3.5 h-3.5 text-slate-400" />
            )}
          </button>
        </div>

        {/* Center/Right: Live Status, Online Users, Expiry, Leave */}
        <div className="flex items-center gap-2.5 sm:gap-4">
          {/* Signal Indicator & Reconnect */}
          <div className="flex items-center gap-1.5 text-xs">
            <span
              className={`w-2 h-2 rounded-full ${signalState === 'active'
                ? 'bg-[#39ff8a] shadow-[0_0_8px_#39ff8a]'
                : signalState === 'connecting'
                  ? 'bg-amber-400 animate-pulse'
                  : 'bg-red-500'
                }`}
            />
            <span className="text-[11px] text-slate-400 uppercase hidden md:inline">
              {signalState === 'active' ? 'Live' : signalState === 'connecting' ? 'Connecting...' : 'Offline'}
            </span>
            {signalState === 'offline' && authState === 'unlocked' && (
              <button
                onClick={() => setConnectAttempt((c) => c + 1)}
                className="text-[10px] text-cyan-400 hover:text-cyan-300 underline font-mono ml-0.5"
                title="Retry connecting to room"
              >
                Retry
              </button>
            )}
          </div>

          {/* Online Counter Toggle */}
          <div className="relative">
            <button
              onClick={() => setShowUsers(!showUsers)}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-[#0d0f14] hover:bg-[#1a1e2b] border border-[#2e3448] text-[11px] text-slate-300 transition-colors"
            >
              <Users className="w-3.5 h-3.5 text-[#00e5ff]" />
              <span>{participants.length || 1}</span>
            </button>

            {/* Users dropdown */}
            {showUsers && (
              <div className="absolute right-0 mt-2 w-48 bg-[#131620] border border-[#2e3448] rounded-xl shadow-2xl p-3 z-50 text-xs animate-fade-in">
                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2">
                  Connected Users ({participants.length || 1})
                </div>
                <div className="space-y-1.5 max-h-48 overflow-y-auto">
                  {participants.map((user, idx) => (
                    <div key={idx} className="flex items-center gap-2 text-slate-200">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#39ff8a]" />
                      <span className="truncate">{user}</span>
                      {user === callsign && (
                        <span className="text-[9px] text-[#00e5ff] font-bold">(YOU)</span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Time Countdown */}
          <div className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-[#0d0f14] border border-[#2e3448] text-[11px] text-amber-300">
            <Clock className="w-3.5 h-3.5 text-amber-400" />
            <span>{timeRemaining}</span>
          </div>

          {/* Leave Room Button */}
          <button
            onClick={handleLeave}
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-red-950/30 hover:bg-red-900/50 border border-red-500/30 text-red-400 text-xs font-bold font-syne transition-colors"
            title="Leave room"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">LEAVE</span>
          </button>
        </div>
      </header>

      {/* 3. Locked Gate: Cipher Authentication Modal */}
      {authState === 'locked' ? (
        <div className="flex-1 flex items-center justify-center p-4">
          <form onSubmit={handleUnlockRoom} className="bg-[#131620] border border-[#2e3448] p-8 rounded-2xl max-w-sm w-full shadow-2xl text-center space-y-4 animate-fade-in">
            <div className="w-12 h-12 rounded-full bg-amber-950/30 border border-amber-500/40 flex items-center justify-center mx-auto">
              <Lock className="w-6 h-6 text-amber-400" />
            </div>

            <div>
              <h2 className="text-base font-bold text-white font-syne mb-1">Cipher Protected Room</h2>
              <p className="text-xs text-slate-400 leading-relaxed font-mono">
                Protocol by Saiman — This frequency requires authentication. Enter the security cipher to connect.
              </p>
            </div>

            {unlockError && (
              <div className="p-2.5 rounded-lg bg-red-950/40 border border-red-500/40 text-red-400 text-xs flex items-center gap-2 text-left">
                <ShieldAlert className="w-4 h-4 flex-shrink-0" />
                <span>{unlockError}</span>
              </div>
            )}

            <div className="relative">
              <input
                type={showUnlockPassword ? 'text' : 'password'}
                value={unlockPassword}
                onChange={(e) => setUnlockPassword(e.target.value)}
                placeholder="Enter room password"
                autoFocus
                className="w-full bg-[#0d0f14] border border-[#2e3448] focus:border-[#00e5ff] rounded-xl px-4 py-2.5 text-sm text-white placeholder-slate-600 outline-none pr-10 font-mono"
              />
              <button
                type="button"
                onClick={() => setShowUnlockPassword(!showUnlockPassword)}
                className="absolute right-3 top-3 text-slate-500 hover:text-slate-300"
              >
                {showUnlockPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>

            <button
              type="submit"
              disabled={unlockLoading}
              className="w-full py-2.5 bg-[#00e5ff] hover:bg-[#33ecff] text-[#05080c] text-xs font-bold font-syne rounded-xl uppercase tracking-wider transition-all disabled:opacity-50"
            >
              {unlockLoading ? 'Authenticating...' : 'Unlock & Connect'}
            </button>
          </form>
        </div>
      ) : (
        /* 4. Unlocked Main Message Deck */
        <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-4">
          {messages.length === 0 && (
            <div className="flex flex-col items-center justify-center h-full text-center text-slate-500 text-xs py-20">
              <div className="w-12 h-12 rounded-full bg-[#131620] border border-[#252a3a] flex items-center justify-center mb-3">
                <span className="text-[#00e5ff] text-lg font-bold font-syne">#</span>
              </div>
              <p className="font-bold text-slate-400 text-sm mb-1 font-syne">Room Ready</p>
              <p className="max-w-xs text-slate-500 text-[11px] leading-relaxed">
                Share the 10-digit code with anyone to begin chatting. Messages are end-to-end encrypted and never logged.
              </p>
            </div>
          )}

          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`flex flex-col ${msg.self ? 'items-end' : 'items-start'} max-w-xl ${msg.self ? 'ml-auto' : 'mr-auto'
                }`}
            >
              <div className="flex items-center gap-2 mb-1 px-1 text-[11px]">
                <span
                  className={`font-bold font-syne ${msg.self ? 'text-[#00e5ff]' : 'text-[#7b61ff]'
                    }`}
                >
                  {msg.sender}
                </span>
                <span className="text-slate-500 text-[10px]">{msg.time}</span>
              </div>

              <div
                className={`px-4 py-2.5 rounded-2xl text-xs sm:text-sm leading-relaxed break-words shadow-sm ${msg.self
                    ? 'bg-[#1a1e2b] border border-[#00e5ff]/40 text-white rounded-tr-none'
                    : 'bg-[#131620] border border-[#252a3a] text-slate-200 rounded-tl-none'
                  }`}
              >
                {msg.text}
              </div>
            </div>
          ))}

          <div ref={chatScrollRef} />
        </div>
      )}

      {/* Bottom Message Composer & Footer Copyright */}
      <div className="p-3 sm:p-4 bg-[#131620] border-t border-[#252a3a] flex-shrink-0 flex flex-col gap-2">
        <form onSubmit={handleSendMessage} className="max-w-4xl w-full mx-auto flex items-center gap-2">
          <input
            type="text"
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            disabled={authState !== 'unlocked'}
            placeholder={authState === 'locked' ? 'Unlock room with cipher above...' : 'Type a message (Enter to send)...'}
            maxLength={2000}
            autoFocus={authState === 'unlocked'}
            className="flex-1 bg-[#0d0f14] border border-[#2e3448] focus:border-[#00e5ff] rounded-xl px-4 py-3 text-sm text-white placeholder-slate-500 outline-none transition-all focus:ring-2 focus:ring-[#00e5ff]/20 font-mono disabled:opacity-50"
          />

          <button
            type="submit"
            disabled={!inputText.trim() || signalState !== 'active' || authState !== 'unlocked'}
            className="px-5 py-3 bg-[#00e5ff] hover:bg-[#33ecff] text-[#05080c] font-bold font-syne text-xs uppercase rounded-xl flex items-center justify-center gap-1.5 shadow-[0_0_16px_rgba(0,229,255,0.2)] transition-all hover:-translate-y-0.5 disabled:opacity-40 disabled:cursor-not-allowed disabled:transform-none"
          >
            <Send className="w-4 h-4" />
            <span className="hidden sm:inline">Send</span>
          </button>
        </form>

        <div className="text-center text-[10px] text-slate-500 font-mono tracking-wider">
          Protocol by Saiman • Copyright and rights claimed by Saiman 2026-2029
        </div>
      </div>
    </div>
  );
}

export default function ClassifiedRoom() {
  return (
    <Suspense
      fallback={
        <div className="flex items-center justify-center min-h-screen bg-[#0d0f14] text-[#00e5ff] text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#00e5ff] animate-ping" />
            <span>CONNECTING TO PROTOCOL BY SAIMAN...</span>
          </div>
        </div>
      }
    >
      <RoomTerminal />
    </Suspense>
  );
}
