'use client';

import React, { useEffect, useRef } from 'react';

interface CaptchaWidgetProps {
  onVerify: (token: string) => void;
  onError?: (error: any) => void;
  onExpire?: () => void;
  className?: string;
}

/**
 * Tactical Captcha Widget supporting Cloudflare Turnstile or hCaptcha.
 * Automatically activates if NEXT_PUBLIC_TURNSTILE_SITE_KEY or NEXT_PUBLIC_HCAPTCHA_SITE_KEY is provided.
 * If neither is configured, returns null with zero impact on the UX.
 */
export function CaptchaWidget({ onVerify, onError, onExpire, className = '' }: CaptchaWidgetProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const turnstileSiteKey = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY;
  const hcaptchaSiteKey = process.env.NEXT_PUBLIC_HCAPTCHA_SITE_KEY;

  useEffect(() => {
    if (!turnstileSiteKey && !hcaptchaSiteKey) return;

    if (turnstileSiteKey) {
      // Cloudflare Turnstile Integration
      const scriptId = 'cf-turnstile-script';
      let script = document.getElementById(scriptId) as HTMLScriptElement | null;

      if (!script) {
        script = document.createElement('script');
        script.id = scriptId;
        script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
        script.async = true;
        script.defer = true;
        document.head.appendChild(script);
      }

      const interval = setInterval(() => {
        if ((window as any).turnstile && containerRef.current) {
          clearInterval(interval);
          try {
            (window as any).turnstile.render(containerRef.current, {
              sitekey: turnstileSiteKey,
              theme: 'dark',
              callback: (token: string) => onVerify(token),
              'error-callback': (err: any) => onError && onError(err),
              'expired-callback': () => onExpire && onExpire(),
            });
          } catch (e) {
            console.error('Turnstile render error:', e);
          }
        }
      }, 100);

      return () => clearInterval(interval);
    }

    if (hcaptchaSiteKey) {
      // hCaptcha Integration
      const scriptId = 'hcaptcha-script';
      let script = document.getElementById(scriptId) as HTMLScriptElement | null;

      if (!script) {
        script = document.createElement('script');
        script.id = scriptId;
        script.src = 'https://js.hcaptcha.com/1/api.js?render=explicit';
        script.async = true;
        script.defer = true;
        document.head.appendChild(script);
      }

      const interval = setInterval(() => {
        if ((window as any).hcaptcha && containerRef.current) {
          clearInterval(interval);
          try {
            (window as any).hcaptcha.render(containerRef.current, {
              sitekey: hcaptchaSiteKey,
              theme: 'dark',
              callback: (token: string) => onVerify(token),
              'error-callback': (err: any) => onError && onError(err),
              'expired-callback': () => onExpire && onExpire(),
            });
          } catch (e) {
            console.error('hCaptcha render error:', e);
          }
        }
      }, 100);

      return () => clearInterval(interval);
    }
  }, [turnstileSiteKey, hcaptchaSiteKey, onVerify, onError, onExpire]);

  if (!turnstileSiteKey && !hcaptchaSiteKey) {
    return null;
  }

  return (
    <div className={`flex flex-col items-center justify-center my-3 p-2 bg-terminal-panel/60 border border-terminal-border rounded ${className}`}>
      <div className="text-[10px] text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 rounded-full bg-tactical-cyan animate-ping"></span>
        Cryptographic Proof of Human Interaction
      </div>
      <div ref={containerRef} />
    </div>
  );
}
