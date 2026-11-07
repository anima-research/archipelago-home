/**
 * Sending mail — only ever the one-time sign-in code (human.ts). Picked by
 * EMAIL_PROVIDER:
 *
 *   resend   HTTPS POST to Resend with RESEND_API_KEY; EMAIL_FROM is the
 *            sender ("Name <no-reply@your.domain>" — a domain with the
 *            provider's DKIM/SPF records, or nothing is delivered)
 *   log      prints the message to the server log — development only, and
 *            refused on a public https deployment, since the code would sit
 *            in the logs of a real sign-in
 *
 * Unset = no email sign-in: the method isn't offered and its routes 404.
 */
import type { FetchLike } from './oauth.js';

export interface EmailSender {
  send(to: string, subject: string, text: string): Promise<void>;
}

export interface EmailConfig {
  emailProvider?: string;
  resendApiKey?: string;
  emailFrom?: string;
}

const RESEND_URL = 'https://api.resend.com/emails';

export function resendSender(apiKey: string, from: string, fetchImpl: FetchLike = fetch): EmailSender {
  return {
    async send(to, subject, text) {
      const res = await fetchImpl(RESEND_URL, {
        method: 'POST',
        headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
        body: JSON.stringify({ from, to: [to], subject, text }),
        signal: AbortSignal.timeout(10_000),
      });
      // status only: the provider's body may echo the address
      if (!res.ok) throw new Error(`resend: ${res.status}`);
    },
  };
}

export function logSender(log: (line: string) => void = (l) => console.error(l)): EmailSender {
  return {
    async send(to, subject, text) {
      log(`[hn] email (log provider) to ${to}: ${subject}\n${text}`);
    },
  };
}

/** The sender the environment asks for, null for none. Throws on a
 *  half-configured or unsafe choice so the service refuses to start rather
 *  than offer a sign-in that can't deliver. */
export function emailSenderFromConfig(cfg: EmailConfig & { publicUrl: string }, fetchImpl?: FetchLike): EmailSender | null {
  const p = cfg.emailProvider?.trim();
  if (!p) return null;
  if (p === 'resend') {
    if (!cfg.resendApiKey) throw new Error('EMAIL_PROVIDER=resend needs RESEND_API_KEY');
    if (!cfg.emailFrom) throw new Error('EMAIL_PROVIDER=resend needs EMAIL_FROM (e.g. "Home <no-reply@your.domain>")');
    return resendSender(cfg.resendApiKey, cfg.emailFrom, fetchImpl);
  }
  if (p === 'log') {
    if (/^https:/i.test(cfg.publicUrl)) {
      throw new Error('EMAIL_PROVIDER=log prints sign-in codes to the server log — not for a public https deployment; use resend');
    }
    return logSender();
  }
  throw new Error(`EMAIL_PROVIDER "${p}" unknown — resend | log`);
}

export const CODE_TTL_MIN = 10;

export function signInCodeMessage(code: string): { subject: string; text: string } {
  return {
    subject: `Your sign-in code is ${code}`,
    text: `Your sign-in code is ${code}. It expires in ${CODE_TTL_MIN} minutes. If you didn't request this, ignore it.`,
  };
}
