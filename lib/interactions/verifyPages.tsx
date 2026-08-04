// Standalone server-rendered pages for the email-verification flow. These are reached
// from a link in an email (possibly a different browser/session), so they are plain,
// self-contained HTML with no dependency on the OIDC interaction cookie or the antd shell.

import { htmlResponse } from '../html/csp.js';

function esc(value: string): string {
	return value
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;');
}

function page(title: string, bodyHtml: string, status = 200): Response {
	const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><title>${esc(title)}</title></head><body style="font-family: Arial, Helvetica, sans-serif; background:#f0f2f5; margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;"><div style="background:#fff; padding:32px; border-radius:12px; box-shadow:0 2px 8px rgba(0,0,0,0.1); width:400px; text-align:center;">${bodyHtml}</div></body></html>`;
	return htmlResponse(html, { status });
}

export function verifySuccessPage(): Response {
	return page(
		'Email verified',
		`<h2 style="color:#1f1f1f;">Email verified</h2><p style="color:#595959;">Your email address has been confirmed. You can now sign in.</p>`
	);
}

// Failure page for an invalid/expired/used link. Informational — a link click carries no
// bucket context to safely target a resend, so it directs the user back to registration.
export function verifyFailurePage(message: string): Response {
	return page(
		'Verification failed',
		`<h2 style="color:#1f1f1f;">Verification failed</h2><p style="color:#595959;">${esc(message)}</p><p style="color:#8c8c8c; font-size:13px;">Please return to the application and register again to receive a new verification email.</p>`,
		400
	);
}

// 6-digit code entry page (code method). `ref` identifies the challenge; the code is
// never shown here. `error` re-renders after a wrong/expired attempt. Includes a resend
// control that targets this challenge's ref.
export function codeEntryPage(ref: string, error?: string): Response {
	const errorHtml = error ? `<p style="color:#cf1322;">${esc(error)}</p>` : '';
	return page(
		'Enter verification code',
		`<h2 style="color:#1f1f1f;">Enter your code</h2><p style="color:#595959;">We emailed you a 6-digit verification code.</p>${errorHtml}<form method="post" action="/verify-email/code"><input type="hidden" name="ref" value="${esc(ref)}"/><input name="code" inputmode="numeric" pattern="[0-9]*" maxlength="6" placeholder="000000" required style="width:100%; box-sizing:border-box; padding:10px; letter-spacing:6px; text-align:center; font-size:20px; margin-bottom:12px; border:1px solid #d9d9d9; border-radius:6px;"/><button type="submit" style="background:#1677ff; color:#fff; border:none; padding:10px 20px; border-radius:6px; cursor:pointer; width:100%;">Verify</button></form><form method="post" action="/verify-email/resend" style="margin-top:12px;"><input type="hidden" name="ref" value="${esc(ref)}"/><button type="submit" style="background:none; border:none; color:#1677ff; cursor:pointer; text-decoration:underline;">Send a new code</button></form>`
	);
}

export function resendAcceptedPage(): Response {
	return page(
		'Verification email sent',
		`<h2 style="color:#1f1f1f;">Check your email</h2><p style="color:#595959;">If your account still needs verification, a new verification email has been sent.</p>`
	);
}

export function verifyRateLimitedPage(message: string): Response {
	return page(
		'Please wait',
		`<h2 style="color:#1f1f1f;">Too many requests</h2><p style="color:#595959;">${esc(message)}</p>`,
		429
	);
}
