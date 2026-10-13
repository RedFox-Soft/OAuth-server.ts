// Standalone server-rendered pages for the email-verification flow. These are reached
// from a link in an email (possibly a different browser/session), so they are plain,
// self-contained HTML with no dependency on the OIDC interaction cookie or the antd shell.

import { page } from './plainPage.js';
import { esc } from '../html/escape.js';
import { foxVar } from '../html/theme/palette.js';

export function verifySuccessPage(): Response {
	return page(
		'Email verified',
		`<h2 style="color:${foxVar('text')};">Email verified</h2><p style="color:${foxVar('text-secondary')};">Your email address has been confirmed. You can now sign in.</p>`
	);
}

// Failure page for an invalid/expired/used link. Informational — a link click carries no
// bucket context to safely target a resend, so it directs the user back to registration.
export function verifyFailurePage(message: string): Response {
	return page(
		'Verification failed',
		`<h2 style="color:${foxVar('text')};">Verification failed</h2><p style="color:${foxVar('text-secondary')};">${esc(message)}</p><p style="color:${foxVar('text-muted')}; font-size:13px;">Please return to the application and sign in again to receive a new verification message.</p>`,
		400
	);
}

// 6-digit code entry page (code method). `ref` identifies the challenge; the code is
// never shown here. `error` re-renders after a wrong/expired attempt. Includes a resend
// control that targets this challenge's ref.
export function codeEntryPage(ref: string, error?: string): Response {
	const errorHtml = error
		? `<p style="color:${foxVar('danger-text')};">${esc(error)}</p>`
		: '';
	return page(
		'Enter verification code',
		`<h2 style="color:${foxVar('text')};">Enter your code</h2><p style="color:${foxVar('text-secondary')};">We emailed you a 6-digit verification code.</p>${errorHtml}<form method="post" action="/verify-email/code"><input type="hidden" name="ref" value="${esc(ref)}"/><input name="code" inputmode="numeric" pattern="[0-9]*" maxlength="6" placeholder="000000" required style="width:100%; box-sizing:border-box; padding:10px; letter-spacing:6px; text-align:center; font-size:20px; margin-bottom:12px; border:1px solid ${foxVar('field-border')}; border-radius:6px;"/><button type="submit" style="background:${foxVar('primary-solid')}; color:${foxVar('on-primary')}; border:none; padding:10px 20px; border-radius:6px; cursor:pointer; width:100%;">Verify</button></form><form method="post" action="/verify-email/resend" style="margin-top:12px;"><input type="hidden" name="ref" value="${esc(ref)}"/><button type="submit" style="background:none; border:none; color:${foxVar('link')}; cursor:pointer; text-decoration:underline;">Send a new code</button></form>`
	);
}

export function resendAcceptedPage(): Response {
	return page(
		'Verification email sent',
		`<h2 style="color:${foxVar('text')};">Check your email</h2><p style="color:${foxVar('text-secondary')};">If your account still needs verification, a new verification email has been sent.</p>`
	);
}

export function verifyRateLimitedPage(message: string): Response {
	return page(
		'Please wait',
		`<h2 style="color:${foxVar('text')};">Too many requests</h2><p style="color:${foxVar('text-secondary')};">${esc(message)}</p>`,
		429
	);
}
