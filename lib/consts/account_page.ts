/*
 * The end-user connected-applications page (specs/095). Import-free, so the client resolver, the bucket
 * resolver and the page can all read these without reaching each other.
 */

/*
 * The prefix of the built-in client each end-user bucket signs people in to its page through. A `.` is
 * outside the alphabet every generated client id is drawn from, so no stored client can ever carry it by
 * chance — unlike `scim-`, which a random id could in principle start with. Registration refuses it too,
 * for a deployment whose id factory is its own.
 */
export const ACCOUNT_PAGE_CLIENT_PREFIX = 'account.';

/*
 * How recent a sign-in must be for a person to remove an application's access. Removing access is quick to
 * do and slow to undo for the application, and the page is reached from a browser that may have been left
 * signed in; asking for a sign-in older than this to be repeated keeps someone who walked up to an unlocked
 * browser from doing it. Fifteen minutes is the common window for a sensitive account action. A constant,
 * not a setting: nobody has needed to change it.
 */
export const ACCOUNT_REAUTHENTICATION_SECONDS = 900;

/* The short-lived cookie holding a sign-in the page started, until it comes back. */
export const ACCOUNT_PAGE_COOKIE = '_account_apps';
export const ACCOUNT_PAGE_PENDING_SECONDS = 600;
