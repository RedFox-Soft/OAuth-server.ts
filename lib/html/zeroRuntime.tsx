import type { ReactNode } from 'react';
import { ConfigProvider } from 'antd';

/*
 * antd 6 generates every component's CSS at runtime unless told not to. The hydrated pages link a
 * precompiled antd.css instead, so they must set this flag on **both** the server render and the
 * client hydrate: if the two disagree, one side generates styles the other does not and hydration
 * diverges — in the browser only, and only visibly as a mismatch warning.
 *
 * One component owns the flag so the four entry points cannot drift apart. The terminal pages do not
 * use it: they extract their styles server-side and inline them, which is cheaper for a page that is
 * read once.
 *
 * `zeroRuntime` does not reach zero: it only gates `genComponentStyleHook` (the ~246 KB of hashed
 * per-component rules antd.css now supplies instead). It does not gate `genCSSVarRegister` — a
 * separate hook in @ant-design/cssinjs-utils that every cssVar-mode component calls unconditionally
 * to inject the small `--ant-xxx` custom-property block its classes read from. There is no antd 6.5.1
 * theme prop that suppresses it: `cssVar.key` only renames the scope class (confirmed empirically —
 * pinning it changes neither the tag count nor the byte count), and `StyleProvider`'s `layer` prop
 * feeds a completely different, icon-only zeroRuntime path in `config-provider/index.js` that never
 * touches this hook. Measured floor on /admin: 7 tags, 17,540 B — one root block plus one per
 * distinct cssVar component actually mounted (Typography, Input, Form, Button, Card here).
 */
export function ZeroRuntime({ children }: { children: ReactNode }) {
	return (
		<ConfigProvider theme={{ zeroRuntime: true }}>{children}</ConfigProvider>
	);
}
