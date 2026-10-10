import {
	createContext,
	useCallback,
	useContext,
	useEffect,
	useMemo,
	useRef,
	useSyncExternalStore,
	type AnchorHTMLAttributes,
	type MouseEvent,
	type ReactNode
} from 'react';
import { App } from 'antd';
import { resolveAddress, type Resolved } from './routes.js';

/*
 * The console's history router: the browser's address is the state, and the route table in routes.ts
 * decides what it means.
 *
 * About thirty addresses, no data loaders, and one feature a library would be wanted for (blocking a
 * navigation while a form is dirty) — which is why this is a page of code rather than react-router's
 * data router (specs/079 research R1).
 *
 * The server renders the address it was asked for, and passes it in `window.PROPS.path`; the store
 * answers that path as its server snapshot, so the first client render matches the HTML exactly.
 */

interface Location {
	pathname: string;
	search: string;
}

type Blocker = () => Promise<boolean>;

interface RouterValue {
	location: Location;
	resolved: Resolved;
	navigate: (href: string, options?: { replace?: boolean }) => Promise<boolean>;
	/* Registers a check that may refuse a navigation; returns the function that removes it. */
	block: (blocker: Blocker) => () => void;
}

const RouterContext = createContext<RouterValue | null>(null);

const listeners = new Set<() => void>();

function readLocation(): string {
	return `${window.location.pathname}${window.location.search}`;
}

function subscribe(listener: () => void) {
	listeners.add(listener);
	const onPop = () => {
		listener();
	};
	window.addEventListener('popstate', onPop);
	return () => {
		listeners.delete(listener);
		window.removeEventListener('popstate', onPop);
	};
}

function notify() {
	for (const listener of listeners) listener();
}

function split(href: string): Location {
	const at = href.indexOf('?');
	return at === -1
		? { pathname: href, search: '' }
		: { pathname: href.slice(0, at), search: href.slice(at) };
}

export function RouterProvider({
	initialPath,
	children
}: {
	initialPath: string;
	children: ReactNode;
}) {
	const blockers = useRef(new Set<Blocker>());
	const href = useSyncExternalStore(subscribe, readLocation, () => initialPath);
	const location = split(href);
	const resolved = resolveAddress(location.pathname);

	const allowed = useCallback(async () => {
		for (const blocker of blockers.current) {
			if (!(await blocker())) return false;
		}
		return true;
	}, []);

	const navigate = useCallback(
		async (to: string, options?: { replace?: boolean }) => {
			if (to === readLocation()) return true;
			if (!(await allowed())) return false;
			if (options?.replace) window.history.replaceState(null, '', to);
			else window.history.pushState(null, '', to);
			notify();
			window.scrollTo(0, 0);
			return true;
		},
		[allowed]
	);

	/*
	 * Back and Forward have already changed the address by the time `popstate` fires, so a refusal puts
	 * the address the operator was on back rather than preventing the change.
	 */
	const current = useRef(href);
	useEffect(() => {
		const onPop = () => {
			const target = readLocation();
			void allowed().then((ok) => {
				if (ok) {
					current.current = target;
					return;
				}
				window.history.pushState(null, '', current.current);
				notify();
			});
		};
		window.addEventListener('popstate', onPop);
		return () => {
			window.removeEventListener('popstate', onPop);
		};
	}, [allowed]);
	useEffect(() => {
		current.current = href;
	}, [href]);

	// A redirect address is never shown: it is replaced by the address it stands for.
	useEffect(() => {
		if (resolved.kind === 'redirect') {
			window.history.replaceState(null, '', resolved.to + location.search);
			notify();
		}
	}, [resolved, location.search]);

	const block = useCallback((blocker: Blocker) => {
		blockers.current.add(blocker);
		return () => {
			blockers.current.delete(blocker);
		};
	}, []);

	const value = useMemo(
		() => ({ location, resolved, navigate, block }),
		// `location` is derived from `href`; recomputing on it alone keeps the object stable between renders.
		// eslint-disable-next-line react-hooks/exhaustive-deps
		[href, navigate, block]
	);
	return (
		<RouterContext.Provider value={value}>{children}</RouterContext.Provider>
	);
}

function useRouter(): RouterValue {
	const value = useContext(RouterContext);
	if (!value) throw new Error('the console router is not mounted');
	return value;
}

export function useRoute() {
	const { resolved, location } = useRouter();
	const query = useMemo(
		() => new URLSearchParams(location.search),
		[location.search]
	);
	return { resolved, location, query };
}

export function useNavigate() {
	return useRouter().navigate;
}

/*
 * A real link: middle-click, Ctrl-click and "copy link" work, and keyboard users reach it like any
 * other. Only a plain left click is taken over, so the console moves without a page load.
 */
export function Link({
	href,
	replace,
	children,
	onClick,
	...rest
}: AnchorHTMLAttributes<HTMLAnchorElement> & {
	href: string;
	replace?: boolean;
	children: ReactNode;
}) {
	const navigate = useNavigate();
	const handle = (event: MouseEvent<HTMLAnchorElement>) => {
		onClick?.(event);
		if (
			event.defaultPrevented ||
			event.button !== 0 ||
			event.metaKey ||
			event.ctrlKey ||
			event.shiftKey ||
			event.altKey
		) {
			return;
		}
		event.preventDefault();
		void navigate(href, { replace });
	};
	return (
		<a
			href={href}
			onClick={handle}
			{...rest}
		>
			{children}
		</a>
	);
}

/*
 * While `dirty`, leaving asks first: inside the console through a confirmation that defaults to keeping
 * the edits, and when the browser tab closes through the browser's own warning.
 */
export function useLeaveGuard(dirty: boolean, count = 0) {
	const { block } = useRouter();
	const { modal } = App.useApp();
	useEffect(() => {
		if (!dirty) return;
		const onUnload = (event: BeforeUnloadEvent) => {
			event.preventDefault();
		};
		window.addEventListener('beforeunload', onUnload);
		const release = block(
			() =>
				new Promise<boolean>((resolve) => {
					modal.confirm({
						title:
							count > 1
								? `Discard ${String(count)} unsaved changes?`
								: 'Discard unsaved changes?',
						okText: 'Discard',
						okButtonProps: { danger: true },
						cancelText: 'Keep editing',
						focusable: { autoFocusButton: 'cancel' },
						onOk: () => {
							resolve(true);
						},
						onCancel: () => {
							resolve(false);
						}
					});
				})
		);
		return () => {
			window.removeEventListener('beforeunload', onUnload);
			release();
		};
	}, [dirty, count, block, modal]);
}
