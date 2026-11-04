/*
 * The guide page's only script, and everything it does is optional: the page shows the chosen answer through CSS with
 * scripts off. It adds four things:
 * - the address: `#s=<id>` (first tab) or `#e=<id>` (Enterprise) follows the choice, and opening such a link, or a
 *   `#answer-<id>` link (a common task, the expert table), chooses that answer and its tab; a common task is marked
 *   `aria-current` and takes the place of question 2's answer until a radio is chosen again;
 * - question 1 remembers each actor's answer to question 2, so going back and forth keeps what was chosen;
 * - "Copy prompt" and "Show the steps again", which are hidden until this script marks the page ready;
 * - on a phone, the answer is brought into view after a choice.
 */

type Tab = 'product' | 'enterprise';

function radio(root: HTMLElement, id: string): HTMLInputElement | null {
	const el = root.querySelector(`#${CSS.escape(id)}`);
	return el instanceof HTMLInputElement ? el : null;
}

function checkedIn(root: HTMLElement, name: string): HTMLInputElement | null {
	const el = root.querySelector(`input[name="${name}"]:checked`);
	return el instanceof HTMLInputElement ? el : null;
}

function currentTab(root: HTMLElement): Tab {
	return checkedIn(root, 'guide-tab')?.value === 'enterprise'
		? 'enterprise'
		: 'product';
}

/* The first tab's choice: a common task when one is chosen, else question 2's checked answer. */
function productChoice(root: HTMLElement): string | null {
	return root.dataset.chip ?? checkedIn(root, 'guide-product')?.value ?? null;
}

function answerOf(root: HTMLElement, tab: Tab): HTMLElement | null {
	const id =
		tab === 'product'
			? productChoice(root)
			: (checkedIn(root, 'guide-enterprise')?.value ?? null);
	if (!id) return null;
	const el = root.querySelector(`#answer-${CSS.escape(id)}`);
	return el instanceof HTMLElement ? el : null;
}

function init(root: HTMLElement) {
	const remembered: Record<string, string> = {};
	for (const input of root.querySelectorAll<HTMLInputElement>(
		'input[name="guide-product"][data-actor]'
	)) {
		const actor = input.dataset.actor ?? '';
		if (
			input.checked ||
			(input.dataset.first !== undefined && !remembered[actor])
		)
			remembered[actor] = input.value;
	}
	const chips = [...root.querySelectorAll<HTMLAnchorElement>('a[data-chip]')];

	/* A common task replaces question 2's answer: the radio is unchecked, and remembered to come back to. */
	const setChip = (id: string | null) => {
		if (id === null) delete root.dataset.chip;
		else {
			root.dataset.chip = id;
			const checked = checkedIn(root, 'guide-product');
			if (checked) checked.checked = false;
		}
		for (const chip of chips) {
			if (chip.dataset.chip === id) chip.setAttribute('aria-current', 'true');
			else chip.removeAttribute('aria-current');
		}
	};

	/* Question 2 again, after a common task: the actor's remembered answer. */
	const restoreAnswer = () => {
		const actor = checkedIn(root, 'guide-actor')?.value ?? '';
		const answer = remembered[actor];
		const next = answer ? radio(root, `g-s-${answer}`) : null;
		if (next) next.checked = true;
	};

	const writeAddress = () => {
		const tab = currentTab(root);
		const id =
			tab === 'product'
				? productChoice(root)
				: (checkedIn(root, 'guide-enterprise')?.value ?? null);
		if (!id) return;
		const hash = `#${tab === 'product' ? 's' : 'e'}=${id}`;
		if (window.location.hash !== hash)
			history.replaceState(history.state, '', hash);
	};

	/* Chooses an answer by its id; false when the id is no answer of this page. */
	const choose = (tab: Tab, id: string): boolean => {
		if (tab === 'product') {
			const input = radio(root, `g-s-${id}`);
			if (input) {
				setChip(null);
				input.checked = true;
				const actor = input.dataset.actor;
				if (actor) {
					remembered[actor] = id;
					const first = radio(root, `g-actor-${actor}`);
					if (first) first.checked = true;
				}
			} else if (chips.some((chip) => chip.dataset.chip === id)) {
				setChip(id);
			} else return false;
		} else {
			const input = radio(root, `g-e-${id}`);
			if (!input) return false;
			input.checked = true;
		}
		const tabInput = radio(root, `g-tab-${tab}`);
		if (tabInput) tabInput.checked = true;
		return true;
	};

	const reveal = (el: HTMLElement | null, always = false) => {
		if (!el) return;
		if (!always && !window.matchMedia('(max-width: 767px)').matches) return;
		if (!always && el.getBoundingClientRect().top < window.innerHeight * 0.6)
			return;
		const reduced = window.matchMedia(
			'(prefers-reduced-motion: reduce)'
		).matches;
		el.scrollIntoView({
			behavior: reduced ? 'auto' : 'smooth',
			block: 'start'
		});
	};

	/*
	 * Reads the address. `#answer-<id>` is the link of a common task and of the expert table, which works with scripts
	 * off as a target. `scroll` brings the answer into view: always for a link from below, on a phone only otherwise.
	 */
	const readAddress = (scroll: 'always' | 'phone' | 'never') => {
		let hash = '';
		try {
			hash = decodeURIComponent(window.location.hash.slice(1));
		} catch {
			// A malformed escape is an address no answer has; left to throw, it would stop the script before it is ready.
		}
		let picked: { tab: Tab; id: string } | null = null;
		if (hash.startsWith('s=')) picked = { tab: 'product', id: hash.slice(2) };
		else if (hash.startsWith('e='))
			picked = { tab: 'enterprise', id: hash.slice(2) };
		else if (hash.startsWith('answer-')) {
			const article = root.querySelector(`#${CSS.escape(hash)}`);
			if (article instanceof HTMLElement && article.dataset.id) {
				picked = {
					tab: article.dataset.tab === 'enterprise' ? 'enterprise' : 'product',
					id: article.dataset.id
				};
			}
		}
		if (!picked || !choose(picked.tab, picked.id)) return;
		writeAddress();
		if (scroll !== 'never')
			reveal(answerOf(root, picked.tab), scroll === 'always');
	};

	root.addEventListener('change', (event) => {
		const input = event.target;
		if (!(input instanceof HTMLInputElement)) return;
		if (input.name === 'guide-actor') {
			setChip(null);
			restoreAnswer();
		} else if (input.name === 'guide-product') {
			setChip(null);
			const actor = input.dataset.actor;
			if (actor) remembered[actor] = input.value;
		}
		writeAddress();
		if (input.name !== 'guide-tab') reveal(answerOf(root, currentTab(root)));
	});

	/* A link inside the page to an answer (a common task, the expert table, "the same case as"). */
	root.addEventListener('click', (event) => {
		const link =
			event.target instanceof Element
				? event.target.closest('a[href^="#answer-"]')
				: null;
		if (!(link instanceof HTMLAnchorElement)) return;
		event.preventDefault();
		history.replaceState(history.state, '', link.getAttribute('href') ?? '');
		readAddress(link.dataset.chip ? 'phone' : 'always');
	});

	window.addEventListener('hashchange', () => {
		readAddress('always');
	});

	root.addEventListener('click', (event) => {
		const target = event.target instanceof Element ? event.target : null;
		const answer = target?.closest('.g-answer');
		if (!(answer instanceof HTMLElement)) return;

		if (target?.closest('[data-replay]')) {
			const moving = answer.querySelectorAll<HTMLElement>('.g-row, .g-line');
			for (const el of moving) el.style.animation = 'none';
			answer.getBoundingClientRect();
			for (const el of moving) el.style.animation = '';
			return;
		}

		const copyButton = target?.closest('button');
		const label = copyButton?.querySelector<HTMLElement>('[data-copy]');
		if (!copyButton || !label) return;
		const text = answer.querySelector('[data-prompt]')?.textContent ?? '';
		const failed = answer.querySelector<HTMLElement>('[data-copy-failed]');
		const original = label.textContent;
		const done = () => {
			label.textContent = label.dataset.copied ?? original;
			setTimeout(() => {
				label.textContent = original;
			}, 2000);
		};
		const refused = () => {
			if (failed) failed.hidden = false;
		};
		try {
			navigator.clipboard.writeText(text).then(done, refused);
		} catch {
			refused();
		}
	});

	readAddress('never');
	root.dataset.ready = '';
}

const root = document.querySelector<HTMLElement>('[data-guide]');
if (root) init(root);
