/*
 * Measuring whether a comparison leaks the position of the first difference.
 *
 * One module rather than a copy in each spec, because the part that is easy to get wrong is invisible
 * when wrong. Four disciplines are load-bearing and all four were arrived at by measurement, not by
 * reading:
 *
 * 1. Each sample is assigned to a class at RANDOM. Collected in blocks — all of one class, then all
 *    of the other — a correct constant-time comparison scores |t| = 23.9 here, because thermal and
 *    scheduling drift within a run lands entirely on whichever class was measured second. Randomised,
 *    the same comparison scores under 2.
 *
 * 2. The statistic is the MEDIAN of several independent rounds, not one measurement. A single round
 *    is too noisy to gate on: a first version of this file, threshold 10, failed 5 runs out of 100 on
 *    an unmodified tree — two of them scoring 10.03 and 12.80 on code that does not leak. Excursions
 *    like that are independent between rounds, so a median suppresses them while a real leak, which
 *    is present in every round, survives untouched.
 *
 * 3. Each sample times a BATCH of comparisons rather than one. `Bun.nanoseconds()` is coarse enough
 *    relative to a single comparison that the fastest half of the samples routinely come back
 *    bit-identical — zero variance, and a t of 0/0. That is not hypothetical: it failed 4 runs out of
 *    100 before batching, reported as "the timer produced no usable variation". Timing sixteen
 *    comparisons lifts the measured interval clear of the timer's resolution, and across 280 rounds
 *    afterwards there was not one zero-variance round.
 *
 * 4. The verdict is gated on how BIG the difference is, and only secondarily on how significant it
 *    is. The next block is why; it cost a red CI run to learn and is the easiest of the four to undo
 *    by accident.
 *
 * The technique is dudect's (Reparaz, Balasch, Verbauwhede, 2016) — two input classes, percentile
 * cropping, Welch's t. What is borrowed is the discipline, not the tooling; the effect-size gate is
 * this file's own, for the reason below.
 */

/*
 * Why effect size, and not Welch's t alone.
 *
 * At the settings below |t| is very nearly `15.8 * delta / sd`, and BOTH of those move for reasons
 * that have nothing to do with the code under test.
 *
 * The numerator is not zero for a correct comparison. Two classes differ by 0.1-0.4% of the work even
 * when a leak is impossible: feed the harness two candidates with IDENTICAL CONTENT and it reports
 * the same spread of |t| as it does for the real pair — median 1.20 against 1.06 over twenty freshly
 * allocated pairs. That residue is where the strings happened to land, not what the comparison did
 * with them.
 *
 * The denominator is set by the machine. `Bun.nanoseconds()` is quantised at 100 ns on the Windows
 * development machine, so its sd of ~45 ns is mostly the clock ticking rather than the code varying —
 * a uniform 100 ns quantum contributes 100/sqrt(12) = 29 ns by itself. On Linux the same call
 * resolves to ~57 ns and sd falls to 15-35 ns. So the identical, meaningless 0.2% residue scores
 * about three times higher on the runner than on the machine a t threshold was calibrated on.
 *
 * Which is exactly what happened. CI run #143 failed `constant_equals` on an unmodified tree with
 * rounds 1.7, 2.4, 2.3, 52.3, 52.9, 53.2, 53.3 — a constant numerator, and a denominator that dropped
 * partway through. Note what that implies, because it inverts the advice this file used to give:
 * LOAD MAKES THIS TEST PASS. Twenty-four spinning processes on a twenty-core machine drag the median
 * |t| down to 0.5-0.9, because contention inflates sd. A quiet, precise machine is where a
 * significance threshold fails, not where it succeeds.
 *
 * An effect size does not have that defect. A leak is a fraction of the work, and that fraction is a
 * property of the algorithm: the first-difference mutant costs 52.0% of a comparison on Linux and
 * 59.5% on Windows. The residue is 0.1-0.4% on both. So the gate is a percentage, and it means the
 * same thing on every machine this runs on.
 */

export interface TimingVerdict {
	/* The two classes are distinguishable by time, by enough to matter — the comparison leaks. */
	readonly separable: boolean;
	/* False when the measurement cannot support a conclusion either way. Never treat as a pass. */
	readonly decided: boolean;
	/* Median across rounds. */
	readonly t: number;
	/* Median across rounds of |early - late| as a fraction of one comparison's work. */
	readonly effect: number;
	readonly rounds: readonly number[];
	readonly samples: number;
	readonly reason?: string;
}

export interface TimingOptions {
	readonly rounds?: number;
	readonly perRound?: number;
	readonly batch?: number;
	readonly warmup?: number;
	readonly crop?: number;
	readonly threshold?: number;
	readonly minimumEffect?: number;
}

/*
 * Calibration, ten trials per row, each the median of seven batched rounds, taken on both a Windows
 * development machine and a Linux container on the same hardware — two platforms, because the whole
 * point of an effect-size gate is that it transfers between them and a single-platform calibration
 * could not show that.
 *
 *                                        correct    first-difference mutant
 *   constantEquals (minComp 0)           ≤ 0.20%    51.9% Linux / 59.5% Windows
 *   compareClientSecret (minComp 1000)   ≤ 0.45%    13.7% Linux / 25.5% Windows
 *
 * `minimumEffect` sits at 2%: about three times the worst round a correct comparison produced (0.82%)
 * and about three times below the weakest round a leaking one produced (6.45% — the minComp 1000
 * mutant on Linux, where a thousand bytes of buffer allocation dilute the leak most). Deliberately in
 * the middle of those two in log scale rather than hard against either, because the failure modes are
 * not symmetric: too low is a suite that cries wolf until somebody deletes the case, which is the
 * defect this replaces, and too high is an invariant that stopped being checked.
 *
 * What the floor costs, stated plainly: a position leak worth less than 2% of a comparison is not
 * detected here. It was not detected before either — it sat below the residue — the difference is
 * that the limit is now written down instead of being whatever the calibration machine's clock
 * happened to imply.
 *
 * `threshold` stays at 10 as the SECOND half of the leak verdict. Alone it is machine-dependent, per
 * the block above; alongside the effect floor it does a different job — refusing to call a large
 * difference a leak when the measurement was too noisy to establish it at all.
 *
 * Cropping keeps the FASTEST half. A descheduled sample carries no information about the comparison,
 * while the fast tail is where a leak shows; this is not symmetric trimming and must not be tidied
 * into it.
 */
const DEFAULTS = {
	rounds: 7,
	perRound: 2_000,
	batch: 16,
	warmup: 20_000,
	crop: 0.5,
	threshold: 10,
	minimumEffect: 0.02
} as const;

/*
 * Enough retained samples per class per round for the variance estimate to mean anything. Per ROUND,
 * not per measurement: the confidence comes from the median across rounds, and the calibration above
 * was taken with roughly this many. The default sampling keeps about 500 per class per round — half
 * of `perRound` goes to each class, and cropping keeps half of that — so this floor is a guard against
 * a degenerate call, not a bar the normal configuration has to clear by luck.
 */
const MINIMUM_SAMPLES = 200;

function mean(xs: readonly number[]): number {
	return xs.reduce((sum, x) => sum + x, 0) / xs.length;
}

function variance(xs: readonly number[], m: number): number {
	return xs.reduce((sum, x) => sum + (x - m) ** 2, 0) / (xs.length - 1);
}

function median(xs: readonly number[]): number {
	const sorted = [...xs].sort((a, b) => a - b);
	return sorted[Math.floor(sorted.length / 2)];
}

function cropped(xs: readonly number[], keep: number): number[] {
	const sorted = [...xs].sort((a, b) => a - b);
	return sorted.slice(0, Math.max(1, Math.floor(sorted.length * keep)));
}

function welch(a: readonly number[], b: readonly number[]): number {
	const meanA = mean(a);
	const meanB = mean(b);
	return (
		(meanA - meanB) /
		Math.sqrt(variance(a, meanA) / a.length + variance(b, meanB) / b.length)
	);
}

/*
 * The difference between the classes as a fraction of the work one comparison does. Measured against
 * the FASTER class, so the denominator is a comparison rather than a comparison plus whatever extra
 * the slower class is doing.
 */
function effectShare(a: readonly number[], b: readonly number[]): number {
	const meanA = mean(a);
	const meanB = mean(b);
	return Math.abs(meanA - meanB) / Math.min(meanA, meanB);
}

function percent(fraction: number): string {
	return `${(fraction * 100).toFixed(2)}%`;
}

/**
 * Measures whether `compare` takes distinguishable time for the two candidate classes.
 *
 * `compare` must perform exactly one comparison and nothing else — no allocation of the candidate, no
 * string building — or the setup is what gets measured.
 */
export function measureSeparability(
	compare: (candidate: string) => unknown,
	classes: { readonly early: string; readonly late: string },
	options: TimingOptions = {}
): TimingVerdict {
	const { rounds, perRound, batch, warmup, crop, threshold, minimumEffect } = {
		...DEFAULTS,
		...options
	};

	/* Discarded: otherwise JIT tiering is measured as timing variance. */
	for (let i = 0; i < warmup; i++) {
		compare(i % 2 === 0 ? classes.early : classes.late);
	}

	const scores: number[] = [];
	const shares: number[] = [];
	let retained = Number.POSITIVE_INFINITY;

	for (let round = 0; round < rounds; round++) {
		const early: number[] = [];
		const late: number[] = [];
		for (let i = 0; i < perRound; i++) {
			const useEarly = Math.random() < 0.5;
			const candidate = useEarly ? classes.early : classes.late;
			const started = Bun.nanoseconds();
			for (let k = 0; k < batch; k++) compare(candidate);
			const elapsed = Bun.nanoseconds() - started;
			(useEarly ? early : late).push(elapsed);
		}
		const a = cropped(early, crop);
		const b = cropped(late, crop);
		retained = Math.min(retained, a.length, b.length);
		scores.push(Math.abs(welch(a, b)));
		shares.push(effectShare(a, b));
	}

	if (retained < MINIMUM_SAMPLES) {
		return {
			separable: false,
			decided: false,
			t: Number.NaN,
			effect: Number.NaN,
			rounds: scores,
			samples: retained,
			reason: `only ${retained} samples retained per class per round, below the ${MINIMUM_SAMPLES} needed for a variance estimate`
		};
	}

	if (scores.some((score) => !Number.isFinite(score))) {
		return {
			separable: false,
			decided: false,
			t: Number.NaN,
			effect: Number.NaN,
			rounds: scores,
			samples: retained,
			reason: 'the timer produced no usable variation between samples'
		};
	}

	const t = median(scores);
	const effect = median(shares);

	/*
	 * The primary gate, and the one that means the same thing everywhere. Below the floor there is
	 * nothing an attacker could use even if the difference is real and perfectly significant — and at
	 * that size it is usually neither, being the allocation residue the block at the top describes.
	 */
	if (effect < minimumEffect) {
		return {
			separable: false,
			decided: true,
			t,
			effect,
			rounds: scores,
			samples: retained
		};
	}

	if (t <= threshold) {
		return {
			separable: false,
			decided: true,
			t,
			effect,
			rounds: scores,
			samples: retained
		};
	}

	/*
	 * A difference big enough to matter and significant on the median round, but not on every round.
	 * Consistency is what separates a leak from a machine that moved: a real leak is present in every
	 * round — the mutant's worst round still scores tens — while an excursion large enough to move the
	 * median shows up in some rounds and not others. When the rounds disagree, say so instead of
	 * naming a culprit; the case fails either way, so nothing is weakened by admitting which it was.
	 */
	const everyRoundAgrees = Math.min(...scores) > threshold;

	return everyRoundAgrees
		? {
				separable: true,
				decided: true,
				t,
				effect,
				rounds: scores,
				samples: retained
			}
		: {
				separable: false,
				decided: false,
				t,
				effect,
				rounds: scores,
				samples: retained,
				reason: `a difference of ${percent(effect)} per comparison was measured, over the ${percent(minimumEffect)} that would matter, but the rounds disagree on whether it is significant — ${scores.map((s) => s.toFixed(1)).join(', ')} against a threshold of ${threshold}`
			};
}

/**
 * Fails the case when the comparison leaks, and fails it differently when the machine could not
 * decide. A caller that collapsed the two would recreate the defect this measures: an invariant that
 * is asserted, is not measured, and whose name keeps anybody from noticing.
 */
export function expectIndistinguishable(
	verdict: TimingVerdict,
	subject: string
): void {
	if (!verdict.decided) {
		throw new Error(
			`undecided: ${subject} could not be measured here — ${verdict.reason}. ` +
				'This is not a pass. Raise the round count and re-run; note that loading the machine ' +
				'suppresses this measurement rather than disturbing it, so an idle machine is the ' +
				'honest place to repeat it.'
		);
	}
	if (verdict.separable) {
		throw new Error(
			`${subject} takes distinguishable time for a candidate differing at the first position ` +
				`and one differing at the last: ${percent(verdict.effect)} of a comparison, median ` +
				`|t| = ${verdict.t.toFixed(2)} across rounds ` +
				`${verdict.rounds.map((s) => s.toFixed(1)).join(', ')}, over ${verdict.samples} samples ` +
				'per class per round. A wrong guess can be told from a right one by how long the answer takes.'
		);
	}
}
