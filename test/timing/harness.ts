/*
 * Measuring whether a comparison leaks the position of the first difference.
 *
 * One module rather than a copy in each spec, because the part that is easy to get wrong is invisible
 * when wrong. Two disciplines are load-bearing and both were arrived at by measurement, not by
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
 * The technique is dudect's (Reparaz, Balasch, Verbauwhede, 2016) — two input classes, percentile
 * cropping, Welch's t. What is borrowed is the discipline, not the tooling.
 */

export interface TimingVerdict {
	/* The two classes are distinguishable by time — the comparison leaks. */
	readonly separable: boolean;
	/* False when the measurement cannot support a conclusion either way. Never treat as a pass. */
	readonly decided: boolean;
	/* Median across rounds. */
	readonly t: number;
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
}

/*
 * Calibration on the development machine (Windows, Bun 1.4.0) at the settings below, ten trials per
 * row, each the median of seven batched rounds:
 *
 *                                        correct    first-difference mutant
 *   constantEquals (minComp 0)           ≤ 2.29     ≥ 118.08
 *   compareClientSecret (minComp 1000)   ≤ 1.88     ≥ 371.75
 *
 * And the number that matters more than either column: 100 consecutive runs of `test/timing/` on an
 * unmodified tree, zero failures. Two earlier configurations failed 5 and 4 of the same 100, which is
 * why the count is recorded — 20 runs would have passed both of them.
 *
 * A threshold of 10 sits ~4x above the worst correct observation and an order of magnitude below the
 * weakest leaking one — deliberately in the middle rather than hard against either, because the failure modes at the
 * two ends are not symmetric: too low is a suite that cries wolf until somebody deletes the case, too
 * high is an invariant that stopped being checked. The number lives here, in one place, so a runner
 * that needs a different one is a single edit with a recorded reason rather than a hunt through two
 * spec files.
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
	threshold: 10
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
	const { rounds, perRound, batch, warmup, crop, threshold } = {
		...DEFAULTS,
		...options
	};

	/* Discarded: otherwise JIT tiering is measured as timing variance. */
	for (let i = 0; i < warmup; i++) {
		compare(i % 2 === 0 ? classes.early : classes.late);
	}

	const scores: number[] = [];
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
	}

	if (retained < MINIMUM_SAMPLES) {
		return {
			separable: false,
			decided: false,
			t: Number.NaN,
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
			rounds: scores,
			samples: retained,
			reason: 'the timer produced no usable variation between samples'
		};
	}

	const t = median(scores);

	if (t <= threshold) {
		return {
			separable: false,
			decided: true,
			t,
			rounds: scores,
			samples: retained
		};
	}

	/*
	 * Past the threshold, consistency is what separates a leak from a loaded machine. A real leak is
	 * present in every round — the mutant's worst round still scores tens — while noise large enough
	 * to move the median shows up in some rounds and not others. When the rounds disagree, say so
	 * instead of naming a culprit; the case fails either way, so nothing is weakened by admitting
	 * which of the two it was.
	 */
	const everyRoundAgrees = Math.min(...scores) > threshold;

	return everyRoundAgrees
		? { separable: true, decided: true, t, rounds: scores, samples: retained }
		: {
				separable: false,
				decided: false,
				t,
				rounds: scores,
				samples: retained,
				reason: `rounds disagree — ${scores.map((s) => s.toFixed(1)).join(', ')} against a threshold of ${threshold}, so a leak cannot be told from load here`
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
				'This is not a pass. Re-run on a quieter machine, or raise the round count.'
		);
	}
	if (verdict.separable) {
		throw new Error(
			`${subject} takes distinguishable time for a candidate differing at the first position ` +
				`and one differing at the last: median |t| = ${verdict.t.toFixed(2)} across rounds ` +
				`${verdict.rounds.map((s) => s.toFixed(1)).join(', ')}, over ${verdict.samples} samples ` +
				'per class per round. A wrong guess can be told from a right one by how long the answer takes.'
		);
	}
}
