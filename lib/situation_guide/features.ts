import { ApplicationConfig } from '../configs/application.js';
import {
	GUIDE_FLAG_SETTINGS,
	type GuideFlag
} from '../consts/situation_guide.js';

/*
 * Which instance switches the situation guide cares about, as they are now. Read at call time and never cached, so a
 * saved setting shows on the next read without a restart. Server-only: the console gets these values through
 * `/admin/api/me` and the shell seed, and must not import this module.
 */
export function guideFeatures(): Record<GuideFlag, boolean> {
	const settings = ApplicationConfig as Record<string, unknown>;
	const features = {} as Record<GuideFlag, boolean>;
	for (const flag of Object.keys(GUIDE_FLAG_SETTINGS) as GuideFlag[]) {
		features[flag] = settings[GUIDE_FLAG_SETTINGS[flag]] === true;
	}
	return features;
}
