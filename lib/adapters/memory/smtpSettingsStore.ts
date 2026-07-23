import type { SmtpSettings, SmtpSettingsStoreInstance } from '../types.js';

export class SmtpSettingsStore implements SmtpSettingsStoreInstance {
	private settings: SmtpSettings | null = null;

	async get(): Promise<SmtpSettings | null> {
		return this.settings;
	}

	async set(settings: SmtpSettings): Promise<void> {
		this.settings = settings;
	}
}
