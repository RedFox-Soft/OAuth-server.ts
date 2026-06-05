import type { AdapterConfigStore } from '../types.js';

export class ConfigStore implements AdapterConfigStore {
	static instance = new ConfigStore();
	private config: Record<string, unknown> = {};

	async get(): Promise<Record<string, unknown> | null> {
		return this.config;
	}

	async set(config: Record<string, unknown>): Promise<void> {
		this.config = config;
	}
}

export const configStore = ConfigStore.instance;
