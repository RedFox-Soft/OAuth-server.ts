export class ConfigStore {
	static instance = new ConfigStore();
	private config: Record<string, any> = {};

	async get(): Promise<Record<string, any> | null> {
		return this.config;
	}

	async set(config: Record<string, any>): Promise<void> {
		this.config = config;
	}
}

export const configStore = ConfigStore.instance;
