import { renderToString } from 'react-dom/server';
import { StrictMode } from 'react';
import { LoginPage } from './loginPage.js';
import { ConsentPage } from './consentPage.js';

export const loginServer = (uid: string) => {
	return renderToString(
		<StrictMode>
			<LoginPage uid={uid} />
		</StrictMode>
	);
};

export const consentServer = (uid: string) => {
	return renderToString(
		<StrictMode>
			<ConsentPage
				uid={uid}
				clientName={''}
				scopes={[]}
			/>
		</StrictMode>
	);
};
