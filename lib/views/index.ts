import { Eta } from 'eta';

import layoutTemplate from './layout.ts';
import loginTemplate from './login.ts';
import interactionTemplate from './interaction.ts';

let eta;

export const interaction = (locals) => {
  eta ||= new Eta({ useWith: true });
  return eta.renderString(interactionTemplate, locals);
};

export const layout = (locals) => {
  eta ||= new Eta({ useWith: true });
  return eta.renderString(layoutTemplate, locals);
};

export const login = (locals) => {
  eta ||= new Eta({ useWith: true });
  return eta.renderString(loginTemplate, locals);
};
