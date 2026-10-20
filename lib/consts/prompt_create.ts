/*
 * `prompt=create`, from Initiating User Registration via OpenID Connect 1.0: the client would like its user
 * shown account creation rather than sign-in. Accepted while the policy has a login prompt, which is the
 * prompt that carries it — as the reason below — to the interaction that opens on the registration page.
 */
export const CREATE_PROMPT = 'create';
export const CREATE_PROMPT_REASON = 'create_prompt';
