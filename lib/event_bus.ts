import EventEmitter from 'node:events';

/*
 * eventBus
 *
 * The server's lifecycle events: the actions emit here, deployments subscribe. That is the entire
 * contract, so a bare EventEmitter is the entire implementation — there is no init step, no
 * construction step and nothing to configure. Settings live on ApplicationConfig (validated where
 * they are loaded, in configs/application.ts), on ClientDefaults, or in the addon registry; signing
 * keys are records in the key store (lib/keys/issuer_keys.ts). None of it is an input to this module.
 *
 * It was called `provider` until it stopped being one — inherited from oidc-provider, where a
 * Provider instance owned the configuration, the routes, the model classes and the keys, and was
 * constructed per deployment. Every one of those responsibilities now lives with the module that
 * implements it, and what remained of the class was the event emitter it extended.
 *
 * Importing no model is load-bearing. This module used to need an explicit
 * `import './models/id_token.js'` anchor, because it pulled in Client and Grant for
 * backchannelResult — which made it a participant in the base_token -> base_model -> this module
 * cycle, and entering that cycle here left base_token half-initialised (grant.ts threw "Cannot
 * access 'BaseTokenPayload' before initialization"). Moving backchannelResult to
 * actions/authorization/backchannel_result.ts made this a leaf, so base_model -> here terminates and
 * the anchor is gone. Keep it that way.
 */
export const eventBus = new EventEmitter();
