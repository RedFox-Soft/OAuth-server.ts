import bodyParser from './selective_body.ts';

export default async function parseBodyIfPost(cty, ctx, next) {
  if (ctx.method === 'POST') {
    await bodyParser(cty, ctx, next);
  } else {
    await next();
  }
}
