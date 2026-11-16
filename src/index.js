import { createHandler, parseRoutes } from "./proxy.js";

let cached;

export default {
  async fetch(request, env) {
    if (!cached || cached.routesRaw !== env.ROUTES) {
      cached = {
        routesRaw: env.ROUTES,
        handler: createHandler({ routes: parseRoutes(env.ROUTES), secret: env.PROXY_SECRET }),
      };
    }
    return cached.handler(request);
  },
};
