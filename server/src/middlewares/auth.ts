import jwt from 'jsonwebtoken';
import { PLUGIN_ID } from '../pluginId';

interface JwtPayload {
  userId: number;
  secret: string;
}
function calculateMaxAge(param) {
  const unit = param.slice(-1); // Get the unit (d, h, m)
  const value = parseInt(param.slice(0, -1)); // Get the numerical value

  let maxAge;

  switch (unit) {
    case 'd':
      maxAge = 1000 * 60 * 60 * 24 * value;
      break;
    case 'h':
      maxAge = 1000 * 60 * 60 * value;
      break;
    case 'm':
      maxAge = 1000 * 60 * value;
      break;
    default:
      throw new Error('Invalid tokenExpires format. Use formats like "30d", "1h", "15m".');
  }

  return maxAge;
}
function auth({ strapi }) {
  const config = strapi.config.get(`plugin::${PLUGIN_ID}`);

  const authRoute = config.authRoute ?? '/api/wrapped/auth/login'
  const refreshRoute = config.refreshRoute ?? '/api/wrapped/auth/refresh'

  return async (ctx, next) => {
    await next();
    if (ctx.request.method === 'POST' && ctx.request.path === authRoute) {
      const requestRefresh = ctx.request.body?.requestRefresh || config.requestRefreshOnAll;
      if (ctx.response.body && ctx.response.message === 'OK' && requestRefresh) {
        const refreshEntry = await strapi
          .plugin(PLUGIN_ID)
          .service('service')
          .create(ctx.response.body?.user, ctx);
        const refreshToken = jwt.sign(
          { userId: ctx.response.body?.user?.id, secret: refreshEntry.documentId },
          config.refreshTokenSecret,
          {
            expiresIn: config.refreshTokenExpiresIn,
          }
        );
        if (config.cookieResponse) {
          ctx.cookies.set('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production' ? true : false,
            maxAge: calculateMaxAge(config.refreshTokenExpiresIn),
            domain:
              process.env.NODE_ENV === 'development' ? 'localhost' : process.env.PRODUCTION_URL,
          });
        } else {
          ctx.response.body = {
            ...ctx.response.body,
            refreshToken: refreshToken,
          };
        }
      }
    } else if (ctx.request.method === 'POST' && ctx.request.path === refreshRoute) {
      const refreshToken = ctx.request.body?.refreshToken;
      if (refreshToken) {
        try {
          const decoded = (await jwt.verify(refreshToken, config.refreshTokenSecret)) as JwtPayload;
          if (decoded) {
            const data = await strapi.query('plugin::refresh-token.token').findOne({
              where: { documentId: decoded.secret },
            });

            if (data) {
              const responseBody: { jwt: any; refreshToken?: string } = {
                jwt: strapi
                  .plugin('users-permissions')
                  .service('jwt')
                  .issue({ id: decoded.userId }),
              };
              if (config.refreshTokenRotation) {
                await strapi.query('plugin::refresh-token.token').delete({
                  where: { id: data.id },
                });

                const refreshEntry = await strapi
                  .plugin(PLUGIN_ID)
                  .service('service')
                  .create({ id: decoded.userId }, ctx);
                const newRefreshToken = jwt.sign(
                  { userId: decoded.userId, secret: refreshEntry.documentId },
                  config.refreshTokenSecret,
                  {
                    expiresIn: config.refreshTokenExpiresIn,
                  }
                );
                if (newRefreshToken) {
                  responseBody.refreshToken = newRefreshToken;
                }
              }
              ctx.send(responseBody);
            } else {
              ctx.status = 401;
              ctx.response.body = { error: 'Invalid Token' };
            }
          }
        } catch (err) {
          ctx.status = 401;
          ctx.response.body = { error: 'Invalid Token' };
        }
      }
    }
  };
}
export default auth;
