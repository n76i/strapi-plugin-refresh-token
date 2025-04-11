import jwt from 'jsonwebtoken';
import auth from './auth';
import { PLUGIN_ID } from '../pluginId';

jest.mock('jsonwebtoken', () => ({
  sign: jest.fn(() => 'mockedRefreshToken'),
  verify: jest.fn((token, secret) => {
    if (token === 'invalidToken') {
      throw new Error('Invalid token');
    } else {
      return { userId: 1, secret: 'testDocumentId' };
    }
  }),
}));

describe('Auth Middleware', () => {
  let strapiMock;
  let ctxMock;

  beforeEach(() => {
    process.env.PRODUCTION_URL = 'https://redon2.ca/';
    strapiMock = {
      config: {
        get: jest.fn().mockReturnValue({
          requestRefreshOnAll: true,
          refreshTokenSecret: 'testSecretKey',
          refreshTokenExpiresIn: '30d',
          cookieResponse: false,
          refreshTokenRotation: false,
        }),
      },
      plugin: jest.fn().mockImplementation((pluginId) => {
        if (pluginId === 'users-permissions') {
          return {
            service: jest.fn().mockImplementation((serviceId) => {
              if (serviceId === 'jwt') {
                return {
                  issue: jest.fn().mockReturnValue('mockedJwtToken'),
                };
              }
              return {};
            }),
          };
        }
        return {
          service: jest.fn().mockReturnThis(),
          create: jest.fn().mockResolvedValue({
            documentId: 'testDocumentId',
          }),
        };
      }),
      query: jest.fn().mockReturnThis(),
      findOne: jest.fn().mockResolvedValue({
        documentId: 'testDocumentId',
      }),
      delete: jest.fn().mockResolvedValue({}),
    };

    ctxMock = {
      request: {
        method: 'POST',
        path: '/api/auth/local',
        body: {
          requestRefresh: true,
        },
      },
      response: {
        body: {
          user: {
            id: 1,
          },
        },
        message: 'OK',
      },
      send: jest.fn(),
      status: 200,
      cookies: {
        set: jest.fn(),
      },
    };
  });

  it('should generate a refreshToken in the response body for /api/auth/local', async () => {
    const middleware = auth({ strapi: strapiMock });

    await middleware(ctxMock, () => Promise.resolve());

    expect(ctxMock.response.body.refreshToken).toBeDefined();
    expect(strapiMock.plugin).toHaveBeenCalledWith(expect.stringContaining(PLUGIN_ID));
    expect(jwt.sign).toHaveBeenCalledWith(
      expect.objectContaining({ userId: 1, secret: 'testDocumentId' }),
      'testSecretKey',
      { expiresIn: '30d' }
    );
  });

  it.each([
    { refreshTokenExpiresIn: '1h' },
    { refreshTokenExpiresIn: '15m' },
    { refreshTokenExpiresIn: '7d' },
  ])(
    'should generate a refreshToken in a cookie with refreshTokenExpiresIn: %o for /api/auth/local',
    async ({ refreshTokenExpiresIn }) => {
      strapiMock.config.get.mockReturnValueOnce({
        ...strapiMock.config.get(),
        cookieResponse: true,
        refreshTokenExpiresIn,
      });

      const middleware = auth({ strapi: strapiMock });

      await middleware(ctxMock, () => Promise.resolve());

      expect(ctxMock.cookies.set).toHaveBeenCalledWith(
        'refreshToken',
        expect.any(String),
        expect.objectContaining({
          httpOnly: true,
          secure: expect.any(Boolean),
          maxAge: expect.any(Number),
          domain: expect.any(String),
        })
      );
    }
  );

  it('should throw an error for invalid refreshTokenExpiresIn format', async () => {
    strapiMock.config.get.mockReturnValueOnce({
      ...strapiMock.config.get(),
      cookieResponse: true,
      refreshTokenExpiresIn: '1t',
    });

    const middleware = auth({ strapi: strapiMock });

    await expect(middleware(ctxMock, () => Promise.resolve())).rejects.toThrow(
      'Invalid tokenExpires format. Use formats like "30d", "1h", "15m".'
    );
  });

  it('should send a new JWT on valid /api/auth/local/refresh', async () => {
    ctxMock.request = {
      method: 'POST',
      path: '/api/auth/local/refresh',
      body: {
        refreshToken: jwt.sign({ userId: 1, secret: 'testDocumentId' }, 'testSecretKey', {
          expiresIn: '30d',
        }),
      },
    };

    ctxMock.response = {
      body: {},
      message: 'OK',
    };

    const middleware = auth({ strapi: strapiMock });

    await middleware(ctxMock, () => Promise.resolve());

    expect(ctxMock.send).toHaveBeenCalledWith(
      expect.objectContaining({
        jwt: expect.any(String),
      })
    );
  });

  it('should handle refreshToken rotation for /api/auth/local/refresh', async () => {
    strapiMock.config.get.mockReturnValueOnce({
      ...strapiMock.config.get(),
      refreshTokenRotation: true,
    });

    ctxMock.request = {
      method: 'POST',
      path: '/api/auth/local/refresh',
      body: {
        refreshToken: jwt.sign({ userId: 1, secret: 'testDocumentId' }, 'testSecretKey', {
          expiresIn: '30d',
        }),
      },
    };

    strapiMock.findOne.mockResolvedValue({
      id: 1,
      documentId: 'testDocumentId',
    });

    const middleware = auth({ strapi: strapiMock });

    await middleware(ctxMock, () => Promise.resolve());

    expect(strapiMock.query().delete).toHaveBeenCalledWith({ where: { id: 1 } });
    expect(ctxMock.send).toHaveBeenCalledWith(
      expect.objectContaining({
        jwt: expect.any(String),
        refreshToken: expect.any(String),
      })
    );
  });

  it('should respond with 401 for invalid refreshToken', async () => {
    ctxMock.request = {
      method: 'POST',
      path: '/api/auth/local/refresh',
      body: {
        refreshToken: 'invalidToken',
      },
    };

    const middleware = auth({ strapi: strapiMock });

    await middleware(ctxMock, () => Promise.resolve());

    expect(ctxMock.status).toBe(401);
    expect(ctxMock.response.body.error).toBe('Invalid Token');
  });

  it('should respond with 401 if no data is found for the given documentId', async () => {
    const validRefreshToken = jwt.sign({ userId: 1, secret: 'testDocumentId' }, 'testSecretKey', {
      expiresIn: '30d',
    });

    ctxMock.request = {
      method: 'POST',
      path: '/api/auth/local/refresh',
      body: {
        refreshToken: validRefreshToken,
      },
    };

    strapiMock.findOne.mockResolvedValue(null);

    const middleware = auth({ strapi: strapiMock });

    await middleware(ctxMock, () => Promise.resolve());

    expect(ctxMock.status).toBe(401);
    expect(ctxMock.response.body.error).toBe('Invalid Token');
  });

  it('should handle secure cookie settings in production', async () => {
    process.env.NODE_ENV = 'production';
    strapiMock.config.get.mockReturnValueOnce({
      ...strapiMock.config.get(),
      cookieResponse: true,
    });

    const middleware = auth({ strapi: strapiMock });

    await middleware(ctxMock, () => Promise.resolve());

    expect(ctxMock.cookies.set).toHaveBeenCalledWith(
      'refreshToken',
      expect.any(String),
      expect.objectContaining({
        secure: true,
        domain: process.env.PRODUCTION_URL,
      })
    );
  });
});
