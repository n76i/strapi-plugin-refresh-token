import jwt from 'jsonwebtoken';
import auth from './auth';
import { PLUGIN_ID } from '../pluginId';

jest.mock('jsonwebtoken', () => ({
  sign: jest.fn(() => 'mockedRefreshToken'), // Mock `jwt.sign` to return a dummy refresh token
  verify: jest.fn((token, secret) => {
    if (token === 'invalidToken') {
      throw new Error('Invalid token'); // Simulate an invalid token
    } else {
      return { userId: 1, secret: 'testDocumentId' }; // Simulate a successful verification
    }
  }),
}));

describe('Auth Middleware', () => {
  let strapiMock;
  let ctxMock;

  beforeEach(() => {
    // Mocking Strapi dependencies
    process.env.PRODUCTION_URL = 'https://redon2.ca/'; //awesome ppl 
    strapiMock = {
      config: {
        get: jest.fn().mockReturnValue({
          requestRefreshOnAll: true,
          refreshTokenSecret: 'testSecretKey',
          refreshTokenExpiresIn: '30d',
        }),
      },
      plugin: jest.fn().mockImplementation((pluginId) => {
        if (pluginId === 'users-permissions') {
          return {
            service: jest.fn().mockImplementation((serviceId) => {
              if (serviceId === 'jwt') {
                return {
                  issue: jest.fn().mockReturnValue('mockedJwtToken'), // Mock the 'issue' function
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
    };

    // Mocking ctx (context)
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
      }
    };
  });

  it('Generate refreshToken in body /api/auth/local', async () => {
    const middleware = auth({ strapi: strapiMock });

    await middleware(ctxMock, () => Promise.resolve());

    // Assert that a refresh token is added to response body
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
  ])('Generate refreshToken in cookie with refreshTokenExpiresIn: %o /api/auth/local', async ({ refreshTokenExpiresIn }) => {
    strapiMock.config.get.mockReturnValueOnce({
      ...strapiMock.config.get(),
      cookieResponse: true,
      refreshTokenExpiresIn
    });
  
    const middleware = auth({ strapi: strapiMock });
  
    await middleware(ctxMock, () => Promise.resolve());
  
    // Assert that a refresh token is added to response body
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
    expect(strapiMock.plugin).toHaveBeenCalledWith(expect.stringContaining(PLUGIN_ID));
    expect(jwt.sign).toHaveBeenCalledWith(
      expect.objectContaining({ userId: 1, secret: 'testDocumentId' }),
      'testSecretKey',
      { expiresIn: refreshTokenExpiresIn }
    );
  });
  it('Fail refresh to bad config', async () => {
    strapiMock.config.get.mockReturnValueOnce({
      ...strapiMock.config.get(),
      cookieResponse: true,
      refreshTokenExpiresIn: '1t', //bad param
    });
    const middleware = auth({ strapi: strapiMock });

    await expect(middleware(ctxMock, () => Promise.resolve())).rejects.toThrow('Invalid tokenExpires format. Use formats like "30d", "1h", "15m".');
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

    // Update ctxMock response to initialize it properly for the refresh scenario
    ctxMock.response = {
      body: {},
      message: 'OK',
    };

    const middleware = auth({ strapi: strapiMock });

    await middleware(ctxMock, () => Promise.resolve());

    expect(ctxMock.send).toHaveBeenCalledWith(
      expect.objectContaining({
        jwt: expect.any(String), // jwt should be returned in the response
      })
    );
  });

  it('should receive refreshToken if the rotation is enabled /api/auth/local/refresh', async () => {
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
  
    // Update ctxMock response to initialize it properly for the refresh scenario
    ctxMock.response = {
      body: {},
      message: 'OK',
    };
  
    // Mock the findOne method to return a valid token entry
    strapiMock.query = jest.fn().mockReturnThis();
    strapiMock.findOne = jest.fn().mockResolvedValue({
      id: 1,
      documentId: 'testDocumentId',
    });
  
    // Mock the delete method to do nothing
    strapiMock.delete = jest.fn().mockResolvedValue({});
  
    const middleware = auth({ strapi: strapiMock });
  
    await middleware(ctxMock, () => Promise.resolve());
  
    expect(ctxMock.send).toHaveBeenCalledWith(
      expect.objectContaining({
        jwt: expect.any(String), // jwt should be returned in the response
        refreshToken: expect.any(String), // refreshToken should be returned in the response
      })
    );
  });

  it('should respond with 401 for invalid refresh token', async () => {
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
  it('should respond with 401 if no data found for the given documentId', async () => {
    // Set up a valid refresh token
    const validRefreshToken = jwt.sign(
      { userId: 1, secret: 'testDocumentId' },
      'testSecretKey',
      { expiresIn: '30d' }
    );
  
    ctxMock.request = {
      method: 'POST',
      path: '/api/auth/local/refresh',
      body: {
        refreshToken: validRefreshToken,
      },
    };
  
    // Make the findOne return `null` to simulate no matching entry found
    strapiMock.query = jest.fn().mockReturnThis();
    strapiMock.findOne = jest.fn().mockResolvedValue(null);
  
    const middleware = auth({ strapi: strapiMock });
  
    await middleware(ctxMock, () => Promise.resolve());
  
    // Ensure the middleware sets status to 401 and responds with 'Invalid Token'
    expect(ctxMock.status).toBe(401);
    expect(ctxMock.response.body.error).toBe('Invalid Token');
  });
  
});
