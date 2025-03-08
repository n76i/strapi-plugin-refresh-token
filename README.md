# 
<h1 align="center">
  Strapi5 Refresh Token plugin
</h1>

Strapi Plugin that extends the local authorization functionality to provide Refresh tokens.

## ⚠️ Compatibility with Strapi versions

- This plugin relies on Strapi5 new `documentId`. It will not work with earlier versions!
- Works with `local` provider only.

## ⚙️ Installation

To install the Strapi Refresh Token Plugin, simply run one of the following command:

```
npm install @redon2inc/strapi-plugin-refresh-token
```

```
yarn add @redon2inc/strapi-plugin-refresh-token
```

## Config

You will need to set the following environment variables:
```
 PRODUCTION_URL=value # used for cookie security if enabled
 REFRESH_JWT_SECRET=string 
 ```

This component relies on extending the `user-permissions` types. Extend it by adding the following to `./src/extensions/user-permissions/content-types/user/schema.json`

```javascript
// .. rest of schema
attributes:{
  // .. rest of attributes
  "refresh_tokens": {
      "type": "relation",
      "relation": "oneToMany",
      "target": "plugin::refresh-token.token",
      "mappedBy": "user",
      "private": true,
      "configurable": false
    }
}
// rest of code
```

Modify your plugins file  `config/plugin.ts` to have the following:


```javascript

  // ..other plugins
  'users-permissions': {
        config: {
          jwt: {
            /* the following  parameter will be used to generate:
             - regular tokens with username and password
             - refreshed tokens when using the refreshToken API
            */
            expiresIn: '2h', // This value should be lower than the refreshTokenExpiresIn below.
          },
        },
    },
  'refresh-token': {
    config: {
      refreshTokenExpiresIn: '30d', // this value should be higher than the jwt.expiresIn
      requestRefreshOnAll: false, // automatically send a refresh token in all login requests.
      refreshTokenSecret: env('REFRESH_JWT_SECRET') || 'SomethingSecret',
      cookieResponse: false, // if set to true, the refresh token will be sent in a cookie
      refreshTokenRotation: false, // forces a new Refresh token, deleting the previously used one from the db.
    },
  }
```

## API Usage:

when calling `POST`:`/api/auth/local` include the `requestRefresh` parameter:

```json
{
  "identifier":"username",
  "password":"VerySecurePassword",
  "requestRefresh": true
}
```
The API will respond with the following:
```javascript
{
  "jwt":"token...",
  "user": { /* user object */ },
  "refreshToken": "RefreshToken..."
}
```

to request a new access token use the following: 
`POST`:`/api/auth/local/refresh` with the following payload:
```json
{
  "refreshToken": "RefreshToken...",
}
```
if the Refresh token is valid, the API will return
```json
{
  "jwt": "NewAccessToken..",
  "refreshToken": "NewRefreshToken..", // only if the config.refreshTokenRotation is set to TRUE
}
```

## TODO:
- Expose API so user can clear all sessions on their own. 