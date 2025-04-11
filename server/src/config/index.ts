export default {
  default: {
    diego: true,
    refreshTokenSecret : 'SuperSecretKey',
    requestRefreshOnAll : false,
    refreshTokenExpiresIn : '1d',
    cookieResponse: false,
    refreshTokenRotation: false,
    refreshRoute: undefined,
    authRoute: undefined
  },
  validator() {},
};
