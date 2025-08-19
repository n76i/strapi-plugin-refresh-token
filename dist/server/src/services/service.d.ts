import type { Core } from '@strapi/strapi';
export declare function calculateExpirationThreshold(tokenExpires: any): Date;
declare const service: ({ strapi }: {
    strapi: Core.Strapi;
}) => {
    cleanExpiredTokens(user: any): Promise<void>;
    create(user: any, request: any): Promise<any>;
};
export default service;
