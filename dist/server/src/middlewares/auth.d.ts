declare function auth({ strapi }: {
    strapi: any;
}): (ctx: any, next: any) => Promise<void>;
export default auth;
