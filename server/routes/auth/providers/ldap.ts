import passport from "@outlinewiki/koa-passport";
import Router from "koa-router";
// @ts-expect-error ts-migrate(7016) FIXME: Could not find a declaration file for module 'pass... Remove this comment to see the full error message
import { Strategy as LdapStrategy } from "passport-ldapauth";
import accountProvisioner from "@server/commands/accountProvisioner";
import env from "@server/env";

import passportMiddleware from "@server/middlewares/passport";

const LDAP_URL = process.env.LDAP_URL;
const LDAP_USER = process.env.LDAP_USER;
const LDAP_PASSWORD = process.env.LDAP_PASSWORD;
const LDAP_SEARCH_BASE = process.env.LDAP_SEARCH_BASE;
const LDAP_DOMAIN = process.env.LDAP_DOMAIN;
const LDAP_COMPANY = process.env.LDAP_COMPANY;
const LDAP_USER_FIELD = process.env.LDAP_USER_FIELD;

const router = new Router();
const providerName = "ldapauth";

export const config = {
  name: "LDAP",
  enabled: !!LDAP_URL,
};

if (LDAP_URL) {
  passport.use(
    new LdapStrategy(
      {
        server: {
          url: LDAP_URL,
          bindDN: LDAP_USER,
          bindCredentials: LDAP_PASSWORD,
          searchBase:LDAP_SEARCH_BASE,
          searchFilter: LDAP_USER_FIELD + '={{username}}',
          passReqToCallback: true,
        }  
      },
      async function (user, done) {
        try{

           const result = await accountProvisioner({
              team: {
                name: LDAP_COMPANY,
                domain: LDAP_DOMAIN,
                subdomain: "",
              },
              user: {
                name: user.displayName,
                email: user.mail,
                username: user[LDAP_USER_FIELD],
              },
              authenticationProvider: {
                name: providerName,
                providerId: LDAP_DOMAIN,
              },
              authentication: {
                providerId: user[LDAP_USER_FIELD],
              },
            });
          return done(null, result.user, result);
      }
      catch (err){
        return done(err, null);
      }
  }));

  router.post("ldap", passportMiddleware(providerName));    
}

export default router;
