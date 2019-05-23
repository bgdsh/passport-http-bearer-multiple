import * as strategy from "passport-strategy";
import * as passport from "passport";
import { Request } from "express";
import { IStrategyOptions } from "./options.interface";
import { IToken } from "./token.interface";

export type VerifiedCallback = (err: Error, user?: any, info?: any) => void;
export type VerifyMethod = (
  token: IToken,
  cb: VerifiedCallback,
  req?: Request
) => void;

export class Strategy<T> extends strategy.Strategy {
  private _passReqToCallback: boolean;
  private _verify: VerifyMethod;
  private _realm: string;
  private _scope: string[] = [];
  name: string;

  constructor(options: IStrategyOptions, verify: VerifyMethod) {
    super();
    if (!verify) {
      throw new TypeError("HTTPBearerStrategy requires a verify callback");
    }
    passport.Strategy.call(this);
    this.name = options.strategyName || "bearer";
    this._verify = verify;
    this._realm = options.realm || "Users";
    if (options.scope) {
      this._scope = Array.isArray(options.scope)
        ? options.scope
        : [options.scope];
    }
    this._passReqToCallback = options.passReqToCallback || false;
  }

  authenticate(req: Request) {
    let token: IToken = { token: "", from: "" };
    if (req.headers && req.headers.authorization) {
      token.from = "headers.authorization";
      var parts = req.headers.authorization.split(" ");
      if (parts.length == 2) {
        const scheme = parts[0];
        const credentials = parts[1];
        token.scheme = scheme.toLowerCase();
        token.token = credentials;
      } else {
        token.token = req.headers.authorization;
      }
    }
    if (req.body && req.body.access_token) {
      if (token.token) {
        return this.fail(400);
      }
      token.token = req.body.access_token;
      token.from = "body.access_token";
    }
    if (req.query && req.query.access_token) {
      if (token.token) {
        return this.fail(400);
      }
      token.token = req.query.access_token;
      token.from = "query.access_token";
    }
    if (!token.token) {
      return this.fail(this._challenge(), 401);
    }
    const verified = (err?: Error, user?: T, info?: { message?: string }) => {
      if (err) {
        return this.error(err);
      }
      if (!user) {
        info = info || {};
        return this.fail(this._challenge("invalid_token", info.message), 401);
      }
      this.success(user, info);
    };
    if (this._passReqToCallback) {
      this._verify(token, verified, req);
    } else {
      this._verify(token, verified);
    }
  }

  _challenge(code?: string, desc?: string, uri?: string) {
    var challenge = 'Bearer realm="' + this._realm + '"';
    if (this._scope) {
      challenge += ', scope="' + this._scope.join(" ") + '"';
    }
    if (code) {
      challenge += ', error="' + code + '"';
    }
    if (desc && desc.length > 0) {
      challenge += ', error_description="' + desc + '"';
    }
    if (uri && uri.length > 0) {
      challenge += ', error_uri="' + uri + '"';
    }
    return challenge;
  }
}
