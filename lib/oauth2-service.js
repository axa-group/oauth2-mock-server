/**
 * Copyright (c) AXA Assistance France
 *
 * Licensed under the AXA Assistance France License (the "License"); you
 * may not use this file except in compliance with the License.
 * A copy of the License can be found in the LICENSE.md file distributed
 * together with this file.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * OAuth2 Service library
 * @module lib/oauth2-service
 */

'use strict';

const express = require('express');
const bodyParser = require('body-parser');
const basicAuth = require('basic-auth');
const { EventEmitter } = require('events');
const uuidv4 = require('uuid').v4;

const OPENID_CONFIGURATION_PATH = '/.well-known/openid-configuration';
const TOKEN_ENDPOINT_PATH = '/token';
const JWKS_URI_PATH = '/jwks';
const AUTHORIZE_PATH = '/authorize';
const USERINFO_PATH = '/userinfo';
const REVOKE_PATH = '/revoke';

const issuer = Symbol('issuer');
const requestHandler = Symbol('requestHandler');

const buildRequestHandler = Symbol('buildRequestHandler');
const openidConfigurationHandler = Symbol('openidConfigurationHandler');
const jwksHandler = Symbol('jwksHandler');
const tokenHandler = Symbol('tokenHandler');
const authorizeHandler = Symbol('authorizeHandler');
const userInfoHandler = Symbol('userInfoHandler');
const revokeHandler = Symbol('revokeHandler');

/**
 * Provides a request handler for an OAuth 2 server.
 */
class OAuth2Service extends EventEmitter {
  /**
   * Creates a new instance of OAuth2Server.
   * @param {OAuth2Issuer} oauth2Issuer The OAuth2Issuer instance
   *     that will be offered through the service.
   */
  constructor(oauth2Issuer) {
    super();
    this[issuer] = oauth2Issuer;

    this[requestHandler] = this[buildRequestHandler]();
  }

  /**
   * Returns the OAuth2Issuer instance bound to this service.
   * @type {OAuth2Issuer}
   */
  get issuer() {
    return this[issuer];
  }

  /**
   * Builds a JWT with a key in the keystore. The key will be selected in a round-robin fashion.
   * @param {Boolean} signed A value that indicates whether or not to sign the JWT.
   * @param {(String|Array<String>|jwtTransform)} [scopesOrTransform] A scope, array of scopes,
   *     or JWT transformation callback.
   * @param {Number} [expiresIn] Time in seconds for the JWT to expire. Default: 3600 seconds.
   * @returns {String} The produced JWT.
   */
  buildToken(signed, scopesOrTransform, expiresIn) {
    return this.issuer.buildToken(signed, null, scopesOrTransform, expiresIn);
  }

  /**
   * Returns a request handler to be used as a callback for http.createServer().
   * @type {Function}
   */
  get requestHandler() {
    return this[requestHandler];
  }

  [buildRequestHandler]() {
    const app = express();
    app.disable('x-powered-by');

    app.get(OPENID_CONFIGURATION_PATH, this[openidConfigurationHandler].bind(this));
    app.get(JWKS_URI_PATH, this[jwksHandler].bind(this));
    app.post(TOKEN_ENDPOINT_PATH,
      bodyParser.urlencoded({ extended: false }),
      this[tokenHandler].bind(this));
    app.get(AUTHORIZE_PATH, OAuth2Service[authorizeHandler]);
    app.get(USERINFO_PATH, this[userInfoHandler].bind(this));
    app.post(REVOKE_PATH, this[revokeHandler].bind(this));

    return app;
  }

  [openidConfigurationHandler](req, res) {
    const openidConfig = {
      issuer: this.issuer.url,
      token_endpoint: `${this.issuer.url}${TOKEN_ENDPOINT_PATH}`,
      authorization_endpoint: `${this.issuer.url}${AUTHORIZE_PATH}`,
      userinfo_endpoint: `${this.issuer.url}${USERINFO_PATH}`,
      token_endpoint_auth_methods_supported: ['none'],
      jwks_uri: `${this.issuer.url}${JWKS_URI_PATH}`,
      response_types_supported: ['code'],
      grant_types_supported: ['client_credentials', 'authorization_code', 'password'],
      token_endpoint_auth_signing_alg_values_supported: ['RS256'],
      response_modes_supported: ['query'],
      id_token_signing_alg_values_supported: ['RS256'],
      revocation_endpoint: `${this.issuer.url}${REVOKE_PATH}`,
    };

    return res.json(openidConfig);
  }

  [jwksHandler](req, res) {
    res.json(this.issuer.keys);
  }

  [tokenHandler](req, res) {
    const tokenTtl = 3600;

    res.set({
      'Cache-Control': 'no-store',
      Pragma: 'no-cache',
    });

    let xfn;
    let { scope } = req.body;
    const credentials = basicAuth(req);
    const clientId = credentials ? credentials.name : null;

    switch (req.body.grant_type) {
      case 'client_credentials':
        xfn = (header, payload) => {
          Object.assign(payload, {
            aud: clientId,
            scope,
          });
        };
        break;
      case 'password':
        xfn = (header, payload) => {
          Object.assign(payload, {
            sub: req.body.username,
            amr: ['pwd'],
            scope,
          });
        };
        break;
      case 'authorization_code':
        scope = 'dummy';
        xfn = (header, payload) => {
          Object.assign(payload, {
            sub: 'johndoe',
            amr: ['pwd'],
            scope,
          });
        };
        break;
      case 'refresh_token':
        scope = 'dummy';
        xfn = (header, payload) => {
          Object.assign(payload, {
            sub: 'johndoe',
            amr: ['pwd'],
            scope,
          });
        };
        break;
      default:
        return res.status(400).json({
          error: 'invalid_grant',
        });
    }

    const token = this.buildToken(true, xfn, tokenTtl);
    const body = {
      access_token: token,
      token_type: 'Bearer',
      expires_in: tokenTtl,
      scope,
    };
    if (req.body.grant_type !== 'client_credentials') {
      body.id_token = this.buildToken(true, (header, payload) => {
        Object.assign(payload, {
          sub: 'johndoe',
          aud: clientId,
        });
      }, tokenTtl);
      body.refresh_token = uuidv4();
    }
    const tokenEndpointResponse = {
      body,
      statusCode: 200,
    };
    this.emit('beforeResponse', tokenEndpointResponse);

    return res.status(tokenEndpointResponse.statusCode).json(tokenEndpointResponse.body);
  }

  static [authorizeHandler](req, res) {
    const { scope, state } = req.query;
    const responseType = req.query.response_type;
    const redirectUri = req.query.redirect_uri;
    const code = uuidv4();

    let targetRedirection = `${redirectUri}?code=${encodeURIComponent(code)}&scope=${encodeURIComponent(scope)}&state=${encodeURIComponent(state)}`;
    if (responseType !== 'code') {
      targetRedirection = `${redirectUri}?error=unsupported_response_type&error_description=The+authorization+server+does+not+support+obtaining+an+access+token+using+this+response_type.&state=${encodeURIComponent(state)}`;
    }

    res.redirect(targetRedirection);
  }

  [userInfoHandler](req, res) {
    const userInfoResponse = {
      body: {
        sub: 'johndoe',
      },
      statusCode: 200,
    };
    this.emit('beforeUserinfo', userInfoResponse);
    res.status(userInfoResponse.statusCode).json(userInfoResponse.body);
  }

  [revokeHandler](req, res) {
    const revokeResponse = {
      body: null,
      statusCode: 200,
    };
    this.emit('beforeRevoke', revokeResponse);
    return res.status(revokeResponse.statusCode).json(revokeResponse.body);
  }
}
module.exports = OAuth2Service;
