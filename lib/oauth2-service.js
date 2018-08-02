/**
* Copyright (c) AXA Partners
*
* Licensed under the AXA Partners License (the "License"); you
* may not use this file except in compliance with the License.
* A copy of the License can be found in the LICENSE.md file distributed
* together with this file.
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
**/

/**
 * OAuth2 Service library
 * @module lib/oauth2-service
 */

'use strict';

const express = require('express');
const bodyParser = require('body-parser');

const OPENID_CONFIGURATION_PATH = '/.well-known/openid-configuration';
const TOKEN_ENDPOINT_PATH = '/token';
const JWKS_URI_PATH = '/jwks';

const _issuer = Symbol('issuer');
const _requestHandler = Symbol('requestHandler');

const buildRequestHandler = Symbol('buildRequestHandler');
const openidConfigurationHandler = Symbol('openidConfigurationHandler');
const jwksHandler = Symbol('jwksHandler');
const tokenHandler = Symbol('tokenHandler');

/**
 * Provides a request handler for an OAuth 2 server.
 */
class OAuth2Service {
  /**
   * Creates a new instance of OAuth2Server.
   * @param {OAuth2Issuer} oauth2Issuer The OAuth2Issuer instance that will be offered through the service.
   */
  constructor(oauth2Issuer) {
    this[_issuer] = oauth2Issuer;

    this[_requestHandler] = this[buildRequestHandler]();
  }

  /**
   * Returns the OAuth2Issuer instance bound to this service.
   * @type {OAuth2Issuer}
   */
  get issuer() {
    return this[_issuer];
  }

  /**
   * Builds a JWT with a key in the keystore. The key will be selected in a round-robin fashion.
   * @param {Boolean} signed A value that indicates whether or not to sign the JWT.
   * @param {(String|Array<String>|jwtTransform)} [scopesOrTransform] A scope, array of scopes, or JWT transformation callback.
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
    return this[_requestHandler];
  }

  [buildRequestHandler]() {
    let app = express();
    app.disable('x-powered-by');

    app.get(OPENID_CONFIGURATION_PATH, this[openidConfigurationHandler].bind(this));
    app.get(JWKS_URI_PATH, this[jwksHandler].bind(this));
    app.post(TOKEN_ENDPOINT_PATH, bodyParser.urlencoded({ extended: false }), this[tokenHandler].bind(this));

    return app;
  }

  [openidConfigurationHandler](req, res) {
    let openidConfig = {
      issuer: this.issuer.url,
      token_endpoint: `${this.issuer.url}${TOKEN_ENDPOINT_PATH}`,
      token_endpoint_auth_methods_supported: [ 'none' ],
      jwks_uri: `${this.issuer.url}${JWKS_URI_PATH}`,
      response_types_supported: [ 'code' ],
      grant_types_supported: [ 'client_credentials' ]
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
      'Pragma': 'no-cache'
    });

    if (req.body.grant_type != 'client_credentials') {
      return res.status(400).json({
        error: 'invalid_grant'
      });
    }
  
    let token = this.buildToken(true, req.body.scope, tokenTtl);
  
    let resp = {
      access_token: token,
      token_type: 'Bearer',
      expires_in: tokenTtl,
      scope: req.body.scope
    };
  
    return res.json(resp);
  }
}

module.exports = OAuth2Service;
