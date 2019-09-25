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

'use strict';

const JWKStore = require('./lib/jwk-store');
const OAuth2Issuer = require('./lib/oauth2-issuer');
const OAuth2Server = require('./lib/oauth2-server');

module.exports = {
  JWKStore,
  OAuth2Issuer,
  OAuth2Server,
};
