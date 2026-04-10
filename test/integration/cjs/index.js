'use strict';

const { OAuth2Server } = require('oauth2-mock-server');

const server = new OAuth2Server();
console.log('CJS require: OK', server.constructor.name);
