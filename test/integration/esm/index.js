import { OAuth2Server } from 'oauth2-mock-server';

const server = new OAuth2Server();
console.log('ESM import: OK', server.constructor.name);
