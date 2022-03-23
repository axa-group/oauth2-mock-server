'use strict';
const assert = require('assert');
const {OAuth2Server} = require('oauth2-mock-server');
const request = require('supertest');
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oidc');


function withGoogleOAuthServer(user) {
	before(async function startGoogleOAuthServer() {
		this.oauthServer = new OAuth2Server();

		await this.oauthServer.issuer.keys.generate('RS256');

		this.oauthServer.service.on('beforeTokenSigning', (token, req) => {
			token.payload.sub = user;
		});

		await this.oauthServer.start(0, 'localhost');
		const issuer = this.oauthServer.issuer.url;
		this.oauthConfig = {
			// Google OAuth Config for passport
			clientID: '123',
			clientSecret: 'secret',
			issuer,
			authorizationURL: `${issuer}/authorize`,
			tokenURL: `${issuer}/token`
		};
	});

	after(async function stopGoogleOAuthServer() {
		await this.oauthServer.stop();
	});
}

function withApp() {
	before(function startWebServer(done) {
		const self = this;
		const {oauthConfig} = self;
		const app = express();

		app.use(session({secret: 'cat'}))

		function onGoogleAuth(issuer, profile, cb) {
			let user = {id: profile.id, name: 'Tinky Winky', issuer};
			return cb(null, user);
		}

		const googleOptions = {
			...oauthConfig,
			scope: ['email', 'profile'],
			callbackURL: '/auth/google/redirect'
		};

		const googleStrategy = new GoogleStrategy(googleOptions, onGoogleAuth);

		passport.use(googleStrategy);
		passport.serializeUser((user, done) => done(null, user));
		passport.deserializeUser((user, done) => done(null, user));
		app.use(passport.initialize());
		app.use(passport.session());


		app.get('/no-account', function (req, res) {
			// Something went wrong
			return res.status(403).end('no account found');
		});

		app.get('/auth/google/login', passport.authenticate('google'));
		app.get('/auth/google/redirect', passport.authenticate('google'
			, {failureRedirect: 'no-account'})
			, function (req, res) {
				// Save current passport configuration
				return res.json(req.user);
			});

		this.server = app.listen(0, function () {
			self.serverUrl = 'http://localhost:' + this.address().port;
			done();
		});
	});
	after(function destroyWebServer(done) {
		const {server} = this;
		server.close(done);
	});
}

describe('Simple login', function () {
	const expectedUserId = '456';
	withGoogleOAuthServer(expectedUserId);
	withApp();
	it('should be able to login', async function () {
		const {serverUrl} = this;
		await request
			// Use supertest agent (or any other cookie jar) to reuse cookies between redirects
			.agent(serverUrl) 
			.get('/auth/google/login')
			.redirects(5)
			.expect(function (response) {
				const {body} = response;
				assert.deepStrictEqual(body.id, expectedUserId);
			});
	});
});
