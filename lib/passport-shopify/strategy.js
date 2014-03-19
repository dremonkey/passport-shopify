/**
 * Module dependencies.
 */
var util = require('util')
  , url = require('url')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The Shopify authentication strategy authenticates requests by delegating to
 * Shopify using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and `stripe` object, which contains additional info as outlined
 * here: https://stripe.com/docs/connect/oauth.
 * The callback should then call the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Shopify application's API Key
 *   - `clientSecret`  your Shopify application's Shared Secret
 *   - `callbackURL`   URL to which Stipe will redirect the user after granting authorization
 *
 * Examples:
 *     StripeStrategy = require('passport-stripe').Strategy;
 *
 *     ...
 *
 *     passport.use(new ShopifyStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/shopify/callback'
 *       },
 *       function(accessToken, refreshToken, shopify, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};

  if (typeof options.shop === 'undefined') {
    throw new TypeError('Shop option is required!');
  }

  var baseUrl = 'https://' + options.shop + '.myshopify.com/admin/';

  options.authorizationURL = options.authorizationURL || baseUrl + 'oauth/authorize',
  options.tokenURL = options.tokenURL || baseUrl + 'oauth/access_token',
  options.shopProfileURL = options.shopProfileURL || baseUrl + 'shop.json',
  options.scopeSeparator = options.scopeSeparator || ',';

  OAuth2Strategy.call(this, options, verify);
  this.name = 'shopify';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from Shopify.
 *
 * This overrides OAuth2Strategy.prototype.userProfile
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `shopify`
 *   - `id`               the user's Shopify ID
 *   - `username`         the user's Shopify store name
 *   - `displayName`      the user's full name
 *   - `profileUrl`       the URL of the profile for the user on Shopify
 *   - `emails`           the user's email address, only returns emails[0]
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function (accessToken, done) {
  this._oauth2.get(this._options.shopProfileURL, accessToken, function (err, body, res) {
    
    if (err) {
      return done(new InternalOAuthError('failed to fetch user profile', err));
    }

    try {
      var json = JSON.parse(body)
        , shop = {};

      shop.id = json.shop.id;
      shop.provider ='shopify';
      shop.owner = json.shop.shop_owner;
      shop.name = json.shop.name;
      shop.url = json.shop.domain;
      shop.email = json.shop.email;
      shop._raw = body
      shop._json = json

      done(null, shop)
    } 
    catch (e) {
      done(e)
    }
  });
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;