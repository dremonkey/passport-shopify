/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The Shopify authentication strategy authenticates requests by delegating to
 * Shopify using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and `shopify` object. The callback should then call the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *  - `shop`          your Shopify Shop URL (yourshopname.myshopify.com)
 *  - `clientID`      your Shopify application's API Key
 *  - `clientSecret`  your Shopify application's Shared Secret
 *  - `callbackURL`   URL to which Shopify will redirect the user after granting authorization
 *
 * Example:
 *    StripeStrategy = require('passport-stripe').Strategy;
 *
 *    ...
 *
 *    passport.use(new ShopifyStrategy({
 *      shop: 'yourshop.myshopify.com',   
 *      clientID: '123-456-789',
 *      clientSecret: 'shhh-its-a-secret'
 *      callbackURL: 'https://www.example.net/auth/shopify/callback'
 *    },
 *    function(accessToken, refreshToken, shopify, done) {
 *      User.findOrCreate(..., function (err, user) {
 *        done(err, user);
 *      });
 *    }));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy (options, verify) {
  options = options || {};

  if (typeof options.shop === 'undefined') {
    throw new TypeError('The shop option is required!');
  }

  var baseUrl = 'https://' + options.shop + '/admin/';

  options.authorizationURL = options.authorizationURL || baseUrl + 'oauth/authorize';
  options.tokenURL = options.tokenURL || baseUrl + 'oauth/access_token';
  options.shopURL = options.shopURL || baseUrl + 'shop.json';
  options.scopeSeparator = options.scopeSeparator || ',';

  OAuth2Strategy.call(this, options, verify);
  
  this.name = 'shopify';

  // this seems to have been removed from passport-oauth in v1.1.2
  // so adding it back so we can access the options from Strategy.prototype.userProfile
  this._options = options; 
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
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function (accessToken, done) {
  this._oauth2.get(this._options.shopURL, accessToken, function (err, body, res) {
    
    if (err) {
      return done(new InternalOAuthError('failed to fetch user profile', err));
    }

    try {
      var data = JSON.parse(body)
        , shop = {};

      shop.provider ='shopify';
      shop.id = data.shop.id;

      // Owner Info
      shop.owner = data.shop.shop_owner;
      shop.email = data.shop.email;

      // Shop Info
      shop.name = data.shop.name;
      shop.url = data.shop.domain;
      shop.phone = data.shop.phone;
      shop.currency = data.shop.currency;

      // Address Info
      shop.country = data.shop.country;
      shop.address = data.shop.address1;
      shop.city = data.shop.city;
      shop.state = data.shop.province_code;
      shop.zip = data.shop.zip;

      shop._raw = body;
      shop._json = data;

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