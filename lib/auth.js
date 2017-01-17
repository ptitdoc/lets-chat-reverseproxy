var _ = require('lodash'),
    mongoose = require('mongoose'),
    passport = require('passport'),
    ReverseProxyStrategy = require('passport-reverseproxy');

function ReverseProxy(options, core) {
    this.options = options;

    if (this.options.use_ldap_authorization) {
        this.ldap = require('lets-chat-ldap').auth;
    }

    this.core = core;
    this.key = 'reverseproxy';

    this.setup = this.setup.bind(this);
    this.getReverseProxyStrategy = this.getReverseProxyStrategy.bind(this);
    this.authenticate = this.authenticate.bind(this);
    this.getReverseProxyCallback = this.getReverseProxyCallback.bind(this);
    this.createSimpleReverseProxyUser = this.createSimpleReverseProxyUser.bind(this);
}

ReverseProxy.key = 'reverseproxy';

ReverseProxy.prototype.setup = function() {
    passport.use(this.getReverseProxyStrategy());
};

ReverseProxy.prototype.getReverseProxyStrategy = function() {
    var userHeader = this.options.userHeader;
    var headers = {};
    headers[userHeader] = { alias: 'dn_string', required: true };

    return new ReverseProxyStrategy(
        {
            headers: headers
        },
        function (headers, user, done) {
            return done(null, headers[userHeader]);
        }
    );
};

ReverseProxy.prototype.authenticate = function(req, cb) {
    cb = this.getReverseProxyCallback(cb);
    passport.authenticate('reverseproxy', cb)(req);
};

ReverseProxy.prototype.getReverseProxyCallback = function(done) {
    return function(err, dn_string, info) {
        if (err) {
            return done(err);
        }

        if (!dn_string) {
            // Authentication failed
            return done(err, dn_string, info);
        }

        var User = mongoose.model('User');
        User.findOne({ uid: dn.format() }, function (err, user) {
            if (err) {
                return done(err);
            }

	    dn = rfc2253.parse(dn_string);

            if (this.options.use_ldap_authorization) {
                var opts = _.extend(this.options.ldap, {'reverseproxy': true});
                return this.ldap.authorize(opts, this.core, dn.format(), done);

            } else {
                // Not using LDAP
                if (user) {
                    return done(null, user);
                } else {
                    this.createSimpleReverseProxyUser(dn,
                        function(err, newUser) {
                        if (err) {
                            console.error(err);
                            return done(err);
                        }
                        return done(err, newUser);
                    });
                }
            }
        }.bind(this));
    }.bind(this);
};

ReverseProxy.prototype.createSimpleReverseProxyUser = function(dn, cb) {
    this.core.account.create('reverseproxy', {
        uid: dn.format(),
        username: dn.get('CN'),
        displayName: dn.get('CN'),
        firstName: dn.get('CN'),
        lastName: dn.get('CN'),
        email: dn.get('CN').concat("@localhost.local")
    }, cb);
};

module.exports = ReverseProxy;
