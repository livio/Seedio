module.exports = function(app, config, log) {

  var db = require('mongoose'),
      express = require('express'),
      LocalStrategy = require('passport-local').Strategy,
      passport = require('passport'),
      captcha = require('seedio-recaptcha');

  var AccessToken = db.model('AccessToken'),
      User = db.model('User');


  /* ************************************************** *
   * ******************** Routes and Permissions
   * ************************************************** */

  var api = express.Router();

  // Populate users by the '_id' attribute when present.
  api.param('userId', User.findByIdParam);

  // Endpoint where Users can attempt to login or logout.  Login may require
  // a captcha, in which case an error and a flag will be returned.
  api.route('/login')
    .post(User.findByUsernameQuery, captcha.checkLoginCaptcha(config), login)
    .delete(logout);

  // Log a user out.
  api.route('/logout')
    .get(logout)
    .put(logout)
    .post(logout)
    .delete(logout);

  // Request a password reset and a reset password token will be returned to be
  // used in the actual reset password API request.
  api.route('/passwordReset')
    .post(captcha.ensureAdminOrCaptcha(config), User.findByUsernameQuery, requestPasswordReset);

  // Reset a user's password if they have a valid reset password token and security
  // answer.  A captcha may be required, in which case an error and a flag will be returned.
  api.route('/passwordReset/:userId')
    .post(captcha.checkLoginCaptcha(config), User.checkPasswordReset, passwordReset);

  // Use the router and set the router's base url.
  app.use('/api/:version/', api);


  /* ************************************************** *
   * ******************** Web Routes and Permissions
   * ************************************************** */

  var web = express.Router();

  // Use the router and set the router's base url.
  app.use('/', web);


  /* ************************************************** *
   * ******************** Web Route Methods
   * ************************************************** */


  /* ************************************************** *
   * ******************** Route Methods
   * ************************************************** */

  /**
   * End a user's session.
   */
  function logout(req, res, next) {
    req.logout();
    res.setData(true, next);
  }

  function login(req, res, next) {
    passport.authenticate('local', function(err, user) {
      if (err) {
        next(err);
      } else {
        if(req.body.remember) {
          req.session.cookie.expires = false; // Cookie does not expire and will use MongoStores ttl value.
        } else {
          req.session.cookie.maxAge = config.session.cookie.maxAge; // Cookie will expire after configured maxAge.
        }

        req.login(user, function(err) {
          if(err) {
            next(err);
          } else {
            res.setData({ redirect: req.session.returnTo || '/applications' }, next);
          }
        });
      }
    })(req, res, next);
  }

  /**
   * Create a password reset token and return a it in the form of a url.
   * If the user has a email, then an email notification will be sent with the
   * password reset link.  If the user does not have an email, then the url
   * will be returned in the response.
   */
  function requestPasswordReset(req, res, next) {
    req.queriedUser.handlePasswordResetRequest(function(err, user, url) {
      if(err) {
        next(err);
      } else if(url !== undefined) {
        // User does not have an email address so we need to redirect them to
        // the password reset form.
        res.setData({ redirect: url }, next);
      } else {
        // An email was or will be sent to their email, so just return a message to tell them that.
        res.setData({ message: req.i18n.t('server.user.passwordResetEmailSent')}, next);
      }
    });
  }

  /**
   * Set a new user password if the reset token and security answer are correct.
   */
  function passwordReset(req, res, next) {
    var securityAnswer = req.body.securityAnswer || req.query.securityAnswer,
      password = req.body.password || req.query.password,
      passwordResetToken = req.body.passwordReset || req.query.passwordReset;

    req.queriedUser.resetPassword(passwordResetToken, securityAnswer, password, function(err, user) {
      if(err) {
        next(err);
      } else {
        res.setData(user, next);
      }
    });
  }


  /* ************************************************** *
   * ******************** Passport Methods
   * ************************************************** */

  /**
   * Authenticate a user by username and password.
   */
  passport.use(new LocalStrategy(function(username, password, cb) {
    User.findByUsername(username, function(err, user) {
      if(err) {
        cb(err);
      } else {
        user.authenticate(password, cb);
      }
    });
  }));

  /**
   * Only store the user's ID in the session object.
   */
  passport.serializeUser(function(user, done) {
    done(null, user._id);
  });

  /**
   * Use the user ID in the session object to find a user
   * and return that value to passport for authentication
   * purposes.
   */
  passport.deserializeUser(function(userId, done) {
    User.findById(userId).populate('roles').exec(done);
  });

};