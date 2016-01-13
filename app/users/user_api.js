/**
 * Defines routes related to user accounts.
 * @param app is the express application object.
 * @param config is the server's configuration object.
 * @param log is the server's current logger instance.
 */
module.exports = function(app, config, log) {

  var db = require('mongoose'),
    error = require(config.libsDirectory + 'error'),
    express = require('express'),
    captcha = require('seedio-recaptcha'),
    path = require('path'),
    response = new (require('seedio-response'))(config, log),
    _ = require('lodash');

  // Load models used by the controller.
  var User = db.model('User');


  /* ************************************************** *
   * ******************** API Routes and Permissions
   * ************************************************** */

  var api = express.Router();

  // Populate users by the '_id' attribute when present.
  api.param('id', User.routeFindById);

  // Populate users by the 'email' attribute when present.
  api.param('email', User.routeFindById);

  // Populate users by the 'email' or '_id' attribute when present.
  api.param('emailOrId', User.routeFindByIdOrEmail);

  // Query all users or create a new user.
  api.route('/')
    .get(query)
    .post(create);

  // All specific user API requests require authentication.
  //api.route(/\/.+/).all(policy.ensureLoggedInApi('/login'));

  // Completely remove a user from the database.
  api.route('/:id/purge')
    .delete(purge);

  // Find, update, or delete a user.
  api.route('/:id')
    .get(find)
    .put(update)
    .delete(remove);

  // Use the router and set the router's base url.
  app.use('/api/:version/users', api);


  /* ************************************************** *
   * ******************** Route Methods
   * ************************************************** */

  /**
   * Return the user data found in the current query object.
   */
  function find(req, res, next) {
    res.setData(req.query, next);
  }

  /**
   * Query for all users.
   */
  function query(req, res, next) {
    // If user is an admin, return all users with all of their data.
    User.find({}).exec(function(err, users) {
      if (err) {
        next(err);
      } else {
        res.setData(users || [], next);
      }
    });
  }

  /**
   * Create a new user and returns the new user object
   * or an error to the requester.
   */
  function create(req, res, next) {
    var user = new User();

    user.update(req.body, req.user, function(err, user) {
      if(err) {
        next(err);
      } else if( ! user) {
        next(error.build('server.user.updateDidNotReturnUser', 500));
      } else {

        // If a new user was created by a non-authenticated user
        // then log the new user in to their account.
        if( ! req.user) {
          req.login(user, function(err) {
            if(err) {
              next(err);
            } else {
              res.setData(user, next);
            }
          });
        } else {

          // Return the new user's data.
          res.setData(user, next);
        }
      }
    });
  }

  /**
   * Update the user based on the request body object.
   */
  function update(req, res, next) {
    var activated = undefined,
        deactivatedMessage = undefined;

    // If the activated attribute is set to be updated, we should
    // instead use the activate and deactivate methods.  So strip
    // out the activated attribute and update it later.
    if(req.body['activated'] === true && req.queriedUser.activated === false) {
      activated = true;
      delete req.body.activated;
    } else if(req.body['activated'] === false && req.queriedUser.activated === true) {
      activated = false;
      deactivatedMessage = req.body.deactivatedMessage;
      delete req.body.deactivatedMessage;
      delete req.body.activated;
    }

    req.queriedUser.update(req.body, req.user, function(err, user) {
      if(err) {
        next(err);
      } else {
        handleActivatedAttribute(activated, deactivatedMessage, user, function(err, user) {
          if(err) {
            next(err);
          } else {
            res.setData(user, next);
          }
        });
      }
    });
  }

  /**
   * Delete an existing user and return the deleted user.
   */
  function remove(req, res, next) {
    req.queriedUser.delete(req.user, function(err, user) {
      if(err) {
        next(err);
      } else {
        res.setData(user, next);
      }
    });
  }

  /**
   * Purge an existing user from the database and return
   * the purged user.
   */
  function purge(req, res, next) {
    req.queriedUser.purge(req.user, function(err, user) {
      if(err) {
        next(err);
      } else {
        res.setData(user, next);
      }
    });
  }



  /* ************************************************** *
   * ******************** Private Methods
   * ************************************************** */

  /**
   * Handle an update to the activated attribute by using the
   * activate and deactivate methods.
   * @param activated is the new activated attribute value.
   * @param user is the user to update.
   * @param cb is a callback method where an error and/or user are returned.
   */
  var handleActivatedAttribute = function(activated, deactivatedMessage, user, cb) {
    if(activated === true) {
      user.activate(cb);
    } else if(activated === false) {
      user.deactivate(deactivatedMessage, cb);
    } else {
      cb(undefined, user);
    }
  };

  /**
   * If a username attribute is present, check if it is valid.
   * Return an error to the requester if the username is invalid.
   */
  function validateOptionalUsername(req, res, next) {
    var username = req.body.username || req.query.username;

    if(username !== undefined) {
      User.isValidUsername(username, true, req.queriedUser, next);
    } else {
      next();
    }
  }

  /**
   * If a email attribute is present, check if it is valid.
   * Return an error to the requester if the email is invalid.
   */
  function validateOptionalEmail(req, res, next) {
    var email = req.body.email || req.query.email;

    if(email !== undefined) {
      User.isValidEmail(email, true, req.queriedUser, next);
    } else {
      next();
    }
  }


};