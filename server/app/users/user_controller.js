module.exports = function(app, config, log, policy) {

  var db = require('mongoose'),
    express = require('express'),
    captcha = require('seedio-recaptcha'),
    path = require('path'),
    response = new (require('seedio-response'))(config, log),
    _ = require('lodash');

  var AdminRole = config.roles.admin,
      User = db.model('User'),
      UserRole = db.model('UserRole');


  /* ************************************************** *
   * ******************** API Routes and Permissions
   * ************************************************** */

  var api = express.Router();

  // Populate users by the '_id' attribute when present.
  api.param('id', User.findByIdParam);

  // Query all users or create a new user.
  api.route('/')
    .get(policy.ensureLoggedInApi('/login'), query)
    .post(policy.checkLoggedInApi(), captcha.ensureAdminOrCaptcha(config), User.checkWritePermission, validateUsername, validateEmail, create);

  // All specific user API requests require authentication.
  api.route(/\/.+/).all(policy.ensureLoggedInApi('/login'));

  // Completely remove a user from the database.
  api.route('/:id/purge')
    .delete(User.checkPurgePermission, purge);

  // A user can request access to content or functions.
  api.route('/:id/requestAccess')
    .post(User.checkWritePermission, requestResourceAccess);

  // Increase a user's permission to access new content or perform new functions.
  api.route('/:id/grantAccess')
    .post(User.checkGrantPermission, grantResourceAccess);

  api.route('/:id/setPassword')
    .post(User.checkAdminPermission, setPassword);

  // Find, update, or delete a user.
  api.route('/:id')
    .get(User.checkReadPermission, find)
    .put(User.checkWritePermission, validateOptionalUsername, validateOptionalEmail, update)
    .delete(User.checkDeletePermission, remove);

  // Use the router and set the router's base url.
  app.use('/api/:version/users', api);

  // Checks if a username is valid.
  app.post('/api/:version/validateUsername', validateUsername);

  app.post('/api/:version/validateEmail', validateEmail);

  app.post('/api/:version/validateUsernameOrEmail', validateUsernameOrEmail);

  /* ************************************************** *
   * ******************** User Web Routes
   * ************************************************** */


  // Create a router for the following group of requests.
  var web = express.Router();

  // Populate users by _id when present.
  web.param('id', User.findByIdParam);

  // All the following user requests require authentication.
  web.route('/*').all(policy.ensureLoggedInApi('/login'));

  // Use the web router and set the router's base url.
  app.use('/users', web);


  /* ************************************************** *
   * ******************** Web Route Methods
   * ************************************************** */



  /* ************************************************** *
   * ******************** Route Methods
   * ************************************************** */

  /**
   * Return the user data found in the current query object.
   */
  function find(req, res, next) {
    res.setData(req.queriedUser, next);
  }

  /**
   * Query for all users an authenticated user has access to.
   * Admins will receive a list of all the users. Developers and
   * OEMs will receive a list of exactly one user, themselves.
   *
   * Preconditions:
   *   1. User is authenticated and has permission to access this type of data.
   */
  function query(req, res, next) {
    var role = req.user.role;

    if( ! _.isObject(role) || role.index > AdminRole) {
      res.setData([ req.user ], next);
    } else {
      // If user is an admin, return all users with all of their data.
      User.find({}).exec(function(err, users) {
        if (err) {
          next(err);
        } else {
          res.setData(users || [], next);
        }
      });
    }
  }

  /**
   * Create a new user and returns the new user object
   * or an error to the requester.
   */
  function create(req, res, next) {
    var user = new User();

    User.isValidUsername(req.body.username, true, req.queriedUser, function(err) {
      if(err) {
        next(err);
      } else {
        user.update(req.body, req.user, function(err, user) {
          if(err) {
            next(err);
          } else if(!user) {
            res.setError("Updated user object was not returned.", 500);
          } else {
            if( ! _.isObject(req.user)) {
              req.login(user, function(err) {
                if(err) {
                  next(err);
                } else {
                  res.setData(user, next);
                }
              });
            } else {
              res.setData(user, next);
            }
          }
        });
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

  /**
   * Request access to one or more resources for a user.
   */
  function requestResourceAccess(req, res, next) {
    req.queriedUser.requestResourceAccess(req.body.resources, function(err, results) {
      if(err) {
        next(err);
      } else {
        res.setData(results, next)
      }
    });
  }

  /**
   * Grant access to one or more resources for a user.
   */
  function grantResourceAccess(req, res, next) {
    req.queriedUser.grantResourceAccess(req.body.resources, function(err, results) {
      if(err) {
        next(err);
      } else {
        res.setData(results, next);
      }
    });
  }

  /**
   * Check if a username is valid and return success or an error.
   */
  function validateUsername(req, res, next) {
    User.isValidUsername(req.body.username || req.query.username, true, req.queriedUser, function(err) {
      if(err) {
        next(err);
      } else {
        res.setData(true, next);
      }
    });
  }

  /**
   * Check if a email is valid and return success or an error.
   */
  function validateEmail(req, res, next) {
    User.isValidEmail(req.body.email || req.query.email, true, req.queriedUser, function(err) {
      if(err) {
        next(err);
      } else {
        res.setData(true, next);
      }
    });
  }

  /**
   * Check if a username or email address is valid.  Then return
   * success or an error to the requester.
   */
  function validateUsernameOrEmail(req, res, next) {
    var usernameOrEmail = req.body.usernameOrEmail || req.query.usernameOrEmail;

    if(User.isEmail(usernameOrEmail)) {
      User.findByEmail(usernameOrEmail, function(err) {
        if(err) {
          next(err);
        } else {
          res.setData(true, next);
        }
      });
    } else {
      User.findByUsername(usernameOrEmail, function(err) {
        if(err) {
          next(err);
        } else {
          res.setData(true, next);
        }
      });
    }
  }

  /**
   * Set a new password for a user and notify them via email of the
   * new password.  This should only be used by admins.
   */
  function setPassword(req, res, next) {
    var password = req.body.password || req.query.password;

    if(password !== undefined && password !== null && password !== "") {
      req.queriedUser.update({password: password}, req.user, function(err, user) {
        if(err) {
          next(err);
        } else {
          res.setData(user, next);
        }
      });
    } else {
      res.setBadRequest('server.error.invalidPassword');
    }
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