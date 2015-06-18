module.exports = function(app, config, log) {

  var AdminRole = config.roles.admin,
      async = require('async'),
      crucial = require("crucial"),
      crypto = require('crypto'),
      DeveloperRole = config.roles.developer,
      db = require('mongoose'),
      isObjectIdString = new RegExp("^[0-9a-fA-F]{24}$"),
      i18n = require('i18next'),
      path = require('path'),
      ObjectId = db.Schema.ObjectId,
      Schema = db.Schema,
      uuid = require('node-uuid'),
      _ = require('lodash');

  var validateEmailRegEx = /^([\w-]+(?:\.[\w-]+)*)@((?:[\w-]+\.)*\w[\w-]{0,66})\.([a-z]{2,6}(?:\.[a-z]{2})?)$/i;

  var User = new Schema({
    activated:             { type: Boolean, default: true },
    dateCreated:           { type: Date, default: Date.now },
    deactivatedMessage:    { type: String, default: "" },
    deleted:               { type: Boolean, default: false },
    email:                 { type: String, trim: true, lowercase: true, sparse: true },
    failedLoginAttempts:   { type: Number, default: 0 },
    lastLogin:             { type: Date, default: Date.now },
    lastUpdated:           { type: Date, default: Date.now },
    lastUpdatedBy:         { type: ObjectId, ref: 'User' },
    passwordHash:          { type: String, default: "" },
    passwordResetHash:     { type: String, default: "" },
    requestedOemAccess:    { type: Boolean, default: false},
    roles:                 [{ type: ObjectId, ref: 'UserRole' }],
    securityQuestion:      { type: String, default: i18n.t('server.user.defaultSecurityQuestion') },
    securityAnswerHash:    { type: String, default: "" },
    username:              { type: String, trim: true, lowercase: true, unique: true }
  });


  /* ************************************************** *
   * ******************** Virtual Getters
   * ************************************************** */

  /**
   * Return the password hash value.
   */
  User.virtual('password').get(function() {
    return this.passwordHash;
  });

  /**
   * Return the password reset hash value.
   */
  User.virtual('passwordReset').get(function() {
    return this.passwordResetHash;
  });

  /**
   * Return the security answer hash value.
   */
  User.virtual('securityAnswer').get(function() {
    return this.securityAnswerHash;
  });

  /**
   * Return the most permissive role in a user's role list.
   * The most permissive is always the first role.
   */
  User.virtual('role').get(function() {
    if( ! (this.roles !== undefined && this.roles.length > 0)) {
      log.t("User role is undefined? ");
      log.t(this);
    }
    return (this.roles !== undefined && this.roles.length > 0) ? this.roles[0] : undefined;
  });


  /* ************************************************** *
   * ******************** Virtual Setters
   * ************************************************** */

  /**
   * Hash and save a new password for the user.  This
   * method is used by crucial and the virtual password
   * attribute.
   * @param password is the plain text password.
   * @param cb is a callback method were the updated user
   * or error is returned.
   */
  User.methods.setPassword = function(password, cb) {
    setUserPassword(this, password, cb);
  };

  /**
   * Hash and save a new password reset token for the user.
   * This method is used by crucial and the virtual password
   * reset attribute.
   * @param token is the plain text password reset token.
   * @param cb is a callback method were the updated user
   * or error is returned.
   */
  User.methods.setPasswordReset = function(token, cb) {
    setUserPasswordReset(this, token, cb);
  };

  /**
   * Hash and save a new security answer for the user.
   * This method is used by crucial and the virtual security
   * answer attribute.
   * @param securityAnswer is the plain text security answer.
   * @param cb is a callback method were the updated user
   * or error is returned.
   */
  User.methods.setSecurityAnswer = function(securityAnswer, cb) {
    setUserSecurityAnswer(this, securityAnswer, cb);
  };


  /* ************************************************** *
   * ******************** Static Methods
   * ************************************************** */

  /**
   * Returns whether or not a string is an email address.
   * @param v
   * @returns {boolean}
   */
  User.statics.isEmail = function(v) {
    return validateEmailRegEx.test(v);
  };

  /**
   * Find a user by username or return an error for the invalid username.
   * @param username is the username to query.
   * @param cb is a callback method where the user or error are returned.
   */
  User.statics.findByUsername = function(username, cb) {
    db.model('User').isValidUsername(username, false, undefined, function(err) {
      if(err) {
        cb(err);
      } else {
        db.model("User").findOne({username: username.toLowerCase()}).populate('roles').exec(function(err, user) {
          if(err) {
            cb(err);
          } else if(!user) {
            err = new Error(i18n.t('server.error.invalidUsername'));
            err.status = 400;
            cb(err);
          } else {
            cb(undefined, user);
          }
        });
      }
    });
  };

  /**
   * Find a user by email or return an error for the invalid email address.
   * @param email is the email address to query.
   * @param cb is a callback method where the user or error are returned.
   */
  User.statics.findByEmail = function(email, cb) {
    if(email !== undefined && email !== null && email !== "") {
      db.model('User').isValidEmail(email, false, undefined, function(err) {
        if(err) {
          cb(err);
        } else {
          db.model("User").findOne({email: email.toLowerCase()}).populate('roles').exec(function(err, user) {
            if(err) {
              cb(err);
            } else if(!user) {
              err = new Error(i18n.t('server.error.invalidEmail'));
              err.status = 400;
              cb(err);
            } else {
              cb(undefined, user);
            }
          });
        }
      });
    } else {
      var err = new Error(i18n.t('server.error.invalidEmail'));
      err.status = 400;
      cb(err);
    }
  };

  /**
   * Checks if the username specified is valid.
   *
   * 1. Usernames cannot be duplicates.
   * 2. Usernames must be defined.
   * 3. Usernames cannot contains spaces.
   * 4. Usernames cannot be too damn long.
   *
   * @param username is the username string to test.
   * @param checkForDuplicate when true will ensure the username is not already in the database.
   * @param currentUser is the user that the email will be assigned to.
   * @param cb is a callback method where the result or error are returned.
   */
  User.statics.isValidUsername = function(username, checkForDuplicate, currentUser, cb) {
    if(username === null || username === undefined || username === "") {
      var err = new Error(i18n.t('server.error.invalidUsername'));
      err.status = 400;
      cb(err);
    } else if(username.toLowerCase() === "too damn long") {
      var err = new Error(i18n.t('server.error.invalidUsernameTooDamnLong'));
      err.status = 400;
      cb(err);
    } else if(username.indexOf(' ') >= 0) {
      var err = new Error(i18n.t('server.error.invalidUsernameHasSpaces'));
      err.status = 400;
      cb(err);
    } else if(username.length >= 600) {
      var err = new Error(i18n.t('server.error.invalidUsernameTooDamnLong'));
      err.status = 400;
      cb(err);
    } else if(validateEmailRegEx.test(username)) {
      var err = new Error(i18n.t('server.error.invalidUsernameEmailAddress'));
      err.status = 400;
      cb(err);
    } else {
      if(checkForDuplicate) {
        db.model("User").findOne({username: username.toLowerCase()}).exec(function(err, user) {
          if(err) {
            cb(err);
          } else if(user && (currentUser === undefined || (currentUser && ! user._id.equals(currentUser._id)))) {
            err = new Error(i18n.t('server.error.duplicateUsername'));
            err.status = 400;
            cb(err);
          } else {
            cb();
          }
        });
      } else {
        cb();
      }
    }
  };

  /**
   * Checks if the email specified is valid.
   *
   * 1. emails cannot be duplicates.
   * 2. emails do not need to be defined.
   * 3. emails cannot contains spaces.
   * 4. emails cannot be too damn long.
   * 5. emails must be in a valid email format (aka something@something.something)
   *
   * @param email is the email string to test.
   * @param checkForDuplicate when true will ensure the email is not already in the database.
   * @param currentUser is the user that the email will be assigned to.
   * @param cb is a callback method where the result or error are returned.
   */
  User.statics.isValidEmail = function(email, checkForDuplicate, currentUser, cb) {
    if(email === null || email === undefined || email === "") {
      cb();
    } else if(email.indexOf(' ') >= 0) {
      var err = new Error(i18n.t('server.error.invalidEmailHasSpaces'));
      err.status = 400;
      cb(err);
    } else if(email.length >= 600) {
      var err = new Error(i18n.t('server.error.invalidEmailTooDamnLong'));
      err.status = 400;
      cb(err);
    } else {
      if( ! validateEmailRegEx.test(email)) {
        var err = new Error(i18n.t('server.error.invalidEmail'));
        err.status = 400;
        cb(err);
      } else {
        if(checkForDuplicate) {
          db.model("User").findOne({email: email.toLowerCase()}).exec(function(err, user) {
            if(err) {
              cb(err);
            } else if(user && (currentUser === undefined ||(currentUser && ! user._id.equals(currentUser._id)))) {
              err = new Error(i18n.t('server.error.duplicateEmail'));
              err.status = 400;
              cb(err);
            } else {
              cb();
            }
          });
        } else {
          cb();
        }
      }
    }
  };

  /**
   * Find a user by username found in a requests query string.
   * @param req is the express request object.
   * @param res is the express response object.
   * @param cb is a callback method.
   */
  User.statics.findByUsernameQuery = function(req, res, cb) {
    var username = req.body.username || req.query.username;

    if( ! _.isString(username)) {
      res.setBadRequest('server.error.invalidUsername');
    } else {
      db.model("User").findOne({username: username.toLowerCase()}).populate('roles').exec(function(err, user) {
        if(err) {
          cb(err);
        } else if(!user) {
          res.setBadRequest('server.error.invalidUsername');
        } else {
          req.queriedUser = user;
          cb();
        }
      });
    }
  };

  /**
   * A route method used to find a user by ID.
   * @param {Object} req is the express request object.
   * @param {Object} res is the express response object.
   * @param {Function} cb is a callback method.
   * @param {String} id is the application's ID parameter.
   * @returns If an error occurred it is returned as the first parameter in the callback.
   */
  User.statics.findByIdParam = function(req, res, cb, id) {
    if( ! db.Types.ObjectId.isValid(id)) {
      return res.setBadRequest('server.error.invalidObjectId');
    }

    db.model('User').findById(id).exec(function(err, user) {
      if(err) {
        return cb(err);
      }

      if( ! user) {
        return res.setNotFound();
      }

      req.queriedUser = user;
      cb();
    });
  };

  /**
   * Find a user by userId found in a requests query string.
   * If the ID is invalid an error will be returned.
   * @param req is the express request object.
   * @param res is the express response object.
   * @param next is a callback method.
   */
  User.statics.findByIdQuery = function(req, res, next) {
    if( ! req || ! req.query || ! _.isString(req.query.userId)) {
      return next();
    }

    var id = req.query.userId;

    if( ! db.Types.ObjectId.isValid(id)) {
      return res.setBadRequest('server.error.invalidObjectId');
    }

    db.model('User').findById(id).exec(function(err, user) {
      if(err) {
        next(err);
      } else if( ! user) {
        res.setBadRequest('server.error.invalidUserId');
      } else {
        req.queriedUser = user;
        next();
      }
    });
  };

  /**
   * Check if the current user has permission to read the currently
   * queried user's data.  If the user does not, a permission
   * denied message will be returned.  This assumes the currently
   * queried user is located in req.queriedUser.
   *
   * Admins can access all user data.
   * Developers can access their own data.
   * OEMs can access their own data.
   */
  User.statics.checkReadPermission = function(req, res, next) {
    if( ! _.isObject(req.user)) {
      log.t("User.checkReadPermission(): Unauthorized, a user is not logged in: req.user = %s", req.user);
      return res.setUnauthorized();
    }

    var role = req.user.role;

    // Check for a valid user role value.
    if( ! role) {
      log.t("User.checkReadPermission(): Permission Denied, user role is invalid", JSON.stringify(role, undefined, 2));
      return res.setPermissionDenied();
    }

    // Check for a queried user.
    if( ! _.isObject(req.queriedUser)) {
      // If the queried user is not defined, then we will use the currently
      // logged in user.  So no further checks are required.
      return next();
    }

    // Users with a role higher than Admin can only view their own user information.
    if(role.index > AdminRole && req.queriedUser._id.toString() !== req.user._id.toString()) {
      log.t("User.checkReadPermission(): Permission Denied, non-admins can only view their own information.  Current user %s is not %s.", req.queriedUser._id.toString(), req.user._id.toString());
      return res.setPermissionDenied();
    }

    // All private data is removed in the sanitize method.

    next();
  };

  /**
   * Check if the current user has permission to delete the currently
   * queried user.  If the user does not, a permission
   * denied message will be returned.  This assumes the currently
   * queried user is located in req.queriedUser.
   *
   * Admins can delete any user.
   * Developers can only delete their own user object.
   * OEMs can only delete their own user object.
   */
  User.statics.checkDeletePermission = function(req, res, next) {
    if( ! _.isObject(req.user)) {
      log.t("User.checkDeletePermission(): Unauthorized, a user is not logged in: req.user = %s", req.user);
      return res.setUnauthorized();
    }

    var role = req.user.role;

    // Check for a valid user role value.
    if( ! role) {
      log.t("User.checkDeletePermission(): Permission Denied, user role is invalid", JSON.stringify(role, undefined, 2));
      return res.setPermissionDenied();
    }

    // Ensure the queried user is defined.
    if( ! _.isObject(req.queriedUser)) {
      log.t("User.checkDeletePermission(): Bad Request, queried user is not defined.");
      return res.setBadRequest();
    }

    // Ensure the queried user is not already deleted.
    if(req.queriedUser.deleted) {
      log.t("User.checkDeletePermission(): Not Found, queried user is already deleted.");
      return res.setNotFound();
    }

    // Users with a role higher than Admin can only delete their own user.
    if(role.index > AdminRole && req.queriedUser._id.toString() !== req.user._id.toString()) {
      log.t("User.checkDeletePermission(): Permission Denied, non-admins can only delete their own information.  Current user %s is not the queried user %s.", req.user._id.toString(), req.queriedUser._id.toString());
      return res.setPermissionDenied();
    }

    next();
  };

  /**
   * Check if the current user has permission to purge the currently
   * queried user data.  If the user does not, a permission
   * denied message will be returned.
   *
   * Admins can purge any user.
   * Developers cannot purge users.
   * OEMs cannot purge users.
   */
  User.statics.checkPurgePermission = function(req, res, next) {
    if( ! _.isObject(req.user)) {
      log.t("User.checkPurgePermission(): Unauthorized, a user is not logged in: req.user = %s", req.user);
      return res.setUnauthorized();
    }

    var role = req.user.role;

    // Check for a valid user role value.
    if( ! role) {
      log.t("User.checkPurgePermission(): Permission Denied, user role is invalid", JSON.stringify(role, undefined, 2));
      return res.setPermissionDenied();
    }

    // Ensure the queried user is defined.
    if( ! _.isObject(req.queriedUser)) {
      log.t("User.checkPurgePermission(): Bad Request, queried user is not defined.");
      return res.setBadRequest();
    }

    // Only admin users can purge a user.
    if(role.index > AdminRole) {
      log.t("User.checkPurgePermission(): Permission Denied, only admins can purge a user.  User's current role: %s", role.index);
      return res.setPermissionDenied();
    }

    // Admins cannot purge themselves.
    if(req.queriedUser._id.toString() === req.user._id.toString()) {
      log.t("User.checkPurgePermission(): Permission Denied, an admin cannot purge themselves. Current user %s is the queried user %s.",  req.user._id.toString(), req.queriedUser._id.toString());
      return res.setPermissionDenied('server.error.permissionDeniedPurgeUser');
    }

    next();
  };

  /**
   * Check if the current user has permission to modify the currently
   * queried or create a new user with data from the request body.
   * If the user does not, a permission denied message will be returned.
   * This assumes the currently queried user is located in
   * req.queriedUser.
   *
   * Admins can create or modify any user.
   * Developers, OEMs, and Anonymous users can create new users.
   * Developers and OEMs can modify their own user object.
   */
  User.statics.checkWritePermission = function(req, res, next) {
    var isLoggedIn = _.isObject(req.user);
    var updatingExistingUser = _.isObject(req.queriedUser);

    // If we are updating a user, make sure the user is authenticated,
    // has a proper role, and the queried user is valid.
    if(isLoggedIn) {

      // Make sure the user role is valid.
      if( ! req.user.role) {
        log.t("User.checkWritePermission(): Permission Denied, user role is invalid", JSON.stringify(req.user.role, undefined, 2));
        return res.setPermissionDenied();
      }

      // If the user is an admin, they are ok to update anything.
      if(req.user.role.index == AdminRole) {
        return next();
      }

      // If not an admin and updating a user, make sure the authenticated user is updating themselves.
      if(updatingExistingUser && (req.user._id.toString() !== req.queriedUser._id.toString())) {
        log.t("User.checkWritePermission(): Permission Denied, non-admins can only update their own information.  Current user %s is not the queried user %s.", req.user._id.toString(), req.queriedUser._id.toString());
        return res.setPermissionDenied();
      }
    }

    // Check for valid attributes, non-admins can only update some attributes.
    for(var key in req.body) {
      if(req.body.hasOwnProperty(key)) {
        switch(key) {
          case 'dateCreated':
          case 'deactivatedMessage':
          case 'deleted':
          case 'failedLoginAttempts':
          case 'lastLogin':
          case 'lastUpdated':
          case 'lastUpdatedBy':
          //case 'oauth2ClientId':
          case 'passwordHash':
          case 'passwordResetHash':
          case 'requestedOemAccess':
          case 'role':
          case 'roles':
          case 'securityAnswerHash':
            return res.setPermissionDenied('server.error.forbiddenAttribute');

          case 'username':
            // Some attributes cannot be changed once the user is created.
            if(updatingExistingUser) {
              log.t("User.checkWritePermission(): Permission Denied, non-admins cannot update the %s attribute.  Current user %s", key, JSON.stringify(req.user._id, undefined, 2));
              return res.setPermissionDenied('server.error.forbiddenAttribute');
            }
            break;

          default:
            break;
        }
      }
    }

    if(updatingExistingUser) {
      if(isLoggedIn) {
        next();
      } else {
        log.t("User.checkWritePermission(): Permission Unauthorized, a user must be logged in to perform a user update.");
        res.setUnauthorized();
      }
    } else {
      // Find the default user role.
      db.model('UserRole').findOne({index: DeveloperRole}, function(err, developerRole) {
        if(err) {
          next(err);
        } else if( ! developerRole) {
          res.setError("Cannot find the developer role with index " + DeveloperRole, 500);
        } else {
          req.body.roles = [developerRole];
          next();
        }
      });
    }

  };

  /**
   * Check if the current user has permission to grant permissions to the
   * currently queried user.  If the user does not, a permission denied
   * message will be returned.
   *
   * Admins can grant permission to any user.
   * Developers cannot grant permission users.
   * OEMs cannot grant permission users.
   */
  User.statics.checkGrantPermission = function(req, res, next) {
    if( ! _.isObject(req.user)) {
      return res.setUnauthorized();
    }

    var role = req.user.role;

    // Check for a valid user role value.
    if( ! role) {
      return res.setPermissionDenied();
    }

    // Ensure the queried user is defined.
    if( ! _.isObject(req.queriedUser)) {
      return res.setBadRequest();
    }

    // Only admin users can grant access to a user.
    if(role.index > AdminRole) {
      return res.setPermissionDenied();
    }

    // Currently this is ok, but maybe in the future it might not be.
    // Admins cannot grant access to themselves.
    //if(req.queriedUser._id.toString() === req.user._id.toString()) {
    //  return res.setPermissionDenied('server.error.permissionDeniedPurgeUser');
    //}

    next();
  };

  User.statics.checkPasswordReset = function(req, res, next) {
    var user = req.queriedUser,
        passwordReset = req.body.passwordReset || req.query.passwordReset;

    // Ensure the queried user was found and defined.
    if( ! _.isObject(user)) {
      return req.setNotFound();
    }

    // If the user is deactivated, then we cannot check the password reset token until
    // they are reactivated.
    if( ! user.activated) {
      var err = new Error(user.deactivatedMessage || i18n.t('server.error.deactivated'));
      err.status = 403;
      next(err);
    } else {
      compareToHash(passwordReset, user.passwordResetHash, function(err, isPasswordHashValid) {
        if(err) {
          next(err);
        } else if(!isPasswordHashValid) {
          user.handleFailedSecurityAnswerAttempt(next);
        } else {
          next();
        }
      });
    }
  };

  /**
   * Checks if the currently logged in user has admin permissions
   * or not.  If they do not, then an error is returned.
   */
  User.statics.checkAdminPermission = function(req, res, next) {
    if( ! _.isObject(req.user)) {
      return res.setUnauthorized();
    }

    var role = req.user.role;

    // Check for a valid user role value.
    if( ! role) {
      return res.setPermissionDenied();
    }

    if(role.index > AdminRole) {
      return res.setPermissionDenied();
    }

    next();
  };


  /* ************************************************** *
   * ******************** Instance Methods
   * ************************************************** */

  /**
   * @returns {boolean} if a captcha is required on the login
   * request for a user.
   */
  User.methods.isLoginRecaptchaRequired = function() {
    return (this.failedLoginAttempts >= config.authentication.failedLoginAttempts.recaptchaRequired);
  };

  /**
   * @returns the most permissive role in a user's roles attribute.
   * The returned value will be an ObjectId or a populated role object
   * depending on whether or not the current user's roles attribute is
   * populated or not.
   */
  User.methods.getMostPermissiveRole = function() {
    if(this.roles === null || this.roles === undefined || this.roles.length <= 0) {
      return undefined;
    } else {
      return this.roles[0];
    }
  };

  /**
   * Query if a user has a specified role using the role's ID.
   * @param roleId is the role ID to query for.
   * @param cb is a callback method where the result or error is returned.
   */
  User.methods.hasRoleId = function(roleId, cb) {
    return createUserHasRoleIdMethod(this, roleId)(cb);
  };

  /**
   * Query if a user has a specified role using the role's index.
   * @param roleIndex is the role index to query for.
   * @param cb is a callback method where the result or error is returned.
   */
  User.methods.hasRoleIndex = function(roleIndex, cb) {
    return createUserHasRoleIndexMethod(this, roleIndex)(cb);
  };

  /**
   * Check if the user has the specified role index permission level.
   * @param roleIndex is a role index value to check for.
   * @returns {boolean} true if the user has the specified permission level, false otherwise.
   */
  User.methods.hasPermission = function(roleIndex) {
    var mostPermissiveRole = this.getMostPermissiveRole();
    return (mostPermissiveRole ? mostPermissiveRole.index : Number.MAX_VALUE) <= roleIndex;
  };

  /**
   * Query if the user contains a application specified by ID asynchronously.
   * @param appId is the applications ObjectId
   * @param cb is a callback method where the boolean result or error are returned.
   */
  User.methods.hasApplication = function(appId, cb) {
    if( ! isObjectIdString.test(appId) && ! db.Types.ObjectId.isValid(appId)) {
      return cb(undefined, false);
    }

    if(this.applications === null || this.applications === undefined || this.applications.length <= 0) {
      return cb(undefined, false);
    } else {
      // Check if the user has the application in their list.
      for(var i = this.applications.length-1; i >= 0; --i) {
        // If the app is populated, check the _id parameter.
        if(_.isObject(this.applications[i]) && this.applications[i]._id) {
          if(this.applications[i]._id.equals(appId)) {
            return cb(undefined, true);
          }
        } else if(this.applications[i].equals(appId)){
          return cb(undefined, true);
        }
      }
      return cb(undefined, false);
    }
  };


  /**
   * Add the OEM role to a user and remove the requestedOemAccess
   * flag, if it was set.  If the user already has the OEM role, then
   * return an error.
   * @param cb is a callback method where an error or the result are returned.
   */
  User.methods.grantOemRoleAccess = function(cb) {
    return createUserGrantOemRoleMethod(this)(cb);
  };

  /**
   * Request access to the OEM role for the user, if
   * they have not already requested it and do not have
   * the OEM role.
   * @param cb is a callback method where the result or error will be returned.
   */
  User.methods.requestOemRole = function(cb) {
    return createUserRequestOemRoleMethod(this)(cb);
  };

  /**
   * Request access to one or more resources for a user.  If any of the
   * resources requested are invalid an error will be returned.
   * @param resources is a string or array of strings that are keywords for resources.
   * @param cb is a callback method where an error or results are returned.
   */
  User.methods.requestResourceAccess = function(resources, cb) {
    var err,
        tasks = [],
        user = this;

    // Check for a valid resource or list of resources,
    // and format the resources parameter as an array.
    if(resources === undefined || resources === null) {
      err = new Error(i18n.t('server.error.badRequest'));
      err.status = 400;
      return cb(err);
    } else if(_.isString(resources)) {
      resources = [ resources ];
    } else if( ! _.isArray(resources) || resources.length == 0){
      err = new Error(i18n.t('server.error.badRequest'));
      err.status = 400;
      return cb(err);
    }

    // Create a method to request permission to each valid resource request.
    for(var i = 0; i < resources.length; i++) {
      if( ! _.isString(resources[i])) {
        err = new Error(i18n.t('server.error.badRequest'));
        err.status = 400;
        return cb(err);
      }

      switch(resources[i].split("/").pop().toLowerCase()) {
        case 'server':
        case 'oemrole':
          tasks.push(createUserRequestOemRoleMethod(user));
          break;

        default:
          err = new Error(i18n.t('server.error.unknownResource'));
          err.status = 400;
          return cb(err);
      }
    }

    // Execute the resource request methods.
    async.series(tasks, cb);
  };

  /**
   * Grant access to one or more resources for a user.  If any of the
   * resources specified are invalid an error will be returned.
   * @param resources is a string or array of strings that are keywords for resources.
   * @param cb is a callback method where an error or results are returned.
   */
  User.methods.grantResourceAccess = function(resources, cb) {
    var err,
      tasks = [],
      user = this;

    // Check for a valid resource or list of resources,
    // and format the resources parameter as an array.
    if(resources === undefined || resources === null) {
      err = new Error(i18n.t('server.error.badRequest'));
      err.status = 400;
      return cb(err);
    } else if(_.isString(resources)) {
      resources = [ resources ];
    } else if( ! _.isArray(resources) || resources.length == 0){
      err = new Error(i18n.t('server.error.badRequest'));
      err.status = 400;
      return cb(err);
    }

    // Create a method to grant permission to each valid resource.
    for(var i = 0; i < resources.length; i++) {
      if( ! _.isString(resources[i])) {
        err = new Error(i18n.t('server.error.badRequest'));
        err.status = 400;
        return cb(err);
      }

      switch(resources[i].split("/").pop().toLowerCase()) {
        case 'server':
        case 'oemrole':
          tasks.push(createUserGrantOemRoleMethod(user));
          break;

        default:
          err = new Error(i18n.t('server.error.unknownResource'));
          err.status = 400;
          return cb(err);
      }
    }

    // Execute the resource grant methods.
    async.series(tasks, cb);
  };

  /**
   * Deactivate the user and provide a deactivated message.  This will also
   * attempt to notify the user of the deactivation.
   * @param locale is the message or message identifier for the i18n translation file.
   * @param cb is a callback method where an error or updated user are returned.
   */
  User.methods.deactivate = function(locale, cb) {
    var user = this;

    if( ! user.activated) {
      cb(new Error("User is already deactivated."));
    } else {
      user.activated = false;
      user.deactivatedMessage = i18n.t(i18n.t(locale || 'server.error.deactivated') || locale);
      user.save(cb);
    }
  };

  /**
   * Activate the user and notify them of the activation.
   * @param cb is a callback method where an error or updated user are returned.
   */
  User.methods.activate = function(cb) {
    var user = this;

    if(user.activated) {
      cb(new Error("User is already activated."));
    } else {
      user.activated = true;
      //user.deactivatedMessage = "";
      user.save(cb);
    }
  };

  /**
   * Handle a failed login attempt for a user by incrementing the
   * failed login counter and taking action if there are too many
   * failed attempts.  An error will be returned to the callback
   * that is to be sent back to the user.
   * @param cb a callback method where the error and user will be returned.
   */
  User.methods.handleFailedLoginAttempt = function(cb) {
    var user = this;
    user.failedLoginAttempts++;

    if(user.failedLoginAttempts >= config.authentication.failedLoginAttempts.deactivate) {
      user.deactivate('server.error.deactivated', function(err, user) {
        if(err) {
          cb(err);
        } else {
          err = new Error(user.deactivatedMessage);
          err.status = 403;
          cb(err, user);
        }
      });
    } else {
      user.save(function(err, user) {
        if(err) {
          cb(err);
        } else {
          err = new Error(i18n.t('server.error.invalidPassword'));
          err.status = 400;
          cb(err, user);
        }
      });
    }
  };

  /**
   * Handle a failed security answer attempt for a user by incrementing the
   * failed login counter and taking action if there are too many
   * failed attempts.  An error will be returned to the callback
   * that is to be sent back to the user.
   * @param cb a callback method where the error and user will be returned.
   */
  User.methods.handleFailedSecurityAnswerAttempt = function(cb) {
    var user = this;
    user.failedLoginAttempts++;

    if(user.failedLoginAttempts >= config.authentication.failedLoginAttempts.deactivate) {
      user.deactivate('server.error.deactivated', function(err, user) {
        if(err) {
          cb(err);
        } else {
          err = new Error(user.deactivatedMessage);
          err.status = 403;
          cb(err, user);
        }
      });
    } else {
      user.save(function(err, user) {
        if(err) {
          cb(err);
        } else {
          err = new Error(i18n.t('server.error.invalidSecurityAnswer'));
          err.status = 400;
          cb(err, user);
        }
      });
    }
  };

  /**
   * Handle a successful login for a user by setting the
   * last login date/time and resetting the failed login counter.
   * @param cb is a callback method where an error or the user is returned.
   */
  User.methods.handleSuccessfulLogin = function(cb) {
    var user = this;

    if(user.failedLoginAttempts > 0) {
      user.failedLoginAttempts = 0;
    }

    user.lastLogin = Date.now();

    user.save(function(err, user) {
      if(err) {
        cb(err);
      } else {
        cb(undefined, user);
      }
    });
  };

  /**
   * Authenticates a user based on the password and if the user
   * is activated.  It also keeps track of failed login attempts
   * and takes action when too many have occurred.
   * @param password is the plain text password to be compared.
   * @param cb is a callback method where an error or user is returned.
   */
  User.methods.authenticate = function(password, cb) {
    var user = this;

    if( user.deleted) {
      var err = new Error(i18n.t('server.error.invalidUsername'));
      err.status = 400;
      cb(err);
    } else if( ! user.activated) {
      var err = new Error(user.deactivatedMessage || i18n.t('server.error.deactivated'));
      err.status = 403;
      cb(err);
    } else {
      compareToHash(password, user.passwordHash, function(err, isAuthenticated) {
        if(err) {
          cb(err);
        } else if( ! isAuthenticated) {
          user.handleFailedLoginAttempt(cb);
        } else {
          user.handleSuccessfulLogin(cb);
        }
      });
    }
  };

  /**
   * Sanitize a user return object by removing any
   * fields that should remain private.  This will also remove
   * all methods from the application object.
   * @param currentUser is the requesting user.
   * @param cb is a callback method where the sanitized user or
   * error are returned.
   * @returns a sanitized object with the application's data.
   */
  User.methods.sanitize = function(currentUser, cb) {
    var user = (this).toObject();

    // Non-admins cannot view private information.
    if( ! currentUser || ! currentUser.role || currentUser.role.index > AdminRole) {
      delete user.__v;
      delete user.deleted;
      delete user.passwordHash;
      delete user.passwordResetHash;
      delete user.securityAnswerHash;
    }

    // Make sure we return an unpopulated roles attribute.
    for(var i = 0; i < user.roles.length; i++) {
      if(user.roles[i]._id) {
        user.roles[i] = user.roles[i]._id;
      }
    }

    return cb(undefined, user);
  };

  /**
   * Validate the user's security answer and reset the the password.
   * @param securityAnswer is the answer to the security question to be validated.
   * @param newPassword is the new user password to be set.
   * @param cb is a callback method where an error or updated user are returned.
   */
  User.methods.resetPassword = function(passwordReset, securityAnswer, newPassword, cb) {
    var user = this;

    if( ! securityAnswer || ! _.isString(securityAnswer) || ! passwordReset || ! _.isString(passwordReset)) {
      user.handleFailedSecurityAnswerAttempt(cb);
    } else {
      compareToHash(passwordReset, user.passwordResetHash, function(err, isPasswordHashValid) {
        if(err) {
          cb(err);
        } else if( ! isPasswordHashValid) {
          user.handleFailedSecurityAnswerAttempt(cb);
        } else {

          if(securityAnswer && _.isString(securityAnswer)) {
            securityAnswer = securityAnswer.toLowerCase().trim();
          }

          compareToHash(securityAnswer, user.securityAnswerHash, function(err, isAuthenticated) {
            if(err) {
              cb(err);
            } else if( ! isAuthenticated) {
              user.handleFailedSecurityAnswerAttempt(cb);
            } else {
              user.failedLoginAttempts = 0;
              user.setPassword(newPassword, cb);
            }
          });
        }
      });
    }
  };

  /**
   * Handle a user's request to reset their password.  This will
   * create a password reset token used to track security question
   * answer attempts. This token will be included in a url returned
   * to the call in an email (if the user has an email) or in the
   * response object.
   * @param cb is the callback method where an error or user and url
   * are returned.
   */
  User.methods.handlePasswordResetRequest = function(cb) {
    var user = this,
        passwordResetUrl,
        passwordResetToken;

    passwordResetToken = createRandomTextSync(config.crypto.plainTextSize).toString('hex');

    passwordResetUrl = config.server.url + "/passwordReset/" + user._id +"?passwordReset=" + passwordResetToken;
    setUserPasswordReset(user, passwordResetToken, function(err, user) {
      if(user.email !== undefined && user.email !== null) {
        cb(undefined, user);
      } else {
        cb(undefined, user, passwordResetUrl);
      }
    });
  };

  /* ************************************************** *
   * ******************** Event Methods
   * ************************************************** *
   * Methods that are executed when an event, such as
   * pre-save or pre-validate.                          */

  /**
   * Called before a user model object is saved.
   * This will sort the roles array by highest priority first.
   */
  User.pre('save', function(cb) {
    var user = this;

    // Sort the role list from most permissive to least.
    db.model('UserRole').populate(user, { path: "roles" }, function(err, user) {
      if(err) {
        cb(err);
      } else {
        user.roles.sort(compareRoles);
        cb();
      }
    });
  });

  User.methods.preUpdate = function(originalUser, newUser, requestingUser, cb) {
    if(newUser && newUser.roles && newUser.roles.length <= 0) {
      log.t("User.preUpdate(): User %s about to be updated with empty roles. ", newUser);
    }

    if(originalUser && originalUser.roles && originalUser.roles.length <= 0 && newUser && newUser.roles && newUser.roles.length <= 0) {
      log.t("User.preUpdate(): User exists without roles: %s", JSON.stringify(originalUser, undefined, 2));
      log.t("User.preUpdate(): Update to apply to user: %s", JSON.stringify(newUser, undefined, 2));
    }

    cb(undefined, newUser);
  };

  /**
   * Called by crucial before a user is updated.
   * @param originalUser is the original user object without any updated fields.
   * @param newUser is user object that is about to be saved.
   * @param cb is a callback method where an error and/or new user should be returned.
   */
  User.methods.preSaveUpdate = function(originalUser, newUser, cb) {
    if( (! originalUser || originalUser.roles.length <= 0) && (! newUser || ! newUser.roles || newUser.roles.length <= 0) ) {
      log.t("About to update user with invalid roles");
      log.t(originalUser);
      log.t(newUser);
    }
    cb(undefined, newUser);
  };

  /**
   * Called by crucial after a user is updated.
   * @param originalUser is the original user object without any updated fields.
   * @param updatedUser is user object that was just saved.
   * @param cb is a callback method where an error and/or updated user should be returned.
   */
  User.methods.postSaveUpdate = function(originalUser, updatedUser, cb) {
    // Send username changed notification to user.
    //if(originalUser.username != undefined && originalUser.username != null && originalUser.username != "" && originalUser.username != updatedUser.username) {
    //  notification.sendUsernameChanged(updatedUser, originalUser.username);
    //}

    if( ! updatedUser || updatedUser.roles.length <= 0) {
      log.t("Updated user with invalid roles");
      log.t(originalUser);
      log.t(updatedUser);
    }

    cb(undefined, updatedUser);
  };


  /* ************************************************** *
   * ******************** Private Methods
   * ************************************************** *
   * Methods that are only available to the user model  */

  /**
   * Create a method to query if a user has a role using the role index.
   * @param user is the user to query against
   * @param roleIndex is the role index to query for.
   * @returns {Function} a method that accepts a callback.
   */
  var createUserHasRoleIndexMethod = function(user, roleIndex) {
    return function(cb) {
      db.model('UserRole').findOne({index: roleIndex}).exec(function(err, role) {
        if(err) {
          cb(err);
        } else if( ! role) {
          cb(new Error("Cannot find role with index of " + roleIndex));
        } else {
          createUserHasRoleIdMethod(user, role._id)(cb);
        }
      });
    }
  };

  /**
   * Create a method to query if a user has a role using the role ID.
   * @param user is the user to query against
   * @param roleId is the role ID to query for.
   * @returns {Function} a method that accepts a callback.
   */
  var createUserHasRoleIdMethod = function(user, roleId) {
    return function(cb) {
      if( ! roleId) {
        return cb(new Error("Cannot check if user has an invalid roleId of " + roleId));
      }

      if(user.roles === null || user.roles === undefined || user.roles.length < 1) {
        cb(undefined, false);
      } else {
        for(var i = user.roles.length - 1; i >= 0; --i) {
          if((user.roles[i] && user.roles[i]._id && user.roles[i]._id.toString() === roleId.toString()) || user.roles[i].toString() === roleId.toString()) {
            return cb(undefined, true);
          }
        }
        return cb(undefined, false);
      }
    }
  };

  /**
   * Create a method to request the OEM role for a specified user.
   * If the user already has the OEM role or has already requested
   * the role, then an error will be returned.  A notification will
   * be sent to admin(s) that the user is requesting access.
   * @param user is the user to request the OEM role for.
   * @returns {Function} a function that accepts a callback method as its only parameter.
   */
  var createUserRequestOemRoleMethod = function(user) {
    return function(cb) {

      // Check if the user has already requested the OEM role.
      if(user.requestedOemAccess) {
        var err = new Error(i18n.t('server.error.accessAlreadyRequested'));
        err.status = 400;
        return cb(err);
      }

      // Check if the user already has the OEM role.
      user.hasRoleIndex(config.roles.oem, function(err, userHasOemRole) {
        if(err) {
          cb(err);
        } else if(userHasOemRole) {
          var err = new Error(i18n.t('server.error.accessAlreadyGranted'));
          err.status = 400;
          cb(err);
        } else {
          // User does not have the OEM role and has not already requested it.

          // Send out a notification to the admin(s).
          // TODO: Send email to admins.

          // Mark the user as having requested access.
          user.requestedOemAccess = true;
          user.save(function(err, user) {
            if(err) {
              cb(err);
            } else {
              cb(undefined, true);
            }
          });
        }
      });
    }
  };

  /**
   * Add the OEM role to a user and remove the requestedOemAccess
   * flag, if it was set.  If the user already has the OEM role, then
   * return an error.
   * @param user is the user object to grant access to.
   * @return {function} a method that accepts a callback as a parameter were an error or the result are returned.
   */
  var createUserGrantOemRoleMethod = function(user) {
    return function(cb) {
      // Check if the user already has the OEM role.
      db.model('UserRole').findOne({index: config.roles.oem}, function(err, oemRole) {
        if(err) {
          cb(err);
        } else if(!oemRole) {
          cb(new Error("OEM role with index " + config.roles.oem + " was not found."));
        } else {
          user.hasRoleId(oemRole._id, function(err, userHasOemRole) {
            if(err) {
              cb(err);
            } else if(userHasOemRole) {
              var err = new Error(i18n.t('server.error.accessAlreadyGranted'));
              err.status = 400;
              cb(err);
            } else {
              // User does not have the OEM role, so add it.
              user.requestedOemAccess = false;
              user.roles.push(oemRole);
              user.save(function(err, user) {
                if(err) {
                  cb(err);
                } else {
                  cb(undefined, true);
                }
              });
            }
          });
        }
      });
    }
  };

  /**
   * Hash and save a user's password if it is valid.
   * @param user is the user to save the password to.
   * @param password is the plain text password.
   * @param cb is an optional callback method where an error or updated user are returned.
   */
  var setUserPassword = function(user, password, cb) {
    // If a callback method is not provided, create one to log any errors.
    cb = (cb) ? cb : function(err) { if(err) { log.e(err); }};

    // Hash the password, store it, and save the user.
    hasher(password, function(err, passwordHash) {
      user.passwordHash = passwordHash;
      user.save(cb);
    });
  };

  /**
   * Hash and save a user's password reset token if it is valid.
   * @param user is the user to save the password to.
   * @param token is the plain text password reset token.
   * @param cb is an optional callback method where an error or updated user are returned.
   */
  var setUserPasswordReset = function(user, token, cb) {
    // If a callback method is not provided, create one to log any errors.
    cb = (cb) ? cb : function(err) { if(err) { log.e(err); }};

    // Hash the password, store it, and save the user.
    hasher(token, function(err, passwordResetHash) {
      user.passwordResetHash = passwordResetHash;
      user.save(cb);
    });
  };

  /**
   * Hash and save a user's security answer if it is valid.  The
   * security answer will be put to lower case and trimmed before it
   * is hashed.  Be sure to also perform these steps when comparing values.
   * @param user is the user to save the password to.
   * @param securityAnswer is the plain text security answer.
   * @param cb is an optional callback method where an error or updated user are returned.
   */
  var setUserSecurityAnswer = function(user, securityAnswer, cb) {
    // If a callback method is not provided, create one to log any errors.
    cb = (cb) ? cb : function(err) { if(err) { log.e(err); }};

    if(securityAnswer && _.isString(securityAnswer)) {
      securityAnswer = securityAnswer.toLowerCase().trim();
    }

    // Hash the password, store it, and save the user.
    hasher(securityAnswer, function(err, securityAnswerHash) {
      user.securityAnswerHash = securityAnswerHash;
      user.save(cb);
    });
  };

  /**
   * Create a string from a hash packet object that contains
   * all of the data concatenated in a readable format.
   * @param hashPacketObject is the hash packet object to be converted to a string.
   * @returns {string} is the hash packet string.
   */
  var hashPacketObjectToString = function(hashPacketObject) {
    return hashPacketObject.keySize + ","
      + hashPacketObject.iterations + ","
      + hashPacketObject.saltSize + ","
      + hashPacketObject.salt
      + hashPacketObject.hash;
  };

  /**
   * Create a data object from a hash packet string.
   * @param hashPacketString is a string that contains a stored hash and data about the hash.
   * @returns {Object} an object with data about the hash.
   */
  var hashPacketStringToObject = function(hashPacketString) {
    // Create the default object using values from the config file.
    var obj = {
      hash: '',
      iterations: config.crypto.iterations || 10000,
      keySize: config.crypto.keySize || 64,
      salt: '',
      saltSize: config.crypto.saltSize
    };

    // If the hashPacketString is defined, then the hash string values
    // will overwrite the defaults.
    if(hashPacketString !== undefined && hashPacketString !== null) {
      var hashPacketItems = hashPacketString.split(','),
        headerLength = 3;

      // If the hash packet string does not have at least 5
      // items separated by commas then it is invalid.
      if(hashPacketItems.length < (headerLength + 1)) {
        return obj;
      }

      // Key size is the first parameter representing how long the
      // hash value will be.  Remember that since we are storing the
      // hash values as hex, they will actually be double the size.
      obj.keySize = Number(hashPacketItems[0]);
      headerLength += hashPacketItems[0].length;

      // Iterations is the second parameter representing how many
      // rounds to use when hashing.
      obj.iterations = Number(hashPacketItems[1]);
      headerLength += hashPacketItems[1].length;

      // Salt size is the third parameter representing how long the
      // salt value will be.  Remember that since we are storing the
      // salt values as hex, they will actually be doulbe the size.
      obj.saltSize = Number(hashPacketItems[2]);
      headerLength += hashPacketItems[2].length;

      // Salt is the fourth parameter and should be double the length of the salt size.
      obj.salt = hashPacketString.substring(headerLength, headerLength + (obj.saltSize * 2));

      // Hash is the final parameter and should be double the length of the key size.
      obj.hash = hashPacketString.substring(headerLength + (obj.saltSize * 2));
    }

    return obj;
  };

  /**
   * Take a plain text string and return a string that contains
   * the plain text hash and other data used by the hashing method.
   * @param text is the plain text to be hashed.
   * @param cb is a method where the string of hash and data are returned, or an error.
   */
  var hasher = function(text, cb) {
    // Create a hash packet with the default values.
    var hashPacket = hashPacketStringToObject();

    // If the text is not defined, create a random string to hash.
    if(text === undefined || text === null || text === "") {
      text = createRandomTextSync(config.crypto.plainTextSize)
    }

    // Generate a new salt if one does not exist.
    if(hashPacket.salt === undefined || hashPacket.salt === null || hashPacket.salt === "") {
      hashPacket.salt = createRandomTextSync(hashPacket.saltSize).toString('hex');
    }

    // Hash the plain text using the hashPacket settings.
    crypto.pbkdf2(text, hashPacket.salt, hashPacket.iterations, hashPacket.keySize, function(err, hash) {
      if(err) {
        cb(err);
      } else {
        // Add the hash in hex to the hash packet.
        hashPacket.hash = hash.toString('hex');

        // Return the hash packet as a string.
        cb(undefined, hashPacketObjectToString(hashPacket));
      }
    });
  };

  /**
   * Compare plain text to a stored hash.
   * @param text is the plain text to compare.
   * @param hashPacketString is the stored hash.
   * @param cb is a callback method where the result or error is returned.
   */
  var compareToHash = function(text, hashPacketString, cb) {
    // If the text is invalid, then return false.
    if(text === undefined || text === null || text === "") {
      cb(undefined, false);
    }



    // Create a hash packet object from the string.
    var hashPacket = hashPacketStringToObject(hashPacketString);

    // Encrypt the plain text using the same parameters as the stored hash.
    crypto.pbkdf2(text, hashPacket.salt, hashPacket.iterations, hashPacket.keySize, function(err, hash) {
      if(err || ! hash) {
        cb(err, false);
      } else {
        // Return the hash comparison result.
        cb(undefined, hash.toString('hex') == hashPacket.hash);
      }
    });
  };

  /**
   * Create a random string of text of the given size.
   * @param length is the length of the text.
   * @returns a string of the given length.
   */
  var createRandomTextSync = function(length) {
    var text;
    try {
      text = crypto.randomBytes(length || 256);
    } catch(err) {
      log.e(err);
      text = uuid.v4();
    }

    return text;
  };

  /**
   * Compare method used to sort roles by index value from
   * lowest to highest value.
   * @param a is the first role
   * @param b is the second role
   * @returns {number} greater than 0 if a > b, less than 0 if a < b,
   * and 0 if a = b.
   */
  var compareRoles = function(a,b) {
    if(a && b) {
      if(a.index > b.index) {
        return 1;
      } else if(a.index < b.index) {
        return -1;
      }
    }
    return 0;
  };


  /* ************************************************** *
   * ******************** Mongoose Plugins
   * ************************************************** *
   * Enable additional functionality through 3rd party
   * plugins http://plugins.mongoosejs.com/             */

  db.plugin(crucial.mongoose);

  /* ************************************************** *
   * ******************** Exports
   * ************************************************** *
   * Export the model's methods and data so it can be
   * required by other parts of the application.        */

  db.model('User', User);

};