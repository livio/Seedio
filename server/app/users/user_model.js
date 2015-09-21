/**
 * Defines a user account in the application.
 * @param app is the express application object.
 * @param config is the server's configuration object.
 * @param log is the server's current logger instance.
 */
module.exports = function(app, config, log) {


  /* ************************************************** *
   * ******************** Local Variables
   * ************************************************** *
   * Variables used only by this exported method.       */

  // External and internal modules.
  var async = require('async'),
      crucial = require('crucial'),
      crypto = require('crypto'),
      db = require('mongoose'),
      error = require(config.libsDirectory + 'error'),
      i18n = require('i18next'),
      path = require('path'),
      security = require(config.libsDirectory + 'Security')(config, log),
      uuid = require('node-uuid'),
      validator = require('validator'),
      _ = require('lodash');

  // Reference to the mongoose ObjectId type.
  var ObjectId = db.Schema.ObjectId;


  /* ************************************************** *
   * ******************** User Schema
   * ************************************************** *
   * The Mongoose data definition.                      */

  var User = new db.Schema({
    // Flags a user as activated or deactivated.  User's
    // that are deactivated will not be authenticated.
    activated: {
      default: true,
      type: Boolean
    },

    // Date and time the user object was created.
    dateCreated: {
      default: Date.now,
      type: Date
    },

    // A message describing why a user was deactivated.
    // Can be displayed to the user or other admins.
    deactivatedMessage: {
      default: "",
      type: String
    },

    // Marks the user object as deleted without actually
    // loosing the user's information.
    deleted: {
      default: false,
      type: Boolean
    },

    // User's email address.
    email: {
      lowercase: true,
      sparse: true,
      trim: true,
      type: String
    },

    // Keeps track of the number of failed security attempts
    // (e.g. failed login, password reset, security question)
    // since the last successful login.  Used to detect
    // break-in attempts.
    failedSecurityAttempts: {
      default: 0,
      type: Number
    },

    // Date and time the user last logged in.
    lastLogin: {
      default: Date.now,
      type: Date
    },

    // Date and time the user object was last updated by a user.
    lastUpdated: {
      default: Date.now,
      type: Date
    },

    // User who last updated the object.
    lastUpdatedBy: {
      ref: 'User',
      type: ObjectId
    },

    // Stores the user's calculated password hash, salt, and
    // other cryptography related information.
    passwordHash: {
      default: "",
      type: String
    },

    // A password reset token is generated to authenticate a
    // user while resetting a forgotten password.  The
    // calculated password reset hash, salt, and other
    // cryptography related information is stored here.
    passwordResetHash: {
      default: "",
      type: String
    },

    // A security challenge given to a user as an alternate
    // or additional means of authentication.
    securityQuestion: {
      default: defaultSecurityQuestion,
      trim: true,
      type: String
    },

    // The expected response to the security question is
    // stored here along with the salt and other cryptography
    // related information.
    securityAnswerHash: {
      default: "",
      type: String
    }

  });


  /* ************************************************** *
   * ******************** Virtual Getters
   * ************************************************** *
   * Variables that you can get, but are not persisted
   * to MongoDB.                                        */

  /**
   * Get the user's password hash.
   * @return {string} a string containing the password
   * hash, salt, and other cryptography information.
   */
  User.virtual('password').get(function() {
    return this.passwordHash;
  });

  /**
   * Get the user's password reset hash.
   * @return {string} a string containing the password
   * reset hash, salt, and other cryptography information.
   */
  User.virtual('passwordReset').get(function() {
    return this.passwordResetHash;
  });

  /**
   * Get the user's security answer hash.
   * @return {string} a string containing the security
   * answer hash, salt, and other cryptography information.
   */
  User.virtual('securityAnswer').get(function() {
    return this.securityAnswerHash;
  });


  /* ************************************************** *
   * ******************** Virtual Setters
   * ************************************************** *
   * Variables that you can set, but are not persisted
   * to MongoDB.                                        */

  /**
   * Hash and save a new password for the user.
   *
   * Note:  This method is called by the crucial library.
   * @param {string} password is the plain text password.
   * @param {userCallback} cb is a callback method.
   */
  User.methods.setPassword = function(password, cb) {
    setUserPassword(this, password, cb);
  };

  /**
   * Hash and save a new password reset token for the user.
   *
   * Note:  This method is called by crucial library.
   * @param {string} token is the plain text password reset token.
   * @param {userCallback} cb is a callback method.
   */
  User.methods.setPasswordReset = function(token, cb) {
    setUserPasswordReset(this, token, cb);
  };

  /**
   * Hash and save a new security answer for the user.
   *
   * Note:  This method is called by crucial library.
   * @param {string} securityAnswer is the plain text security answer.
   * @param {userCallback} cb is a callback method.
   */
  User.methods.setSecurityAnswer = function(securityAnswer, cb) {
    setUserSecurityAnswer(this, securityAnswer, cb);
  };


  /* ************************************************** *
   * ******************** Default Setters
   * ************************************************** *
   * Methods used by the Mongoose schema when
   * initializing new schema objects.                   */

  /**
   * Creates a default security question for a new user
   * object based on the language requested.
   * @returns {string} a security question string.
   */
  function defaultSecurityQuestion() {
    return i18n.t('server.user.default.securityQuestion');
  }


  /* ************************************************** *
   * ******************** Static Methods
   * ************************************************** *
   * Schema methods that can be called without an first
   * creating an instance.                              */

  /**
   * A route method used to find a user by email address
   * or ID.
   * @param {object} req is the express request object.
   * @param {object} res is the express response object.
   * @param {next} cb is an express callback method.
   * @param {string} emailOrId is a user's email address
   * or ID to search by.
   */
  User.statics.routeFindByIdOrEmail = function(req, res, cb, emailOrId) {
    if(db.Types.ObjectId.isValid(id)) {
      db.model('User').routeFindById(req, res, cb, emailOrId);
    } else if(validator.isEmail(email)) {
      db.model('User').routeFindByEmail(req, res, cb, emailOrId);
    } else {
      res.setBadRequest('server.user.invalidEmailOrId', 400);
    }
  };

  /**
   * A route method used to find a user by ID.
   * @param {object} req is the express request object.
   * @param {object} res is the express response object.
   * @param {next} cb is an express callback method.
   * @param {string} id is the user's ID parameter.
   */
  User.statics.routeFindById = function(req, res, cb, id) {
    if( ! db.Types.ObjectId.isValid(id)) {
      res.setBadRequest('server.error.invalidObjectId');
    } else {
      db.model('User').findById(id).exec(function(err, user) {
        if(err) {
          cb(err);
        } else if( ! user) {
          res.setNotFound();
        } else {
          req.query = user;
          cb();
        }
      });
    }
  };

  /**
   * A route method used to find a user by email address.
   * @param {object} req is the express request object.
   * @param {object} res is the express response object.
   * @param {next} cb is an express callback method.
   * @param {string} email is the user's email parameter.
   */
  User.statics.routeFindByEmail = function(req, res, cb, email) {
    if(validator.isEmail(email)) {
      res.setBadRequest('server.user.invalidEmail', 400);
    } else {
      db.model('User').find({'email': email}).exec(function(err, user) {
        if(err) {
          cb(err);
        } else if( ! user) {
          res.setNotFound();
        } else {
          req.query = user;
          cb();
        }
      });
    }
  };

  /**
   * Query for a user by email.
   * @param {string} email is a potential user's email address.
   * @param {userCallback} cb is a callback method.
   */
  User.statics.findByEmail = function(email, cb) {
    if(validator.isEmail(email)) {
      db.model("User").findOne({ email: email.toLowerCase() }).exec(function(err, user) {
        if(err) {
          cb(err);
        } else if(! user) {
          cb(error.build('server.user.invalidEmail', 400));
        } else {
          cb(undefined, user);
        }
      });
    } else {
      cb(error.build('server.user.invalidEmail', 400));
    }
  };


  /* ************************************************** *
   * ******************** Instance Methods
   * ************************************************** *
   * Schema methods that are attached to each instance. */

  /**
   * Activate the user and clear the deactivated message.
   *
   * Note:  A notification is sent to the user when the
   * account becomes activated.
   *
   * @param {userCallback} cb is a callback method.
   */
  User.methods.activate = function(cb) {
    var user = this;

    if(user.activated) {
      cb(error.build('server.user.alreadyActivated', 400));
    } else {
      user.activated = true;
      user.deactivatedMessage = "";
      user.save(cb);
    }
  };

  /**
   * Checks if a user is authenticated and track the successful or
   * unsuccessful login.  If the user is not authenticated then an
   * error will be returned in the callback method.  If there have
   * been too many failed login attempts, appropriate action will
   * be taken.
   *
   * @param {string} password is the plain text password to be compared.
   * @param {userCallback} cb is a callback method.
   */
  User.methods.authenticate = function(password, cb) {
    var user = this;

    // Deleted users should be treated as if they do not exist.
    if(user.deleted) {
      cb(error.build('server.user.invalidUsername', 400));

    // Deactivated users cannot login.
    } else if( ! user.activated) {
      cb(error.build(user.deactivatedMessage || 'server.user.deactivated', 403));

    // Check if the user entered the correct password.
    } else {
      security.compareToHash(password, user.passwordHash, function(err, isAuthenticated) {
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
   * Deactivate the user and set the deactivated message.
   *
   * Note:  A notification is sent to the user's email address
   * when the account becomes deactivated.
   *
   * @param {string} locale is either a message or an i18n message identifier.
   * @param {userCallback} cb is a callback method.
   */
  User.methods.deactivate = function(locale, cb) {
    var user = this;

    if( ! user.activated) {
      cb(error.build('server.user.alreadyDeactivated', 400));
    } else {
      user.activated = false;
      user.deactivatedMessage = i18n.t(i18n.t(locale || 'server.user.default.deactivatedMessage') || locale);

      // TODO:  Log user out if they are logged in.
      user.save(cb);
    }
  };

  /**
   * Handle a failed login attempt for a user by incrementing the
   * failed security attempt counter and taking action if there are
   * too many failed attempts.
   *
   * Note:  If a user becomes deactivated a notification will be sent
   * to the user.
   *
   * @param {userCallback} cb is a callback method.
   */
  User.methods.handleFailedLoginAttempt = function(cb) {
    this.handleFailedSecurityAttempt('server.user.tooManyFailedLoginAttempts', 'server.user.invalidPassword', cb);
  };

  /**
   * Handle a failed password attempt for a user by incrementing the
   * failed security attempt counter and taking action if there are
   * too many failed attempts.
   *
   * Note:  If a user becomes deactivated a notification will be sent
   * to the user.
   *
   * @param {userCallback} cb is a callback method.
   */
  User.methods.handleFailedPasswordAttempt = function(cb) {
    this.handleFailedSecurityAttempt('server.user.tooManyFailedPasswordAttempts', 'server.user.invalidPassword', cb);
  };

  /**
   * Handle a failed password reset attempt for a user by incrementing
   * the failed security attempt counter and taking action if there are
   * too many failed attempts.
   *
   * Note:  If a user becomes deactivated a notification will be sent
   * to the user.
   *
   * @param {userCallback} cb is a callback method.
   */
  User.methods.handleFailedPasswordResetAttempt = function(cb) {
    this.handleFailedSecurityAttempt('server.user.tooManyFailedPasswordResetAttempts', 'server.user.invalidPassword', cb);
  };

  /**
   * Handle a failed security answer attempt for a user by incrementing
   * the failed security attempt counter and taking action if there are
   * too many failed attempts.
   *
   * Note:  If a user becomes deactivated a notification will be sent
   * to the user.
   *
   * @param {userCallback} cb is a callback method.
   */
  User.methods.handleFailedSecurityAnswerAttempt = function(cb) {
    this.handleFailedSecurityAttempt('server.user.tooManyFailedSecurityAnswers', 'server.user.invalidSecurityAnswer', cb);
  };

  /**
   * Handle a failed security attempt for a user by incrementing the
   * failed security attempt counter and taking action if there are
   * too many failed attempts.
   *
   * Note:  If a user becomes deactivated a notification will be sent
   * to the user.
   *
   * @param {string} errorLocale is an i18n locale string or an error
   * message that will be included in the returned error.
   * @param {string} deactivatedErrorLocale is an i18n locale string or
   * an error message that will be used as the deactivated message, if a
   * user is deactivated for too many security attempts.
   * @param {userCallback} cb is a callback method.
   */
  User.methods.handleFailedSecurityAttempt = function(errorLocale, deactivatedErrorLocale, cb) {
    var user = this;

    // Increment the failed security attempt counter.
    user.failedSecurityAttempts++;

    // If the account should be disabled from too many failed attempts, deactivate the user.
    if(user.failedSecurityAttempts >= config.models.user.failedSecurityAttempts.deactivate) {
      user.deactivate(errorLocale || 'server.user.tooManyFailedSecurityAttempts', function(err, user) {
        cb(err || error.build(user.deactivatedMessage, 403), user);
      });

      // Otherwise, save the user and return the error.
    } else {
      user.save(function(err, user) {
        cb(err || error.build(deactivatedErrorLocale || 'server.user.invalidInput', 400), user);
      });
    }
  };

  /**
   * Handle a successful login for a user by setting the last login
   * date/time and resetting the failed security attempt counter.
   * @param {userCallback} cb is a callback method.
   */
  User.methods.handleSuccessfulLogin = function(cb) {
    var user = this;

    user.failedSecurityAttempts = 0;
    user.lastLogin = Date.now();

    user.save(cb);
  };

  /**
   * Check if the ReCAPTCHA should be required for the user to login.
   * @returns {boolean} true if the ReCAPTCHA is required.
   */
  User.methods.isLoginRecaptchaRequired = function() {
    return (this.failedSecurityAttempts >= config.models.user.failedSecurityAttempts.recaptchaRequired);
  };

  /**
   * Sanitize a user schema object by removing all methods
   * and attributes that should remain private.
   *
   * Note: The returned user object will no longer be a
   * mongoose schema object.
   *
   * @param {object} currentUser is the requesting user.
   * @param {userCallback} cb is a callback method.
   */
  User.methods.sanitize = function(currentUser, cb) {
    var user = (this).toObject();

    delete user.__v;
    delete user.deleted;
    delete user.passwordHash;
    delete user.passwordResetHash;
    delete user.securityAnswerHash;

    return cb(undefined, user);
  };

  /**
   * Set the user's password to the specified value if the security
   * answer and password reset token are both valid.
   * @param passwordResetToken is the password reset token to be validated.
   * @param securityAnswer is the answer to the security question to be validated.
   * @param newPassword is the new user password to be set.
   * @param {userCallback} cb is a callback method.
   */
  User.methods.resetPassword = function(passwordResetToken, securityAnswer, newPassword, cb) {
    var user = this;

    user.verifyPasswordReset(passwordResetToken, function(err, user) {
      if(err) {
        cb(err);
      } else {
        user.verifySecurityAnswer(securityAnswer, function(err, user) {
          if(err) {
            cb(err);
          } else {
            user.failedSecurityAttempts = 0;
            user.setPassword(newPassword, cb);
          }
        });
      }
    });
  };

  /**
   * Checks if a string is the user's password.
   *
   * If an invalid password is found then a failed security
   * attempt will be recorded and appropriate action will be taken.
   * If the password is valid, then the failed security attempt counter
   * will be reset.
   *
   * @param {string} password is the plain text password to be compared.
   * @param {userCallback} cb is a callback method.
   */
  User.methods.verifyPassword = function(password, cb) {
    var user = this;

    security.compareToHash(password, user.passwordHash, function(err, isValid) {
      if(err) {
        cb(err);
      } else if( ! isValid) {
        user.handleFailedPasswordAttempt(cb);
      } else {
        user.failedSecurityAttempts = 0;
        user.save(cb);
      }
    });
  };

  /**
   * Check if a string matches the user's security answer.
   *
   * Note: Security answers are not case sensitive.
   *
   * @param {string} securityAnswer is the string to verify.
   * @param {userCallback} cb is a callback method.
   */
  User.methods.verifySecurityAnswer = function(securityAnswer, cb) {
    var user = this;

    // A securityAnswer value of null, undefined, false, 0, NaN, "", or not a string is invalid.
    if( ! securityAnswer || ! _.isString(securityAnswer)) {
      user.handleFailedSecurityAnswerAttempt(cb);
    } else {

      // Security answers are not case sensitive and do not include extraneous spaces.
      securityAnswer = securityAnswer.toLowerCase().trim();

      security.compareToHash(securityAnswer, user.securityAnswerHash, function(err, isAuthenticated) {
        if(err) {
          cb(err, user);
        } else if( ! isAuthenticated) {
          user.handleFailedSecurityAnswerAttempt(cb);
        } else {
          cb(undefined, user);
        }
      });
    }
  };

  /**
   * Check if a string matches the user's password reset.
   *
   * Note: Security answers are not case sensitive.
   *
   * @param {string} passwordReset is the string to verify.
   * @param {userCallback} cb is a callback method.
   */
  User.methods.verifyPasswordReset = function(passwordReset, cb) {
    var user = this;

    // A securityAnswer value of null, undefined, false, 0, NaN, "", or not a string is invalid.
    if( ! passwordReset || ! _.isString(passwordReset)) {
      user.handleFailedPasswordResetAttempt(cb);
    } else {
      security.compareToHash(passwordReset, user.passwordResetHash, function(err, isValid) {
        if(err) {
          cb(err, user);
        } else if( ! isValid) {
          user.handleFailedPasswordResetAttempt(cb);
        } else {
          cb(undefined, user);
        }
      });
    }
  };


  /* ************************************************** *
   * ******************** Event Methods
   * ************************************************** *
   * Methods that are executed when an event, such as
   * pre-save or pre-validate.                          */

  /**
   * Called before a user is updated by the crucial module.
   * @param {object} originalUser is the current user object in the database.
   * @param {object} newUser is the user attributes that will be updated.
   * @param {object} requestingUser is the user who
   * @param {updateCallback} cb is a callback method.
   */
  User.methods.preUpdate = function(originalUser, newUser, requestingUser, cb) {
    // Handles checks that may be required when a user updates their password.
    verifyCurrentPasswordOnUpdate(originalUser, newUser, requestingUser, cb);
  };

  /**
   * Called before an updated user is saved by the crucial module.
   * @param {object} originalUser is the original user object without any updated fields.
   * @param {object} newUser is user object that is about to be saved.
   * @param {updateCallback} cb is a callback method where an error and/or new user should be returned.
   */
  User.methods.preSaveUpdate = function(originalUser, newUser, cb) {
    cb(undefined, newUser);
  };

  /**
   * Called by crucial after a user is updated.
   * @param {object} originalUser is the original user object without any updated fields.
   * @param {object} updatedUser is user object that was just saved.
   * @param {updateCallback} cb is a callback method where an error and/or updated user should be returned.
   */
  User.methods.postSaveUpdate = function(originalUser, updatedUser, cb) {
    // Send username changed notification to user.
    //if(originalUser.username != undefined && originalUser.username != null && originalUser.username != "" &&
    // originalUser.username != updatedUser.username) { notification.sendUsernameChanged(updatedUser,
    // originalUser.username); }
    cb(undefined, updatedUser);
  };


  /* ************************************************** *
   * ******************** Private Methods
   * ************************************************** *
   * Methods that are only available to the user model  */

  /**
   * Ensure that the passed parameter is a callback
   * method, otherwise creates a new callback method
   * that will log any errors it receives.
   * @param {function|undefined} cb is a possible callback method.
   * @returns {function} a callback method.
   */
  var ensureCallbackIsDefined = function(cb) {
    if(cb) {
      return cb;
    } else {
      return function(err) {
        if(err) {
          log.e(err);
        }
      };
    }
  };

  /**
   * Hash and save a user's password if it is valid.
   * @param user is the user to save the password to.
   * @param password is the plain text password.
   * @param {userCallback} cb is a callback method.
   */
  var setUserPassword = function(user, password, cb) {
    // If a callback method is not provided, create one to log any errors.
    cb = ensureCallbackIsDefined(cb);

    // Ensure the password meets any and all requirements
    verifyPasswordRequirements(user, password, function(err, password) {
      if(err) {
        cb(err);
      } else {

        // Hash the password, store it, and save the user.
        security.hasher(password, function(err, passwordHash) {
          user.passwordHash = passwordHash;
          user.save(cb);
        });
      }
    });
  };

  /**
   * Hash and save a user's password reset token if it is valid.
   * @param user is the user to save the password to.
   * @param token is the plain text password reset token.
   * @param {userCallback} cb is a callback method.
   */
  var setUserPasswordReset = function(user, token, cb) {
    // If a callback method is not provided, create one to log any errors.
    cb = ensureCallbackIsDefined(cb);

    // TODO: Verify the password reset token is URL friendly.

    // Hash the password, store it, and save the user.
    security.hasher(token, function(err, passwordResetHash) {
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
   * @param {userCallback} cb is a callback method.
   */
  var setUserSecurityAnswer = function(user, securityAnswer, cb) {
    // If a callback method is not provided, create one to log any errors.
    cb = ensureCallbackIsDefined(cb);

    verifySecurityAnswerRequirements(user, securityAnswer, function(err) {
      if(err) {
        cb(err);
      } else {
        securityAnswer = securityAnswer.toLowerCase().trim();

        // Hash the password, store it, and save the user.
        security.hasher(securityAnswer, function(err, securityAnswerHash) {
          user.securityAnswerHash = securityAnswerHash;
          user.save(cb);
        });
      }
    });
  };

  /**
   * Checks if the user is updating their password.  If
   * they are, then the current user password is verified
   * or an error is returned.
   *
   * Note:  You can toggle this functionality on/off in the
   * server configuration object.
   *
   * @param {object} originalUser is the current user in the database.
   * @param {object} newUser is the new user object attributes.
   * @param {object} requestingUser is the user who is requesting the action.
   * @param {updateCallback} cb is a callback method.
   */
  var verifyCurrentPasswordOnUpdate = function(originalUser, newUser, requestingUser, cb) {
    if(config.models.user.password.changeRequiresCurrentPassword) {
      if(newUser.password === undefined || newUser.password === null) {
        cb(undefined, originalUser, newUser, requestingUser);
      } else {
        if( ! newUser.currentPassword === undefined || newUser.currentPassword === null || newUser.currentPassword === "") {
          cb(error.build('server.user.currentPasswordRequired', 400));
        } else {
          originalUser.verifyPassword(newUser.currentPassword, function(err, originalUser) {
            if(err) {
              cb(err);
            } else {
              delete newUser.currentPassword;
              cb(undefined, originalUser, newUser, requestingUser);
            }
          });
        }
      }
    }
  };

  /**
   * Checks if a given password meets all the password
   * requirements set by the configuration file and/or
   * application.
   * @param user is the user who owns the password.
   * @param password is the password value to check.
   * @param {passOrFail} cb is a callback method.
   */
  var verifyPasswordRequirements = function(user, password, cb) {
    // A password value of null, undefined, false, 0, NaN, "", or not a string is invalid.
    if( ! password || ! _.isString(password)) {
      cb(error.build('server.user.passwordMustBeString', 400));

      // A password cannot be shorter than the minimum length.
    } else if(password.length < config.models.user.password.minLength) {
      cb(error.build('server.user.passwordTooShort', 400));

      // A password cannot be longer than the maximum length.
    } else if(password.length > config.models.user.password.maxLength) {
      cb(error.build('server.user.passwordTooLong', 400));

      // Password meets all requirements.
    } else {
      cb(undefined);
    }
  };

  /**
   * Checks if a given security answer meets all the
   * requirements set by the configuration file and/or
   * application.
   * @param user is the user who owns the password.
   * @param securityAnswer is the security answer value to check.
   * @param {passOrFail} cb is a callback method.
   */
  var verifySecurityAnswerRequirements = function(user, securityAnswer, cb) {
    // A security answer value of null, undefined, false, 0, NaN, "", or not a string is invalid.
    if( ! securityAnswer || ! _.isString(securityAnswer)) {
      cb(error.build('server.user.securityAnswerMustBeString', 400));

    // A security answer cannot be shorter than the minimum length.
    } else if(securityAnswer.length < config.models.user.securityAnswer.minLength) {
      cb(error.build('server.user.securityAnswerTooShort', 400));

    // A security answer cannot be longer than the maximum length.
    } else if(securityAnswer.length > config.models.user.securityAnswer.maxLength) {
      cb(error.build('server.user.securityAnswerTooLong', 400));

    // Security answer meets all requirements.
    } else {
      cb(undefined);
    }
  };


  /* ************************************************** *
   * ******************** Mongoose Plugins
   * ************************************************** *
   * Enable additional functionality through 3rd party
   * plugins http://plugins.mongoosejs.com/             */

  //db.plugin(crucial.mongoose);

  /* ************************************************** *
   * ******************** Exports
   * ************************************************** *
   * Export the model's methods and data so it can be
   * required by other parts of the application.        */

  var UserSchema = db.model('User', User);


  /* ************************************************** *
   * ******************** Validation Methods
   * ************************************************** */

  /**
   * Validates an email address before it is stored to
   * a user's email attribute.  Returns an error
   * message if the email address is invalid.
   */
  /*UserSchema.schema.path('email').validate(function(v) {
    return validator.isEmail(v);
  }, i18n.t('server.user.invalidEmailAddress'));
*/

};


/* ************************************************** *
 * ******************** Documentation Stubs
 * ************************************************** */

/**
 * The results of finding, modifying, or deleting a user
 * object are returned to this callback method.
 *
 * @callback userCallback
 * @param {object|undefined} error describes the error that occurred.
 * @param {object|undefined} user is the modified user object.
 */

/**
 * The next callback method in a series of express routes.
 *
 * @callback next
 * @param {object|undefined} error describes the error that occurred.
 */

/**
 * The results of finding, modifying, or deleting a user
 * object are returned to this callback method.
 *
 * @callback updateCallback
 * @param {object|undefined} error describes the error that occurred.
 * @param {object} originalUser is the current user in the database.
 * @param {object} newUser is the new user object attributes.
 * @param {object} requestingUser is the user who is requesting the action.
 */

/**
 * The results of finding, modifying, or deleting a user
 * object are returned to this callback method.
 *
 * @callback passwordResetRequestCallback
 * @param {object|undefined} error describes the error that occurred.
 * @param {object|undefined} user is the modified user object.
 * @param {string} passwordResetToken is the generated password reset token.
 * @param {string} url is the URL visited next by the user to continue the password reset request.
 */

/**
 * The passOrFail callback method will return an error if one occurred
 * otherwise it will not return anything.
 *
 * @callback passOrFail
 * @param {object|undefined} error describes the error that occurred.
 */