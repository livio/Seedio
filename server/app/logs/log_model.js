module.exports = function(app, config, log) {
      var AdminRole = config.roles.admin,
          _ = require('lodash'),
          db = require('mongoose');

  /* ************************************************** *
   * ******************** Schema
   * ************************************************** */

  var Log = new db.Schema({}, {
    strict: false
  });

  /* ************************************************** *
   * ******************** Static Methods
   * ************************************************** */

  /**
   * Records a new log in the database.
   * @param {object} obj - Javascript object that will be logged.
   * @param callback - Async Callback
   */
  Log.statics.record = function(obj, callback) {
    var Log = this;

    if(!obj) {
      callback(new Error('obj is required'))
    }

    new Log(obj).save(function(err, log) {
        if(err) {
          if(callback) {
            return callback(err);
          }
        } else {
          if(callback) {
            return callback(undefined, log)
          }
        }
      })
  };

  /**
   * Check if the current user has permission to read the logs.
   * If the user does not, a permission denied message will be returned.
   * his assumes the currently queried user is located in req.queriedUser.
   * Admins can access logs.
   */
  Log.statics.checkReadPermission = function(req, res, next) {
    if( ! _.isObject(req.user)) {
      log.t("Log.checkReadPermission(): Unauthorized, a user is not logged in: req.user = %s", req.user);
      return res.setUnauthorized();
    }

    var role = req.user.role;

    // Check for a valid user role value.
    if( ! role) {
      log.t("Log.checkReadPermission(): Permission Denied, user role is invalid", JSON.stringify(role, undefined, 2));
      return res.setPermissionDenied();
    }

    // Users with a role higher than Admin can only view their own user information.
    if(role.index !== AdminRole) {
      log.t("Log.checkReadPermission(): Permission Denied, non-admins can not view log information.");
      return res.setPermissionDenied();
    }

    // All private data is removed in the sanitize method.

    next();
  };

  /* ************************************************** *
   * ******************** Private Methods
   * ************************************************** */


  /* ************************************************** *
   * ******************** Mongoose Plugins
   * ************************************************** *
   * Enable additional functionality through 3rd party
   * plugins http://plugins.mongoosejs.com/             */

  /* ************************************************** *
   * ******************** Exports
   * ************************************************** *
   * Export the model's methods and data so it can be
   * required by other parts of the application.        */

  db.model('Log', Log);
};
