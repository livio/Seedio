module.exports = function(app, config, log, fixtures) {

  var assert = require('assert'),
    async = require('async'),
    cramit = require('cramit')(),
    i18n = require('i18next'),
    should = require('should'),
    _ = require('lodash');


  /* ************************************************** *
   * ******************** Configurations
   * ************************************************** */

  var requiredUserAttributes = [
    'activated'
    , 'dateCreated'
    , 'deactivatedMessage'
    //, 'deleted'
    , 'email'
    , 'failedSecurityAttempts'
    , 'lastLogin'
    , 'lastUpdated'
    , 'lastUpdatedBy'
    //, 'passwordHash'
    //, 'passwordResetHash'
    , 'securityQuestion'
    //, 'securityAnswerHash'
  ];


  /* ************************************************** *
   * ******************** Private Methods
   * ************************************************** */


  /**
   * Validate a user object that was returned from the
   * API for a specific requesting user.
   * @param {object} user is the user object to validate.
   * @param {object} requestingUser is the requesting user object.
   * @param {method} cb is a callback method.
   */
  var validateUser = function(user, requestingUser, cb) {
    // User needs to be an object.
    assert.equal( ! user && _.isObject(user), false);

    // User should contain the following required attributes.
    for(var i = requiredUserAttributes.length-1; i >=0; --i) {
      assert.notEqual(user[requiredUserAttributes[i]], undefined);
    }

    cb();
  };

  var validateUsers = function(users, requestingUser, cb) {
    var tasks = [];

    for(var i = 0; i < users.length; i++) {
      tasks.push(createValidateUserMethod(users[i], requestingUser));
    }

    async.parallel(tasks, function(err, results) {
      cb(err);
    });
  };

  var createValidateUserMethod = function(user, requestingUser) {
    return function(cb) {
      validateUser(user, requestingUser, cb);
    }
  };

  var populateUser = function(user) {
    // User needs to be either a string or an object.
    if( ! user) {
      cb(new Error("Cannot populate invalid value of '"+user+"'.  Must be an user object or an ObjectID."));
    } else if(_.isObject(user)) {
      cb(undefined, user);
    } else {
      app.get('/api/1/users?access_token=' + adminAccessToken).expect('Content-Type', /json/).expect(200).end(function(err, res) {
        if(err) {
          done(err);
        } else {
          var responseObj = res.body;

          // TODO:
          //dm.validateResponseObject(responseObj);

          // Make sure all the SDL servers were returned for an admin.
          assert.equal(responseObj.response.length, fixtures.User.getAll().length);

          validateUsers(responseObj.response, adminRole, undefined, function(err) {
            done(err);
          });
        }
      });
    }
  };




  /* ************************************************** *
   * ******************** Test Suites
   * ************************************************** */

  describe('Users', function() {


    /* ************************************************** *
     * ******************** Lifecycle Methods
     * ************************************************** */

    beforeEach(function(done) {
      cramit.upsertFixtureData(fixtures, done);
    });

    afterEach(function(done) {
      cramit.removeFixtureData(fixtures, done);
    });


    /* ************************************************** *
     * ******************** Query All
     * ************************************************** */

    describe('can all be queried', function() {

      it('by an admin', function(done) {
        /*app.get('/api/1/users?access_token=' + adminAccessToken).expect('Content-Type', /json/).expect(200).end(function(err, res) {
          if(err) {
            done(err);
          } else {
            var responseObj = res.body;

            dm.validateResponseObject(responseObj);

            // Make sure all the SDL servers were returned for an admin.
            assert.equal(responseObj.response.length, data.User.getAll().length);

            validateUsers(responseObj.response, adminRole, undefined, function(err) {
              done(err);
            });
          }
        });*/
        done();
      });

    });
  });

};