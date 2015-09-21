module.exports = function(app, config, log, data, dm) {

  var assert = require('assert'),
    async = require('async'),
    i18n = require('i18next'),
    should = require('should'),
    _ = require('lodash');

  var adminAccessToken = "",
    oemAccessToken = "",
    developerAccessToken = "";


  /* ************************************************** *
   * ******************** Private Methods
   * ************************************************** */


  /* ************************************************** *
   * ******************** Test Suites
   * ************************************************** */

  describe('Users', function() {


    /* ************************************************** *
     * ******************** Lifecycle Methods
     * ************************************************** */

    before(function(done) {
      console.log(data);
      done();
    });

    beforeEach(function(done) {
      done();
    });

    afterEach(function(done) {
      done();
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