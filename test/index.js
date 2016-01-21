// Set the node environment mode to testing.
process.env.NODE_ENV = 'test';

var app = require('../index.js'),
    config = require('../config/'),
    crave = require("crave"),
    log = new (require('seedio-log'))(config),//TODO: Match whatever index does.
    path = require("path"),
    supertest = require('supertest')(app);

var applicationPath = path.resolve("./app"),
    cramit = require("cramit")(config.cramit, log),
    fixtures = {};

// Set crave to find files based on the file name.
crave.setConfig({
  identification: {
    type: "filename",         // Look at the file name.
    identifier: "_"           // Look for an underscore preceding a file type.
  }
});

cramit.setDatabaseInstance(require('mongoose'));

describe('Seedio', function() {

  // Load the test data object that will be passed into each test file.
  before(function(done) {
    this.timeout(0);

    cramit.findAllFixtures(applicationPath, {}, function(err, _fixtures) {
      if(err) {
        done(err);
      } else {
        fixtures = _fixtures;
        done();
      }
    });
  });

  it('load all tests', function(done) {
    this.timeout(0);
    // Recursively load all the test files that are located in the apps folder.
    crave.directory(applicationPath, ["test"], done, supertest, config, log, fixtures);
  });

});