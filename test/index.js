// Set the node environment mode to testing.
process.env.NODE_ENV = 'test';

var app = require('../index.js'),
    config = require('../config/'),
    crave = require("crave"),
    log = new (require('seedio-log'))(config),
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

    var loadModels = function(cb) {
      // Configure Crave.
      crave.setConfig({
        error: true,
        cache: {                    // Crave can store the list of files to load rather than create it each time.
          enable: false             // Disable caching of the list of files to load.  In production this should be enabled.
        },
        identification: {           // Variables related to how to find and require files are stored here.
          type: "filename",         // Determines how to find files.  Available options are: 'string', 'filename'
          identifier: "_"           // Determines how to identify the files.
        }
      });

      // Recursively load all files of the specified type(s) that are also located in the specified folder.
      //crave.directory(applicationPath, [ "model" ], cb, app, config, log);
      cb();
    };

    // Find all fixtures.
    loadModels(function(err) {
      if(err) {
        return done(err);
      }
      cramit.findAllFixtures(applicationPath, {}, function(err, _fixtures) {
        if(err) {
          done(err);
        } else {
          fixtures = _fixtures;
          done();
        }
      });
    });
  });

  it('load all tests', function(done) {
    this.timeout(0);
    // Recursively load all the test files that are located in the apps folder.
    crave.directory(applicationPath, ["test"], done, supertest, config, log, fixtures);
  });

});