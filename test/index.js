// Set the node environment mode to testing.
process.env.NODE_ENV = 'test';

var app = require('../index.js'),
    assert = require('assert')  ,
    config = require('../config/'),
    crave = require("crave"),
    DM = require('../libs/dataManager/'),
    log = new (require('seedio-log'))(config),
    path = require("path"),
    supertest = require('supertest')(app);

var applicationPath = path.resolve("./app"),
    data = {},
    dm = new DM(app, config, log);

// Set crave to find files based on the file name.
crave.setConfig({
  identification: {
    type: "filename",         // Look at the file name.
    identifier: "_"           // Look for an underscore preceding a file type.
  }
});

describe('Seedio', function() {

  // Load the test data object that will be passed into each test file.
  before(function(done) {
    this.timeout(0);

    // Format the returned data object into something the test files can use.
    var formatData = function(err, files, results) {
      if(err) {
        done(err);
      } else {
        for(var i = 0; i < results.length; i++) {
          if(results[i] !== undefined && results[i].error === undefined && results[i].name !== undefined) {
            data[results[i].name] = results[i];
          }
        }
        done();
      }
    };

    // Recursively load all data files that are located in the apps folder.
    crave.directory(applicationPath, ["fixture"], formatData, supertest, config, log, dm);
  });

  it('load all tests', function(done) {
    this.timeout(0);
    // Recursively load all the test files that are located in the apps folder.
    crave.directory(applicationPath, ["test"], done, supertest, config, log, data, dm);
  });

});