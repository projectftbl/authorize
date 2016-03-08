var _ = require('lodash')
  , should = require('chai').should()
  , Sut = require('../lib')
  , permissions = Sut.permissions
  , rights = Sut.rights;

describe('When using the Authorizer service', function() {

  var suite = this;

  var p = function(thing, permission) {
    return { thing: thing, permission: permission }
  };

  describe('From roles', function() {
    before(function() {
      suite.sut = new Sut();
    });

    it('Should map empty permissions from empty roles', function() {
      suite.sut.fromRoles([]).should.deep.equal([]);
    });
  });

  describe('With no permissions', function() {
    before(function() {
      suite.sut = new Sut(p('thing', permissions.None));
    });

    validate('thing', [
      [ rights.Nothing, true  ]
    , [ rights.Lookup,  false ]
    , [ rights.Read,    false ]
    , [ rights.Create,  false ]
    , [ rights.Update,  false ]
    , [ rights.Destroy, false ]
    ]);
  });

  describe('With lookup permissions', function() {

    before(function() {
      suite.sut = new Sut(p('thing', permissions.Lookup));
    });

    validate('thing', [
      [ rights.Nothing, true  ]
    , [ rights.Lookup,  true  ]
    , [ rights.Read,    false ]
    , [ rights.Create,  false ]
    , [ rights.Update,  false ]
    , [ rights.Destroy, false ]
    ]);

  });

  describe('With read only permissions', function() {

    before(function() {
      suite.sut = new Sut(p('thing', permissions.ReadOnly));
    });

    validate('thing', [
      [ rights.Nothing, true  ]
    , [ rights.Lookup,  true  ]
    , [ rights.Read,    true  ]
    , [ rights.Create,  false ]
    , [ rights.Update,  false ]
    , [ rights.Destroy, false ]
    ]);
  });

  describe('With editor permissions', function() {

    before(function() {
      suite.sut = new Sut(p('thing', permissions.Editor));
    });

    validate('thing', [
      [ rights.Nothing, true  ]
    , [ rights.Lookup,  true  ]
    , [ rights.Read,    true  ]
    , [ rights.Create,  false ]
    , [ rights.Update,  true  ]
    , [ rights.Destroy, false ]
    ]);
  });

  describe('With full permissions', function() {

    before(function() {
      suite.sut = new Sut(p('thing', permissions.FullAccess));
    });

    validate('thing', [
      [ rights.Nothing, true  ]
    , [ rights.Lookup,  true  ]
    , [ rights.Read,    true  ]
    , [ rights.Create,  true  ]
    , [ rights.Update,  true  ]
    , [ rights.Destroy, true  ]
    ]);
  });

  describe('With multiple permissions for the same thing', function() {

    before(function() {
      suite.sut = new Sut([ p('thing', permissions.ReadOnly), p('thing', permissions.Editor) ]);
    });

    validate('thing', [
      [ rights.Nothing, true  ]
    , [ rights.Lookup,  true  ]
    , [ rights.Read,    true  ]
    , [ rights.Create,  false ]
    , [ rights.Update,  true  ]
    , [ rights.Destroy, false ]
    ]);

  });

  describe('With multiple permissions (including no access) for the same thing', function() {

    before(function() {
      suite.sut = new Sut([ p('thing', permissions.NoAccess), p('thing', permissions.Editor) ]);
    });

    validate('thing', [
      [ rights.Nothing, true  ]
    , [ rights.Lookup,  true  ]
    , [ rights.Read,    true  ]
    , [ rights.Create,  false ]
    , [ rights.Update,  true  ]
    , [ rights.Destroy, false ]
    ]);

  });

  describe('With multiple, different, separate permissions for different things', function() {

    before(function() {
      suite.sut = new Sut([ p('thing', permissions.ReadOnly), p('other', permissions.FullAccess) ]);
    });

    validate('thing', [
      [ rights.Nothing, true  ]
    , [ rights.Lookup,  true  ]
    , [ rights.Read,    true  ]
    , [ rights.Create,  false ]
    , [ rights.Update,  false ]
    , [ rights.Destroy, false ]
    ]);

    validate('other', [
      [ rights.Nothing, true  ]
    , [ rights.Lookup,  true  ]
    , [ rights.Read,    true  ]
    , [ rights.Create,  true  ]
    , [ rights.Update,  true  ]
    , [ rights.Destroy, true  ]
    ]);

  });

  describe('With multiple permissions for different things', function() {

    before(function() {
      suite.sut = new Sut([ 
        p('thing', permissions.ReadOnly),   p('thing', permissions.Editor)
      , p('other', permissions.Lookup),     p('other', permissions.ReadOnly) ]);
    });

    validate('thing', [
      [ rights.Nothing, true  ]
    , [ rights.Lookup,  true  ]
    , [ rights.Read,    true  ]
    , [ rights.Create,  false ]
    , [ rights.Update,  true ]
    , [ rights.Destroy, false ]
    ]);

    validate('other', [
      [ rights.Nothing, true  ]
    , [ rights.Lookup,  true  ]
    , [ rights.Read,    true  ]
    , [ rights.Create,  false ]
    , [ rights.Update,  false ]
    , [ rights.Destroy, false ]
    ]);

  });

  describe('With permissions as an array', function() {

    before(function() {
      suite.sut = new Sut([[ 'thing', permissions.ReadOnly ]]);
    });

    validate('thing', [
      [ rights.Nothing, true  ]
    , [ rights.Lookup,  true  ]
    , [ rights.Read,    true  ]
    , [ rights.Create,  false ]
    , [ rights.Update,  false ]
    , [ rights.Destroy, false ]
    ]);

  });

  describe('With permissions as a string', function() {
    before(function() {
      suite.sut = new Sut([[ 'thing', permissions.ReadOnly ]]);
    });

    it('should have access to read thing', function() {
      suite.sut.can('read thing').should.equal(true);
    });

    it('should have access to lookup thing', function() {
      suite.sut.can('lookup thing').should.equal(true);
    });

    it('should not have access to create thing', function() {
      suite.sut.can('create thing').should.equal(false);
    });

    it('should not have access to random thing', function() {
      suite.sut.can('random thing').should.equal(false);
    });
  });

  function validate(thing, checks) {

    var message = function(check) {
      var m = 'should ';
      if (check[1] === false) m += 'not ';
      m += 'have access to ';
      m += _(rights).findKey(function(r) { return r === check[0] }).toLowerCase()
      m += ' on ' + thing;
      return m;
    };

    checks.forEach(function(check) {
      it(message(check), function() {
        suite.sut.can(thing, check[0]).should.equal(check[1]);
      });
    });
  };

});