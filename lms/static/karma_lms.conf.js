// Karma config for lms suite.
// Docs in common/static/common/js/karma.common.conf.js

/* jshint node: true */
/*jshint -W079 */
'use strict';
var path = require('path');
var configModule = require(path.join(__dirname, '../../common/static/common/js/karma.common.conf.js'));

var files = {
    libraryFilesToInclude: [
        {pattern: 'xmodule_js/common_static/js/vendor/jquery.event.drag-2.2.js', included: true},
        {pattern: 'xmodule_js/common_static/js/vendor/slick.core.js', included: true},
        {pattern: 'xmodule_js/common_static/js/vendor/slick.grid.js', included: true}
    ],

    libraryFiles: [
        {pattern: 'common/js/**/*.js'},
        {pattern: 'edx-pattern-library/js/**/*.js'},
        {pattern: 'edx-ui-toolkit/js/**/*.js'},
        {pattern: 'js/RequireJS-namespace-undefine.js'},
        {pattern: 'xmodule_js/common_static/coffee/src/**/*.js'},
        {pattern: 'xmodule_js/common_static/js/**/*.js'},
        {pattern: 'xmodule_js/src/capa/*.js'},
        {pattern: 'xmodule_js/src/video/*.js'},
        {pattern: 'xmodule_js/src/xmodule.js'}
    ],

    sourceFiles: [
        {pattern: 'coffee/src/**/!(*spec).js'},
        {pattern: 'js/**/!(*spec|djangojs).js'},
        {pattern: 'support/js/**/!(*spec).js'},
        {pattern: 'teams/js/**/!(*spec).js'},
        {pattern: 'xmodule_js/common_static/coffee/**/!(*spec).js'}
    ],

    specFiles: [
        {pattern: 'js/spec/**/*spec.js'},
        {pattern: 'support/js/spec/**/*spec.js'},
        {pattern: 'teams/js/spec/**/*spec.js'}
    ],

    fixtureFiles: [
        {pattern: 'js/fixtures/**/*.html'},
        {pattern: 'common/templates/**/*.*'},
        {pattern: 'support/templates/**/*.*'},
        {pattern: 'teams/templates/**/*.*'},
        {pattern: 'templates/**/*.*'}
    ],

    runFiles: [
        {pattern: 'js/spec/main.js', included: true}
    ]
};

module.exports = function (config) {
    configModule.configure({
        config: config,
        files: files
    });
};
