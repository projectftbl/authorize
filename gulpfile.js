var gulp = require('gulp');

require('@ftbl/gulp')(gulp, { test: { coverage: 65 }});

gulp.task('default', [ 'test' ]);
