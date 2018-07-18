'use strict';

module.exports = {
  testEnvironment: 'node',
  collectCoverage: true,
  coverageDirectory: 'TestResults/coverage',
  coveragePathIgnorePatterns: [ '<rootDir>/test/' ],
  reporters: [
    'default',
    [ 'jest-junit', { output: 'TestResults/testresults.xml' } ]
  ],
  coverageReporters: [ 'text', 'html', 'cobertura' ]
};
