'use strict';

module.exports = {
  testEnvironment: 'node',
  collectCoverage: true,
  coverageDirectory: 'TestResults/coverage',
  coveragePathIgnorePatterns: ['<rootDir>/test/'],
  reporters: [
    'default',
    ['jest-junit', { outputDirectory: 'TestResults', outputName: 'testresults.xml' }],
  ],
  coverageReporters: ['text', 'html', 'cobertura'],
};
