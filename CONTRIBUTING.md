# How to Contribute

## Reporting Issues

Should you run into issues with the project, please don't hesitate to let us know by
[filing an issue](https://github.com/axa-group/oauth2-mock-server/issues/new).

Pull requests containing only failing tests demonstrating the issue are welcomed
and this also helps ensure that your issue won't regress in the future once it's fixed.

## Pull Requests

We accept [pull requests](https://github.com/axa-group/oauth2-mock-server/pull/new/master)!

Generally we like to see pull requests that

- Maintain the existing code style
- Are focused on a single change (i.e. avoid large refactoring or style adjustments in untouched code if not the primary goal of the pull request)
- Have [good commit messages](https://chris.beams.io/posts/git-commit/)
- Have tests
- Don't decrease the current code coverage (see `TestResults/coverage/index.html`)

## Running tests

To run tests locally, first install all dependencies.

```shell
npm install
```

From the root directory, run the tests.

```shell
npm run test
```
