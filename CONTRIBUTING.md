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
- Have tests that cover the new or modified behaviour
- Don't decrease the current code coverage

## Development setup

Install all dependencies:

```sh
npm install
```

## Checking your work

In order to locally validate your changes, run the following

```sh
npm test
```

This will perform these checks:

- TypeScript type validation
- Eslint
- Tests execution (with text based coverage reporting)

To get a prettier detailed view on the current coverage

```sh
npx vitest --run --coverage --coverage.reporter=html
```

The html based coverage will be available under the `coverage/` directory.

## AI coding agents

If you are an AI coding agent working in this repository, read [AGENTS.md](./AGENTS.md) in full before making any changes.
It contains mandatory rules and machine-oriented conventions for TypeScript, testing, and the checks required before marking any task as done.
