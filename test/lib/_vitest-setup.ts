// From https://github.com/vitest-dev/vitest/issues/1692#issuecomment-1366855827

process.on('unhandledRejection', (reason) => {

  console.error('/!\\ Failed to handle promise rejection');
  throw reason;
});

export default {};
