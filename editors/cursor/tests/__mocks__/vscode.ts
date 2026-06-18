const workspace = {
  workspaceFolders: undefined,
  getConfiguration: jest.fn().mockReturnValue({
    get: jest.fn().mockReturnValue(".cursorrules"),
  }),
};

module.exports = { workspace };
