// This is a template for a jsconfig.json file which will be
// generated when starting the dev server or a build.
module.exports = {
  baseUrl: '.',
  compilerOptions: {
    baseUrl: '.',
    outDir: "./dist/",
    noImplicitAny: true,
    module: "es2022",
    target: "es2016",
    lib: ["es6"],
    esModuleInterop: true,
    forceConsistentCasingInFileNames: true,
    sourceMap: true,
    allowJs: true,
    strict: true,
    skipLibCheck: true,
    moduleResolution: "node",
  },
  include: ['src/**/*', 'tests/**/*'],
  exclude: ["node_modules"],
  // ...
  // `paths` will be automatically generated using aliases.config.js
  // ...
}