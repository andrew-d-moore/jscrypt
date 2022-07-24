const appConfig = require('./src/app.config')
const path = require('path');

module.exports = {
  name: appConfig.title,
  entry: './src/main.ts',
  mode: 'development',
  devtool: 'inline-source-map',
  entry: {
    main: './src/main.ts',
	},
  output: {
    filename: '[name].bundle.js',
    path: path.resolve(__dirname, 'dist'),
    clean: true,
  },
  resolve: {
    extensions: ['.tsx', '.ts', '.js']
  },
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
  optimization: {
    splitChunks: {
      minSize: 10000,
      maxSize: 250000
    }
	}
};