const path = require('path');

module.exports = {
  mode: 'development',
  devtool: 'eval-source-map',
  entry: './src/index.ts',
  output: {
    filename: 'index.js',
    path: path.resolve(__dirname, 'dist'),
    publicPath: '/dist/',
    library: {
      name: 'blindnet',
      type: 'umd'
    }
  },
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        loader: 'ts-loader',
        exclude: /node_modules/,
      },
    ]
  },
  resolve: {
    fallback: { crypto: false },
    extensions: ['.ts', '.js']
  }
}