const path = require('path');

module.exports = {
  mode: 'development',
  devtool: 'eval-source-map',
  entry: './src/index.ts',
  output: {
    // [name].[contentHash].bundle.js
    filename: 'blindnet.js',
    path: path.resolve(__dirname, 'dist'),
    publicPath: "/dist/",
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
    extensions: [".tsx", ".ts", ".js"]
  }
  // module: {
  //   loaders: [
  //     {
  //       test: /(\\.js)$/,
  //       loader: 'babel',
  //       exclude: /node_modules/
  //     },
  //     {
  //       test: /(\\.js)$/,
  //       loader: "eslint-loader",
  //       exclude: /node_modules/
  //     }
  //   ]
  // },
  // resolve: {
  //   root: path.resolve('./src'),
  //   extensions: ['', '.js']
  // }
}