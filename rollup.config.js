import resolve from 'rollup-plugin-node-resolve'
import commonjs from 'rollup-plugin-commonjs'
import typescript from 'rollup-plugin-typescript2'
import { terser } from "rollup-plugin-terser"
import pkg from './package.json'

export default [
	{
		input: 'src/index.ts',
		output: [
			{ name: 'blindnet', file: pkg.browser, format: 'umd' }
		],
		plugins: [
			resolve({
				browser: true,
				extensions: ['.ts', '.js'],
				preferBuiltins: false
			}),
			commonjs(),
			typescript(),
			terser()
		]
	},
	{
		input: 'src/index.ts',
		external: [
			'crypto'
		],
		output: [
			{ file: pkg.module, format: 'es' }
		],
		plugins: [
			resolve({
				browser: true,
				extensions: ['.ts', '.js'],
				preferBuiltins: false
			}),
			commonjs(),
			typescript(),
		]
	},
	{
		input: 'src/index.ts',
		output: [
			{ file: pkg.main, format: 'cjs' }
		],
		plugins: [
			resolve({
				browser: true,
				extensions: ['.ts', '.js'],
				preferBuiltins: false
			}),
			commonjs(),
			typescript(),
		]
	}
]
