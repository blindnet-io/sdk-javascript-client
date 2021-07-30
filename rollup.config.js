import resolve from 'rollup-plugin-node-resolve'
import commonjs from 'rollup-plugin-commonjs'
import typescript from 'rollup-plugin-typescript2'
import { terser } from "rollup-plugin-terser"
import pkg from './package.json'

const common = {
	input: 'src/index.ts',
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

export default [
	{
		...common,
		output: [
			{ name: 'blindnet', file: pkg.main, format: 'umd' }
		],
		plugins: [
			...common.plugins,
			terser()
		]
	}
]
