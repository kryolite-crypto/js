import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';

export default [
	// browser-friendly UMD build
	{
		input: [
			'./build/index.js'
		],
		output: {
			name: 'kryolite',
			file: './lib/kryolite.umd.js',
			format: 'umd'
		},
		plugins: [
			nodeResolve({
				// pass custom options to the resolve plugin
				moduleDirectories: ['node_modules']
			}),
			commonjs()
		]
	},
	{
		input: [
			'./build/index.js'
		],
		output: [
			{ file: './lib/kryolite.cjs.js', format: 'cjs' },
			{ file: './lib/kryolite.esm.js', format: 'es' }
		],
		plugins: [
			nodeResolve(),
			commonjs()
		]
	}
];
