const path = require('path');

const config = {
	entry: './run.js', // File đầu vào
	output: {
		// File đầu ra
		filename: 'bundle.js', // Tên file đầu ra
		path: path.resolve(__dirname, 'build'), // Nơi chưa file đầu ra
	},
	mode: 'production',
	resolve: {
		fallback: {
			util: require.resolve('util/'),
			fs: false,
			crypto: false,
		},
	},
};

module.exports = config;
