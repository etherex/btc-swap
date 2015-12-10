module.exports = function(grunt) {
  grunt.initConfig({
    "babel": {
      options: {
        sourceMap: true,
        presets: ['es2015']
      },
      dist: {
        files: {
          "lib/keccak.js": "src/keccak.js",
          "lib/btc-swap.js": "src/btc-swap.js",
          "lib/abi/btc-swap.js": "src/abi/btc-swap.js",
          "lib/abi/btcrelay.js": "src/abi/btcrelay.js"
        }
      }
    },
    eslint: {
      options: {
        configFile: '.eslintrc'
      },
      target: ['Gruntfile.js', 'src/*.js']
    },
    mochacli: {
      options: {
        bail: true
      },
      all: ['test/*.js']
    },
    watch: {
      src: {
        files: ["src/*.js"],
        tasks: ["eslint", "babel"],
        options: {
          spawn: false
        }
      }
    }
  });

  grunt.loadNpmTasks('grunt-babel');
  grunt.loadNpmTasks('grunt-eslint');
  grunt.loadNpmTasks('grunt-mocha-cli');
  grunt.loadNpmTasks('grunt-contrib-watch');

  grunt.registerTask("lint", ["eslint"]);
  grunt.registerTask("build", ["eslint", "babel"]);
  grunt.registerTask('test', ["build", 'mochacli']);
  grunt.registerTask("default", ["build", "watch:src"]);
};
