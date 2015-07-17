module.exports = function(grunt) {
  grunt.initConfig({
    "babel": {
      options: {
        sourceMap: true
      },
      dist: {
        files: {
          "lib/keccak.js": "src/keccak.js",
          "lib/btc-swap.js": "src/btc-swap.js",
          "lib/abi.js": "src/abi.js",
          "lib/debugAbi.js": "src/debugAbi.js"
        }
      }
    }
  });
  grunt.loadNpmTasks('grunt-babel');
  grunt.registerTask("default", ["babel"]);
};
