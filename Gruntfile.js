module.exports = function(grunt) {
  grunt.initConfig({
    "babel": {
      options: {
        sourceMap: true
      },
      dist: {
        files: {
          // "lib/btcproof.js": "src/btcproof.js",
          "lib/keccak.js": "src/keccak.js",
          "lib/btcswap.js": "src/btcswap.js",
          "lib/abi.js": "src/abi.js"
        }
      }
    }
  });
  grunt.loadNpmTasks('grunt-babel');
  grunt.registerTask("default", ["babel"]);
};
