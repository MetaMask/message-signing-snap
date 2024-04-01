/* eslint-disable n/no-sync, jsdoc/match-description */

const { readFileSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');

/**
 * Read the contents of a file and return as a string.
 * @param {string} filePath - The path to the file
 * @returns {string} The file as a string
 */
function readFileContents(filePath) {
  try {
    return readFileSync(filePath, 'utf8');
  } catch (error) {
    console.error(`Error reading file from disk: ${filePath}`, error);
    throw error;
  }
}

// Paths to the files
const bundlePath = require.resolve('../dist/bundle.js');
const iconPath = require.resolve('../images/icon.svg');
const manifestPath = require.resolve('../snap.manifest.json');
const typesPath = require.resolve('../bundle.json.d.ts');

// Read the file contents
const bundle = readFileContents(bundlePath);
const icon = readFileContents(iconPath);
const manifest = JSON.parse(readFileContents(manifestPath));
const types = readFileContents(typesPath);

// Combine the contents into an object
const combined = {
  bundle,
  icon,
  manifest,
};

// Path for the output JSON file
const outputPath = join(__dirname, '..', 'dist/bundle.json');
// Path for the types
const outputPathTypes = join(__dirname, '..', 'dist/bundle.json.d.ts');

// Write the combined contents to a JSON file
try {
  writeFileSync(outputPath, JSON.stringify(combined, null, 0));
  writeFileSync(outputPathTypes, types);
  console.log(`Combined file created successfully at ${outputPath}`);
} catch (error) {
  console.error('Error writing combined file to disk:', error);
  throw error;
}
