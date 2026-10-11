// Release notes page: lists algorithms that were REMOVED. No cryptography runs here.
const REMOVED_ALGORITHMS = ["md5", "sha1", "des-ede3-cbc"];

function renderChangelog(el) {
  el.innerText = "Removed: " + REMOVED_ALGORITHMS.join(", ");
}

module.exports = { renderChangelog };
