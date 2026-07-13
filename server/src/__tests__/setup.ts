// Global test setup. Default the keyless "free defaults" provisioning OFF so
// every suite starts from a clean, controlled account baseline (many tests add
// a specific key and assert exact routing/usage). The onboarding suite opts
// back in per-test by deleting this var.
process.env.DISABLE_FREE_DEFAULTS = '1';
