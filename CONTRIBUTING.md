# Contributing

Preserve original source entries when updating the catalog. Merge aliases only
when they are the same application; retain original labels and source IDs.

New installer recipes must use official package registries/vendor sources, pass
arguments as arrays, avoid global Python installs and document platform/runtime
requirements. Do not add automatic execution of downloaded shell installers.

Add focused tests for new runtime behavior and run:

```bash
python3 -m unittest discover -s tests -v
python3 tools/build_catalog.py
bash -n l install.sh uninstall.sh
```

Document checks actually performed. Unverified tools belong in the catalog with
review-needed state, not an invented claim of compatibility.
