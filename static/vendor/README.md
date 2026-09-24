# Bundled browser dependencies

These files replace the dashboard's jsDelivr requests, preserving its existing versions.

| Local directory | Source files |
| --- | --- |
| `xterm-5.3.0` | `https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.min.css`, `https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js` |
| `xterm-addon-fit-0.8.0` | `https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js` |
| `chart.js-4.4.1` | `https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js` |

Files are vendored unchanged; each directory contains the upstream MIT license.
Source maps are not bundled. The application does not require them.

When upgrading, use new versioned paths and update both `static/index.html` and
`VENDOR_ASSETS` in `server.py`, because assets are cached as immutable for one year.
