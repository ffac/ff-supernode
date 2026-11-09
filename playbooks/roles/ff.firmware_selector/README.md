# gluon-firmware-selector

The firmware_selector role clones the upstream firmware selector (`firmware_selector_repo`, branch `firmware_selector_version`) and overwrites `devices.js` and `config.js` with the templates of this role.

The resulting folder `/var/www/gluon-firmware-selector/` must then be served on a webpage like `firmware.your-ff-domain.de`

## Adjustments

The `devices.js` template is the upstream `devices.js` plus our own devices. The Gluon branches shown by the selector come from `firmware_branches`.

Most crucial things can be edited through the template variables.