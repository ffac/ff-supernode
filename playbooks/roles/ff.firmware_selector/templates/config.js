/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

var config = {
  // list images on console that match no model
  listMissingImages: false,
  // see devices.js for different vendor model maps
  vendormodels: vendormodels,
  // set enabled categories of devices (see devices.js)
  enabled_device_categories: ["recommended", "small_kernel_part", "ath10k_lowmem", "8_32", "4_32", "16_32", "broken"],
  // Display a checkbox that allows to display not recommended devices.
  // This only make sense if enabled_device_categories also contains not
  // recommended devices.
  recommended_toggle: {{ recommended_toggle }},
  // Optional link to an info page about no longer recommended devices
  recommended_info_link: '{{ recommended_info_link }}',
  // community prefix of the firmware images
  community_prefix: '{{ community_prefix }}',
  // firmware version regex
  version_regex: {{ version_regex }},
  // relative image paths and branch

  directories: {

    '/firmware/download/from-2023.2.x/factory/': 'v2023.2',
    '/firmware/download/from-2023.2.x/other/': 'v2023.2',
    '/firmware/download/from-2023.2.x/sysupgrade/': 'v2023.2',

    '/firmware/download/from-2024.1.x/factory/': 'v2024.1',
    '/firmware/download/from-2024.1.x/other/': 'v2024.1',
    '/firmware/download/from-2024.1.x/sysupgrade/': 'v2024.1',

  },
  // page title
  title: 'Firmware',
  // branch descriptions shown during selection
  branch_descriptions: {
    'v2023.1': 'oldstable - Gluon v2023.1.x basiert auf OpenWrt 22.03 - unterstützt Updates von v2021.1 oder neuer',
    'v2023.2': 'stable - Gluon v2023.2.x basiert auf OpenWrt 23.05 - unterstützt Updates von v2023.1 oder neuer',
    'v2024.1': 'experimental - Gluon v2024.1.x basiert auf OpenWrt main - nicht offiziell unterstützt',
  },
  // recommended branch will be marked during selection
  recommended_branch: 'v2023.2',
  // experimental branches (show a warning for these branches)
  experimental_branches: ['v2024.1'],
  // path to preview pictures directory
  preview_pictures: 'https://map.aachen.freifunk.net/pictures-jpg/',
  // link to changelog
  changelog: '{{ firmware_changelog }}'
};
