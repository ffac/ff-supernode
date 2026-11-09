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
{% for branch in firmware_branches %}
    '/firmware/download/{{ branch.dir }}/factory/': '{{ branch.name }}',
    '/firmware/download/{{ branch.dir }}/other/': '{{ branch.name }}',
    '/firmware/download/{{ branch.dir }}/sysupgrade/': '{{ branch.name }}',
{% if not loop.last %}

{% endif %}
{% endfor %}
  },
  // page title
  title: 'Firmware',
  // branch descriptions shown during selection
  branch_descriptions: {
{% for branch in firmware_branches %}
    '{{ branch.name }}': '{{ branch.description }}',
{% endfor %}
  },
  // recommended branch will be marked during selection
  recommended_branch: '{{ firmware_recommended_branch }}',
  // experimental branches (show a warning for these branches)
  experimental_branches: [{% for branch in firmware_branches if branch.experimental | default(false) %}'{{ branch.name }}'{% if not loop.last %}, {% endif %}{% endfor %}],
  // path to preview pictures directory
  preview_pictures: '{{ firmware_preview_pictures }}',
  // link to changelog
  changelog: '{{ firmware_changelog }}'
};
