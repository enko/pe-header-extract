<?php

require_once('../PEHeaderExtract.class.php');

$version_info = new PEHeaderExtract('C:/Windows/regedit.exe');

print_r(array(
  'major' => $version_info->major,
  'minor' => $version_info->minor,
  'revision' => $version_info->revision,
  'build' => $version_info->build,
));