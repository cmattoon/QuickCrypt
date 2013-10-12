<?php
require('QuickCrypt.php');
$QuickCrypt = new QuickCrypt();

// Gets a random password of default length.
$random_password = $QuickCrypt->getRandomPassword();

// Creates a hash
$hash = $QuickCrypt->hash($random_password);

// Check to make sure it's valid
$password_is_valid = $QuickCrypt->checkPassword($random_password, $hash);

// Get the hash type that was created
$hash_type = $QuickCrypt->detectHashType($hash);

// @todo - Expand the stats/benchmarking method
$stats = $QuickCrypt->getStatistics();


?>
<div><strong>Random Password: </strong><?=$random_password;?></div>

<div><strong>Password Hash (<?=$hash_type;?>): </strong><?=$hash;?></div>

<div><?=($password_is_valid) ? '<span style="color:green">Password/Hash Match!</span>' : '<span style="color:red">Error with password/hash</span>';?></div>

<div>Hashing the password took <?=number_format($stats['time_to_hash'], 2);?> seconds at a work factor of <?=$stats['work_factor'];?> (Target 0.25-0.5)</div>
