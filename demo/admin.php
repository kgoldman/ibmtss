<!-- $Id: admin.php 1120 2018-01-02 14:32:44Z kgoldman $ -->

<?php
/* (c) Copyright IBM Corporation 2016.						*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/
?>

<html>
<head>
<title>TSS 2.0 Demo Administration
<?php
echo gethostname();
?>
</title>
<link rel="stylesheet" type="text/css" href="demo.css">
</head>
<body>

<form method="post" action="admin.php">

<div id="header">
<img src="ibm.png" style="float:right;width:200px;height:70px">
<h2>IBM TSS Demo Administration - 
<?php
echo gethostname();
?>
</h2>
</div>

<?php
require '/var/www/html/tpm2/nav.html';
?>

<div id="section">

<?php
if ( $_SERVER['REQUEST_METHOD'] == 'POST' ) {
    $command = $_POST['command'];
    $hic = $_POST['hic'];
    $hip = $_POST['hip'];
    $pwda = $_POST['pwda'];
    $pwdn1 = $_POST['pwdn1'];
    $pwdn2 = $_POST['pwdn2'];
    
    $retval = 0;
    // parameter checks
    if ($retval == 0) {
	if ($command == 'Change Password') {
	    if ($pwdn1 != $pwdn2) {
		echo "New passwords do not match";
		$retval = 1;
		$pwdn1 = $pwda;     // don't roll the old password
	    }
	}
	/* radio buttons, should never occur */
	if (strlen($hic) == 0) {
	    echo "Clock - authorization hierarchy must be specified<br>\n";
	    $retval = 1;
	}
	/* radio buttons, should never occur */
	if (strlen($hip) == 0) {
	    echo "Password - authorization hierarchy must be specified<br>\n";
	    $retval = 1;
	}
    }
    // construct the command
    if ($retval == 0) {
	switch ($command) {
	  case 'Change Password':
	  $commandStr = "/var/www/html/tpm2/hierarchychangeauth";
	    $commandStr .= " -hi " . $hip;
	    if (strlen($pwda) != 0) {
	        $commandStr .= " -pwda " . $pwda;
	    }
	    if (strlen($pwdn1) != 0) {
	        $commandStr .= " -pwdn " . $pwdn1;
	    }
	    break;

	  case 'Set TPM Date and Time':
	    $commandStr = "/var/www/html/tpm2/clockset";
            $commandStr .= " -hi " . $hic;
	    $currenttime = time();				// php time in sec
	    $commandStr .= " -clock " . ($currenttime * 1000);	// TPM command in msec
	    break;

	  case 'SH disable':
	    $commandStr = "/var/www/html/tpm2/hierarchycontrol -hi p -he o -state 0";
	    break;
	  case 'SH enable':
	    $commandStr = "/var/www/html/tpm2/hierarchycontrol -hi p -he o -state 1";
	    break;
	  case 'EH disable':
	    $commandStr = "/var/www/html/tpm2/hierarchycontrol -hi p -he e -state 0";
	    break;
	  case 'EH enable':
	    $commandStr = "/var/www/html/tpm2/hierarchycontrol -hi p -he e -state 1";
	    break;
	  case 'phEnableNV clear':
	    $commandStr = "/var/www/html/tpm2/hierarchycontrol -hi p -he n -state o";
	    break;
	  case 'phEnableNV set':
	    $commandStr = "/var/www/html/tpm2/hierarchycontrol -hi p -he n -state 1";
	    break;
	  default:
	    echo ("Invalid command $command");
	    $retval = 1;
	    break;
	}
    }
    if ($retval == 0) {
	// uncomment for test and debug, permits view of TPM command
        //echo 'Command string: ' . $commandStr. "<br>\n"; $retval = 0;
        unset($output);
        exec ($commandStr, $output, $retval);
        if ($retval == 0) {
            ;
        }
        else {
            echo $commandStr . "<br>\n";
            for ($i = 0 ; $i < count($output) ; $i++) {
                echo $output[$i] . "<br>\n";
            }
        }
    }
}
     
echo "<h3>TPM Information</h3>";
unset($output);
exec ("/var/www/html/tpm2/getcapability -cap 6", $output, $retval);
//print_r($output);

$key = searchForValue("TPM_PT_MANUFACTURER", $output);
$value = $output[$key];
$values = explode (" ", trim($value));
echo "Manufacturer: ";
$chars = str_split ($values[3], 2);
for ($i = 0 ; $i < count($chars) ; $i++) {
    echo chr(hexdec($chars[$i]));
}
echo "<br>\n";

echo "Vendor String: ";
$key = searchForValue("TPM_PT_VENDOR_STRING_1", $output);
$value = $output[$key];
$values = explode (" ", trim($value));
$chars = str_split ($values[3], 2);
for ($i = 0 ; $i < count($chars) ; $i++) {
    echo chr(hexdec($chars[$i]));
}

$key = searchForValue("TPM_PT_VENDOR_STRING_2", $output);
$value = $output[$key];
$values = explode (" ", trim($value));
$chars = str_split ($values[3], 2);
for ($i = 0 ; $i < count($chars) ; $i++) {
    echo chr(hexdec($chars[$i]));
}
echo "<br>\n";

$key = searchForValue("TPM_PT_REVISION", $output);
$value = $output[$key];
$values = explode (" ", trim($value));
echo "Revision: " . hexdec($values[3]) . "<br>\n";

$key = searchForValue("TPM_PT_FIRMWARE_VERSION_1", $output);
$value = $output[$key];
$values = explode (" ", trim($value));
echo "Firmware: " . $values[3];

$key = searchForValue("TPM_PT_FIRMWARE_VERSION_2", $output);
$value = $output[$key];
$values = explode (" ", trim($value));
echo " " . $values[3];
echo "<br>\n";

unset($output);
exec ("/var/www/html/tpm2/readclock", $output, $retval);
$key = searchForValue("TPMS_TIME_INFO", $output);
$value = $output[$key];
$values = explode (" ", trim($value));
echo "TPM Time since startup: " . $values[2] . " msec<br>\n";

$key = searchForValue("  TPMS_CLOCK_INFO", $output);
$value = $output[$key];
$values = explode (" ", trim($value));				// TPM time in msec
echo "TPM Date and Time: " . date(DATE_RSS, ($values[2] / 1000));	// php time in sec

?>

<input type="submit" name="command" value="Set TPM Date and Time">
<input type="radio" name="hic" value="p"
     <?php if ($hic == "p") echo " checked"; ?>>Platform
<input type="radio" name="hic" value="o"
     <?php if (($hic == "o") || !isset($hic)) echo " checked"; ?>>Owner

<h3>TPM Status</h3>

<?php
unset($output);
exec ("/var/www/html/tpm2/getcapability -cap 6 -pr 200 -pc 1", $output, $retval);
$capitems = explode(" ", trim($output[2]));
$val = hexdec($capitems[3]);
if ($val & 0x0001) {
    echo "Owner auth set<br>\n";
}
else {
    echo "Owner auth clear<br>\n";
}
if ($val & 0x0002) {
    echo "Endorsement auth set<br>\n";
}
else {
    echo "Endorsement auth clear<br>\n";
}
if ($val & 0x0004) {
    echo "Lockout auth set<br>\n";
}
else {
    echo "Lockout auth clear<br>\n";
}
if ($val & 0x0100) {
    echo "TPM2_Clear disabled<br>\n";
}
else {
    echo "TPM2_Clear enabled<br>\n";
}
if ($val & 0x0200) {
    echo "In lockout<br>\n";
}
else {
    echo "Not in lockout<br>\n";
}
if ($val & 0x0400) {
    echo "TPM generated EPS<br>\n";
}
else {
    echo "EPS createed outside TPM<br>\n";
}
echo "<br>\n";
unset($output);
exec ("/var/www/html/tpm2/getcapability -cap 6 -pr 201 -pc 1", $output, $retval);
$capitems = explode(" ", trim($output[2]));
$val = hexdec($capitems[3]);
if ($val & 0x0001) {
    echo "Platform hierarchy enabled<br>\n";
}
else {
    echo "Platform hierarchy disabled<br>\n";
}
if ($val & 0x0002) {
    echo "Storage hierarchy enabled &nbsp;&nbsp;&nbsp; <input type=\"submit\" name=\"command\" value=\"SH disable\"><br>\n";
}
else {
    echo "Storage hierarchy disabled &nbsp;&nbsp;&nbsp; <input type=\"submit\" name=\"command\" value=\"SH enable\"><br>\n";
}
if ($val & 0x0004) {
    echo "Endorsement hierarchy enabled &nbsp;&nbsp;&nbsp; <input type=\"submit\" name=\"command\" value=\"EH disable\"><br>\n";
}
else {
    echo "Endorsement hierarchy disabled &nbsp;&nbsp;&nbsp; <input type=\"submit\" name=\"command\" value=\"EH enable\"><br>\n";
}
if ($val & 0x0008) {
    echo "phEnableNV set &nbsp;&nbsp;&nbsp; <input type=\"submit\" name=\"command\" value=\"phEnableNV clear\"><br>\n";
}
else {
    echo "phEnableNV clear &nbsp;&nbsp;&nbsp; <input type=\"submit\" name=\"command\" value=\"phEnableNV set\"><br>\n";
}
?>

<h3>TPM Random Number Generator</h3>

<?php
unset($output);
exec ("/var/www/html/tpm2/getrandom -by 16 -of rng.tmp", $output, $retval);
$rngbinary = file_get_contents ("rng.tmp");
$rngstring = bin2hex ($rngbinary);
echo "Random number: " . $rngstring. "<br>\n";
unlink ('rng.tmp');

function searchForValue($keyword, $arrayToSearch){
    foreach($arrayToSearch as $key => $arrayItem){
        if( stristr( $arrayItem, $keyword ) ){
            return $key;
        }
    }
}

?>

<h3>TPM Authorization</h3>

<input type="radio" name="hip" value="p"
     <?php if ($hip == "p") echo " checked"; ?>>Platform
<input type="radio" name="hip" value="o"
     <?php if (($hip == "o") || !isset($hip)) echo " checked"; ?>>Owner
<br>     
Old Password <input type="password" name="pwda" value="<?php echo $pwdn1; ?>"><br>
New Password <input type="password" name="pwdn1" value="<?php echo $pwdn1; ?>"><br>
New Password <input type="password" name="pwdn2" value="<?php echo $pwdn1; ?>"><br>

<input type="submit" name="command" value="Change Password"><br>

</div>

<?php
require '/var/www/html/tpm2/footer.html';
?>

</body>
</html>
