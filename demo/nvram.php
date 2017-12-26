<!-- $Id: nvram.php 1104 2017-12-06 13:58:03Z kgoldman $ -->

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
<title>TSS 2.0 Demo NV Indexes
<?php
echo gethostname();
?>
</title>
<link rel="stylesheet" type="text/css" href="demo.css">
</head>
			
<div id="header">
<img src="ibm.png" style="float:right;width:200px;height:70px">
<h2>IBM TSS Demo NV Indexes - 
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
    // print_r($_POST);
    //echo "<br>";

    $command = $_POST['command'];
    $ha = $_POST['ha'];
    $pwdpd = $_POST['pwdpd'];
    $pwdpu = $_POST['pwdpu'];
    $pwdn = $_POST['pwdn'];
    $hid = $_POST['hid'];
    $hiu = $_POST['hiu'];
    $ty = $_POST['ty'];
    $wd = $_POST['wd'];
    $szd = $_POST['szd'];
    $szr = $_POST['szr'];
    $ic = $_POST['ic'];
    
    $retval = 0;
    // parameter checks
    if ($retval == 0) {
	if (strlen($ha) == 0) {
	    echo "NV Index handle must be specified<br>";
	    $retval = 1;
	}
	if ($command == 'NV Define Space') {
	    if (strlen($ty) == 0) {
		echo "NV Define Space type must be specified<br>";
		$retval = 1;
	    }
	    if (strlen($hid) == 0) {
		echo "NV Define Space hierarchy must be specified<br>";
		$retval = 1;
	    }
	}
	if ($command == 'NV Undefine Space') {
	    if (strlen($hiu) == 0) {
		echo "NV Define Space hierarchy must be specified<br>";
		$retval = 1;
	    }
	}
    }
    // construct the command
    if ($retval == 0) {
	switch ($command) {
	  case 'NV Define Space':
	    $commandStr = "/var/www/html/tpm2/nvdefinespace";
	    $commandStr .= " -ha " . $ha;
	    if (strlen($pwdn) != 0) {
	        $commandStr .= " -pwdn " . $pwdn;
	    }
	    $commandStr .= " -ty " . $ty;
	    if (strlen($wd) != 0) {
	        $commandStr .= " +at wd";
	    }
	    $commandStr .= " -hi " . $hid;
	    if (strlen($pwdpd) != 0) {
	        $commandStr .= " -pwdp " . $pwdpd;
	    }
	    if (strlen($szd) != 0) {
	        $commandStr .= " -sz " . $szd;
	    }
	    break;
	  case 'NV Undefine Space':
	    $commandStr = "/var/www/html/tpm2/nvundefinespace";
	    $commandStr .= " -ha " . $ha;
	    $commandStr .= " -hi " . $hiu;
	    if (strlen($pwdpu) != 0) {
	        $commandStr .= " -pwdp " . $pwdpu;
	    }
	    break;
	  case 'NV Write':
	    $commandStr = "/var/www/html/tpm2/nvwrite";
	    $commandStr .= " -ha " . $ha;
	    if (strlen($pwdn) != 0) {
	        $commandStr .= " -pwdn " . $pwdn;
	    }
	    if (strlen($ic) != 0) {
	        $commandStr .= " -ic " . $ic;
	    }
	    break;
	  case 'NV Write Lock':
	    $commandStr = "/var/www/html/tpm2/nvwritelock";
	    $commandStr .= " -ha " . $ha;
	    if (strlen($pwdn) != 0) {
	        $commandStr .= " -pwdn " . $pwdn;
	    }
	    break;
	  case 'NV Read':
	    $commandStr = "/var/www/html/tpm2/nvread";
	    $commandStr .= " -ha " . $ha;
	    if (strlen($pwdn) != 0) {
	        $commandStr .= " -pwdn " . $pwdn;
	    }
	    if (strlen($szr) != 0) {
	        $commandStr .= " -sz " . $szr;
	    }
	    break;
	  case 'NV Increment':
	    $commandStr = "/var/www/html/tpm2/nvincrement";
	    $commandStr .= " -ha " . $ha;
	    if (strlen($pwdn) != 0) {
	        $commandStr .= " -pwdn " . $pwdn;
	    }
  	    break;
	  default:
	    echo ("Invalid command $command");
	    $retval = 1;
	    break;
	}
    }
    // run the command
    if ($retval == 0) {
	//echo 'Command string: ' . $commandStr . "<br>";
	unset($output);
	exec ($commandStr, $output, $retval);
	if ($retval == 0) {
	    if ($command == 'NV Define Space') {
		exec ("/var/www/html/tpm2/nvreadpublic -ha " .  $ha);
	    }
	    else if ($command == 'NV Read') {
		echo "NV Read data (hex ascii):<br>\n";
		echo "<kbd>";
		for ($l = 1 ; $l < count($output) ; $l++) {
		    echo $output[$l] . "<br>";
		}
		echo "</kbd>";

		// convert back to ascii
		echo "NV Read data (ascii):<br>\n";
		for ($l = 1 ; $l < count($output) ; $l++) {
		    $chars = str_split ($output[$l], 3);
		    for ($i = 0 ; $i < count($chars) ; $i++) {
		        echo chr('0x' . trim($chars[$i]));
		    }
		    echo "<br>\n";
		}
	    }
	    //echo "Success";
	}
	else {
	    echo $commandStr . "<br>";
	    for ($i = 0 ; $i < count($output) ; $i++) {
		echo $output[$i] . "<br>";
	    }
	}
    }
}
?>


<form method="post" action="nvram.php">

<h3>NV Index Parameters</h3>
Index Handle <input type="text" name="ha" value="<?php
     if (strlen($ha) != 0) {
        echo $ha;
     }
     else {
        echo "01000000";
     }
?>">
<br>
Index Password <input type="password" name="pwdn" value="<?php echo $pwdn; ?>">
<br>

<h3>NV Define Space (Create Index)</h3>

Type
<input type="radio" name="ty" value="o"
          <?php if (($ty == "o") || !isset($ty)) echo " checked"; ?>>Ordinary
<input type="radio" name="ty" value="c"
          <?php if ($ty == "c") echo " checked"; ?>>Counter
<input type="radio" name="ty" value="b"
          <?php if ($ty == "b") echo " checked"; ?>>Bits
<input type="radio" name="ty" value="e"
          <?php if ($ty == "e") echo " checked"; ?>>Extend
<br>
Attributes
<input type="checkbox" name="wd" value="t" checked>Write Define (Lockable)
<br>
Hierarchy
<input type="radio" name="hid" value="p"
          <?php if ($hid == "p") echo " checked"; ?>>Platform
<input type="radio" name="hid" value="o" 
          <?php if (($hid == "o") || !isset($hid)) echo " checked"; ?>>Owner
<br>
Hierarchy Password <input type="password" name="pwdpd" value="<?php echo $pwdpd; ?>">
<br>
Index Size <input type="text" name="szd" value="
<?php
     if (strlen($szd) != 0) {
        echo $szd;
     }
     else {
        echo "8";
     }
?>">
<br>
<input type="submit" name="command" value="NV Define Space">

<h3>NV Undefine Space (Delete Index)</h3>

Hierarchy
<input type="radio" name="hiu" value="p"
          <?php if ($hiu == "p")  echo " checked"; ?>>Platform
<input type="radio" name="hiu" value="o" 
          <?php if (($hiu == "o") || !isset($hiu)) echo " checked"; ?>>Owner
<br>
Hierarchy Password <input type="password" name="pwdpu" value="<?php echo $pwdpu; ?>">
<br>
<input type="submit" name="command" value="NV Undefine Space">

<h3>NV Write</h3>
Data <input type="text" name="ic" value="<?php echo $ic; ?>">
<br>
<input type="submit" name="command" value="NV Write">

<h3>NV Write Lock</h3>
<input type="submit" name="command" value="NV Write Lock">

<h3>NV Read</h3>
Index Size <input type="text" name="szr" value="<?php
     if (strlen($szr) != 0) {
        echo $szr;
     }
     else {
        echo "8";
     }
?>">

<br>
<input type="submit" name="command" value="NV Read">


<h3>NV Increment</h3>
<input type="submit" name="command" value="NV Increment">

</div>

<?php
require '/var/www/html/tpm2/footer.html';
?>

</body>
</html>

