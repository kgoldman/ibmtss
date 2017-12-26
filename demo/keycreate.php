<!-- $Id: keycreate.php 1104 2017-12-06 13:58:03Z kgoldman $ -->

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
<title>TSS 2.0 Demo Key Creation
<?php
echo gethostname();
?>
</title>
<link rel="stylesheet" type="text/css" href="demo.css">
</head>
<body>

<div id="header">
<img src="ibm.png" style="float:right;width:200px;height:70px">
<h2>IBM TSS Demo Key Creation - 
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
require '/var/www/html/tpm2/halg.inc';

if ( $_SERVER['REQUEST_METHOD'] == 'POST' ) {
    //print_r($_POST);
    $command = $_POST['command'];
    $hi = $_POST['hi'];
    $hp = $_POST['hp'];
    $fixedtpm = $_POST['fixedtpm'];
    $fixedparent = $_POST['fixedparent'];
    $da = $_POST['da'];
    $cl = $_POST['cl'];
    $keytype = $_POST['keytype'];
    $pwdpc = $_POST['pwdpc'];
    $pwdph = $_POST['pwdph'];
    $pwdk = $_POST['pwdk'];
    $label= $_POST['label'];
    $msg = $_POST['msg'];
    
    $retval = 0;
    if ($command == 'Create') {
	// parameter checks
	if ($retval == 0) {
	    if (strlen($label) == 0) {
		echo "Label must be specified<br>";
		$retval = 1;
	    }
	    if (strlen($keytype) == 0) {
		echo "Key Type must be specified<br>";
		$retval = 1;
	    }
	    if ($keytype == "bl") {
		if (strlen($msg) == 0) {
		    echo "Message must be specified for sealed data blob<br>";
		    $retval = 1;
		}
	    }
	    if ($keytype != "bl") {
		if (strlen($msg) != 0) {
		    echo "Message must not be specified unless sealed data blob<br>";
		    $retval = 1;
		}
	    }
	    if (strlen($hp) == 0) {
		echo "Parent handle must be specified<br>";
		$retval = 1;
	    }
	}
	if ($retval == 0) {
	    if (isset($cl)) {
	        $commandStr = "/var/www/html/tpm2/createloaded";
	    }
	    else {
	        $commandStr = "/var/www/html/tpm2/create";
	    }
	    // parent handle
	    $commandStr .= " -hp " . $hp;
	    // key attributes
	    if (isset($fixedtpm)) {
		$commandStr .= " -kt f";
	    }
	    if (isset($fixedparent)) {
		$commandStr .= " -kt p";
	    }
	    if (isset($da)) {
		$commandStr .= " -da";
	    }
	    // key type
	    $commandStr .= " -" . $keytype;
	    // parent password
	    if (strlen($pwdpc) != 0) {
		$commandStr .= " -pwdp " . $pwdpc;
	    }
	    // key password
	    if (strlen($pwdk) != 0) {
		$commandStr .= " -pwdk " . $pwdk;
	    }
	    // key label -> output file name
	    $commandStr .= " -opu " . $label . "pub.key";
	    $commandStr .= " -opr " . $label . "priv.key";
	    $commandStr .= " -nalg $halg";
	    $commandStr .= " -halg $halg";
	    // sealed data blob has message to seal and policypcr
 	    if ($keytype == "bl") {
		$commandStr .= " -if message.tmp";
		$commandStr .= " -pol policies/policypcr16aaa" . $halg . ".bin";
	    }
	}
	if ($retval == 0) {
	    if ($keytype == "bl") {
		$rc = file_put_contents ('message.tmp', $msg);
		if (!$rc) {
		    echo "could not write message to message.tmp<br>";
		    $retval = 1;
		}
	    }
	}
	if ($retval == 0) {
	    //echo "Command string: $commandStr. <br>"; $retval = 0;
	    unset($output);
	    exec ($commandStr, $output, $retval);
	    if ($retval == 0) {
		;
	    }
	    else {
		echo "$commandStr <br>";
		for ($i = 0 ; $i < count($output) ; $i++) {
		    echo "$output[$i] <br>";
		}
	    }
	}
	@unlink ('message.tmp');
    }
    elseif ($command == 'Create Primary') {
        $commandStr = "/var/www/html/tpm2/createprimary";
	// hierarchy
        if (strlen($hi) != 0) {
            $commandStr .= " -hi " . $hi;
        }
	// hierarchy password
        if (strlen($pwdph) != 0) {
            $commandStr .= " -pwdp " . $pwdph;
        }
	// key password
        if (strlen($pwdk)!= 0) {
            $commandStr .= " -pwdk " . $pwdk;
        }
        //echo "Command string: $commandStr <br>"; $retval = 0;
        unset($output);
        exec ($commandStr, $output, $retval);
        if ($retval == 0) {
            echo $output[0] . "<br>";
        }
        else {
            echo $commandStr . "<br>";
            for ($i = 0 ; $i < count($output) ; $i++) {
                echo "$output[$i] <br>";
            }
        }
    }
    else {
        echo ("Invalid command $command");
    }
}
?>

<form method="post" action="keycreate.php">

<h3>Common Parameters</h3>
     Key Password <input type="password" name="pwdk" value="<?php echo $pwdk; ?>">(optional)

<h3>Create Primary</h3>
    
<input type="radio" name="hi" value="p"
     <?php if ($hi == "p") echo " checked"; ?>>Platform
<input type="radio" name="hi" value="o"
     <?php if (($hi == "o") || !isset($hi)) echo " checked"; ?>>Owner
<input type="radio" name="hi" value="e"
     <?php if ($hi == "e") echo " checked"; ?>>Endorsement
<input type="radio" name="hi" value="n"
     <?php if ($hi == "n") echo " checked"; ?>>Null
<br>
Hierarchy Password <input type="password" name="pwdph" value="<?php echo $pwdph; ?>">
<br>
<input type="submit" name="command" value="Create Primary">

<h3>Create</h3>

Parent Handle <input type="text" name="hp" value="<?php
     if (strlen($hp) != 0) {
        echo $hp;
     }
     else {
        echo "80000000";
     }
?>"><br> 
Parent Password <input type="password" name="pwdpc" value="<?php echo $pwdpc; ?>">
<br>
Key Label <input type="text" name="label" value="<?php echo $label; ?>">
<br>
Key Attributes
<br>     
<input type="checkbox" name="fixedtpm" value="t"
    <?php if ($fixedtpm == "t") echo "checked"; ?>>Fixed TPM<br>
<input type="checkbox" name="fixedparent" value="t"
    <?php if ($fixedparent== "t") echo "checked"; ?>>Fixed Parent<br>
<input type="checkbox" name="da" value="t"
    <?php if ($da == "t") echo "checked"; ?>>DA Protection<br>
<input type="checkbox" name="cl" value="t"
    <?php if ($cl == "t") echo "checked"; ?>>Create Loaded<br>
Key Type
<br>
<input type="radio" name="keytype" value="st"
     <?php if ($keytype == "st") echo " checked"; ?>>Storage<br>
<input type="radio" name="keytype" value="si"
     <?php if ($keytype == "si") echo " checked"; ?>>Signing<br>
<input type="radio" name="keytype" value="sir"
     <?php if ($keytype == "sir") echo " checked"; ?>>Restricted Signing<br>
<input type="radio" name="keytype" value="kh"
     <?php if ($keytype == "kh") echo " checked"; ?>>Keyed Hash (HMAC)<br>
<input type="radio" name="keytype" value="den"
     <?php if ($keytype == "den") echo " checked"; ?>>RSA Decryption, NULL scheme<br> 
<input type="radio" name="keytype" value="deo"
     <?php if ($keytype == "deo") echo " checked"; ?>>RSA Decryption, OAEP scheme<br>
<input type="radio" name="keytype" value="des"
     <?php if ($keytype == "des") echo " checked"; ?>>AES Encrypt/Decrypt<br>
<input type="radio" name="keytype" value="bl"
     <?php if ($keytype == "bl") echo " checked"; ?>>Data Blob for Unseal

--- Message to Seal <input type="text" name="msg" value="<?php echo $msg; ?>"><br>

<input type="radio" name="keytype" value="gp"
     <?php if ($keytype == "gp") echo " checked"; ?>>RSA General Purpose<br>
<br>
<input type="submit" name="command" value="Create">
</form> 

</div>

<?php
require '/var/www/html/tpm2/footer.html';
?>

</body>
</html>	
