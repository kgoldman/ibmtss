<!-- $Id: sign.php 1104 2017-12-06 13:58:03Z kgoldman $ -->

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
<title>TSS 2.0 Demo Sign
<?php
echo gethostname();
?>
</title>
<link rel="stylesheet" type="text/css" href="demo.css">
</head>
			
<div id="header">
<img src="ibm.png" style="float:right;width:200px;height:70px">
<h2>IBM TSS Demo RSA Sign and Verify - 
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
    //print_r($_POST);
    echo "<br>";

    $command = $_POST['command'];
    $hp = $_POST['hp'];
    $label= $_POST['label'];
    $sigfile= $_POST['sigfile'];
    $msg = $_POST['msg'];
    $pwdk = $_POST['pwdk'];

    $retval = 0;
    // parameter checks
    if ($retval == 0) {
	if (strlen($hp) == 0) {
	    echo "Parent handle must be specified<br>";
	    $retval = 1;
	}
	if (strlen($label) == 0) {
	    echo "Label must be specified<br>";
	    $retval = 1;
	}
	if (strlen($sigfile) == 0) {
	    echo "Signature name must be specified<br>";
	    $retval = 1;
	}
 	if (strlen($msg) == 0) {
	    echo "Message must be specified<br>";
	    $retval = 1;
	}
    }
    if ($retval == 0) {
	$rc = file_put_contents ('message.tmp', $msg);
	if (!$rc) {
	    echo "could not write message to message.tmp<br>";
	    $retval = 1;
	}
    }
    // load the key
    if ($retval == 0) {
        $commandStr = "/var/www/html/tpm2/load";
        $commandStr .= " -hp " . $hp;
        $commandStr .= " -ipu " . $label . "pub.key";
        $commandStr .= " -ipr " . $label . "priv.key";
        if (strlen($pwdp) != 0) {
            $commandStr .= " -pwdp " . $pwdp;
        }
        //echo 'Command string: ' . $commandStr. "<br>";
        unset($output);
        exec ($commandStr, $output, $retval);
        if ($retval != 0) {
            echo $commandStr . "<br>";
            for ($i = 0 ; $i < count($output) ; $i++) {
                echo $output[$i] . "<br>";
            }
        }
    }
    // get the handle from the response
    if ($retval == 0) {
        //print_r($output);
        $values = explode (" ", $output[0]);
        $hk = $values[1];
        echo "Loaded signing key handle: " . $hk . "<br>";
    }
    // construct the sign or verify command using the signing key
    if ($retval == 0) {
	switch ($command) {
	  case 'Sign':
	    $commandStr = "/var/www/html/tpm2/sign";
	    $commandStr .= " -hk " . $hk;
	    $commandStr .= " -os " . $sigfile . ".sig";
	    $commandStr .= " -if message.tmp";
	    if (strlen($pwdk) != 0) {
	        $commandStr .= " -pwdk " . $pwdk;
	    }
	    break;
	  case 'Verify Signature':
	    $commandStr = "/var/www/html/tpm2/verifysignature";
	    $commandStr .= " -hk " . $hk;
	    $commandStr .= " -is " . $sigfile . ".sig";
	    $commandStr .= " -if message.tmp";
	    break;
	  default:
	    echo ("Invalid command $command");
	    $retval = 1;
	    break;
	}
    }
    // run the sign or verify command
    if ($retval == 0) {
	//echo 'Command string: ' . $commandStr. "<br>";
	unset($output);
	exec ($commandStr, $output, $retval);
	if ($retval == 0) {
	    if ($command == 'Sign') {
		;
	    }
	    else if ($command == 'Verify Signature') {
		;
	    }
	    echo "Success";
	}
	else {
	    echo $commandStr . "<br>";
	    for ($i = 0 ; $i < count($output) ; $i++) {
		echo $output[$i] . "<br>";
	    }
	}
    }
    unlink ('message.tmp');
    // flush  
    if (strlen($hk) != 0) {
        $commandStr = "/var/www/html/tpm2/flushcontext";
        $commandStr .= " -ha " . $hk;
        //echo 'Command string: ' . $commandStr. "<br>";
        unset($output);
        exec ($commandStr, $output, $retval);
        if ($retval != 0) {
            echo $commandStr . "<br>";
            for ($i = 0 ; $i < count($output) ; $i++) {
                echo $output[$i] . "<br>";
            }
        }
    }
}
?>

<form method="post" action="sign.php">

<h3>Parameters</h3>
     
Parent Handle <input type="text" name="hp" value="<?php
if (strlen($hp) != 0) {
echo $hp;
}
 else {
echo "80000000";
 }
?>"><br>
Key Label <input type="text" name="label" value="<?php echo $label; ?>">
<br>
Message <input type="text" name="msg" value="<?php echo $msg; ?>">
<br>
Signature Name <input type="text" name="sigfile" value="<?php echo $sigfile; ?>">
<br>
     
<h3>Sign</h3>

Key Password <input type="password" name="pwdk" value="<?php echo $pwdk; ?>">
<br>
<input type="submit" name="command" value="Sign">

<h3>Verify</h3>
<input type="submit" name="command" value="Verify Signature">

</div>

<?php
require '/var/www/html/tpm2/footer.html';
?>

</body>
</html>

