<!-- $Id: unseal.php 1104 2017-12-06 13:58:03Z kgoldman $ -->

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
<title>TSS 2.0 Demo Unseal
<?php
echo gethostname();
?>
</title>
<link rel="stylesheet" type="text/css" href="demo.css">
</head>
<body>
			
<div id="header">
<img src="ibm.png" style="float:right;width:200px;height:70px">
<h2>IBM TSS Demo Unseal - 
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
    echo "<br>";

    $command = $_POST['command'];       // not used
    $hp = $_POST['hp'];
    $pwdp = $_POST['pwdp'];
    $label = $_POST['label'];

    $retval = 0;
    // parameter checks
    if ($retval == 0) {
	if (strlen($hp) == 0) {
	    echo "Parent handle must be specified<br>";
	    $retval = 1;
	}
	if (strlen($label) == 0) {
 	    echo "Sealed data label must be specified<br>";
	    $retval = 1;
	}
    }
    // load the sealed data blob
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
        $blobhandle = $values[1];
        echo "Loaded handle: " . $blobhandle . "<br>";
    }
    // start policy session
    if ($retval == 0) {
        $commandStr = "/var/www/html/tpm2/startauthsession -se p -halg $halg";
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
    if ($retval == 0) {
        //print_r($output);
        $values = explode (" ", $output[0]);
        $sessionhandle = $values[1];
        echo "Policy Session handle: " . $sessionhandle . "<br>";
    }
    // policypcr, select PCR 16
    if ($retval == 0) {
        $commandStr = "/var/www/html/tpm2/policypcr -halg $halg -bm 10000";
        $commandStr .= " -ha " . $sessionhandle;
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
    // unseal to message file
    if ($retval == 0) {
        $commandStr = "/var/www/html/tpm2/unseal";
        $commandStr .= " -ha " . $blobhandle;
        $commandStr .= " -of message.tmp";
        $commandStr .= " -se0 " . $sessionhandle . " 1";
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
    // display the message
    if ($retval == 0) {
        $message = file_get_contents('message.tmp'); 
        echo "Unsealed message: " . $message . "<br>";
    }
    // flush session
    if (strlen($sessionhandle) != 0) {
        $commandStr = "/var/www/html/tpm2/flushcontext";
        $commandStr .= " -ha " . $sessionhandle;
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
    // flush sealed data blob 
    if (strlen($blobhandle) != 0) {
        $commandStr = "/var/www/html/tpm2/flushcontext";
        $commandStr .= " -ha " . $blobhandle;
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
    unlink ('message.tmp');
}
?>

<form method="post" action="unseal.php">

<h2>Unseal</h2>

<p>
     (For the IBM TSS demo, the Unseal policy is hard coded to PCR 16 with a SHA-256 value c2 11 97 64 ... or SHA-1 value 1d 47 f6 8a ... .  Set this value by extending PCR 16 with PCR Extend Data aaa.)
</p>

Parent Handle <input type="text" name="hp" value="<?php
     if (strlen($hp) != 0) {
        echo $hp;
     }
     else {
        echo "80000000";
     }
?>">
<br>
Parent Password <input type="password" name="pwdp" value="<?php echo $pwdp; ?>">
<br>
Sealed Data Label <input type="text" name="label" value="<?php echo $label; ?>">
<br>
<input type="submit" name="command" value="Unseal">

</div>

<?php
require '/var/www/html/tpm2/footer.html';
?>

</body>
</html>

