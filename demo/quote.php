<!-- $Id: quote.php 1104 2017-12-06 13:58:03Z kgoldman $ -->

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
<title>TSS 2.0 Demo Quote
<?php
echo gethostname();
?>
</title>
<link rel="stylesheet" type="text/css" href="demo.css">
</head>
			
<div id="header">
<img src="ibm.png" style="float:right;width:200px;height:70px">
<h2>IBM TSS Demo Quote- 
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
    echo "<br>\n";

    $command = $_POST['command'];
    $hp = $_POST['hp'];
    $hpcr = $_POST['hpcr'];
    $label= $_POST['label'];
    $quotename = $_POST['quotename'];
    $pwdk = $_POST['pwdk'];

    $retval = 0;
    // parameter checks
    if ($retval == 0) {
	if (strlen($hp) == 0) {
	    echo "Parent handle must be specified<br>\n";
	    $retval = 1;
	}
	if (strlen($label) == 0) {
	    echo "Label must be specified<br>\n";
	    $retval = 1;
	}
	if (strlen($quotename) == 0) {
	    echo "Quote name must be specified<br>\n";
	    $retval = 1;
	}
 	if (strlen($hpcr) == 0) {
	    echo "PCR must be specified<br>\n";
	    $retval = 1;
	}
	else {
	    if (($hpcr < 0) || ($hpcr > 23)) {
		echo "PCR must be between 0 and 23<br>\n";
		$retval = 1;
	    }
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
        //echo 'Command string: ' . $commandStr. "<br>\n";
        unset($output);
        exec ($commandStr, $output, $retval);
        if ($retval != 0) {
            echo $commandStr . "<br>\n";
            for ($i = 0 ; $i < count($output) ; $i++) {
                echo $output[$i] . "<br>\n";
            }
        }
    }
    // get the handle from the response
    if ($retval == 0) {
        //print_r($output);
        $values = explode (" ", $output[0]);
        $hk = $values[1];
        echo "Loaded quote signing key handle: " . $hk . "<br>\n";
    }
    // construct the quote or verify command using the signing key
    if ($retval == 0) {
	switch ($command) {
	  case 'Quote':
	    $commandStr = "/var/www/html/tpm2/quote";
	    $commandStr .= " -hk " . $hk;
	    $commandStr .= " -halg " . $halg;
	    $commandStr .= " -hp " . $hpcr;
	    $commandStr .= " -os " . $quotename . ".sig";
	    $commandStr .= " -oa " . $quotename . ".att";
	    if (strlen($pwdk) != 0) {
	        $commandStr .= " -pwdk " . $pwdk;
	    }
	    break;
	  case 'Verify Quote':
	    $commandStr = "/var/www/html/tpm2/verifysignature";
	    $commandStr .= " -hk " . $hk;
	    $commandStr .= " -halg " . $halg;
	    $commandStr .= " -is " . $quotename . ".sig";
	    $commandStr .= " -if " . $quotename . ".att";
	    break;
	  default:
	    echo ("Invalid command $command <br>\n");
	    $retval = 1;
	    break;
	}
    }
    // run the quote or verify command
    if ($retval == 0) {
	//echo 'Command string: ' . $commandStr. "<br>\n";
	unset($output);
	exec ($commandStr, $output, $retval);
	if ($retval == 0) {
	    if ($command == 'Quote') {
		// after a successful quote, display the PCR value quoted */
		$commandStr = "/var/www/html/tpm2/pcrread -ha $hpcr -halg $halg";
		//echo 'Command string: ' . $commandStr. "<br>";
		unset($output);
		exec ($commandStr, $output, $retval);
		printf("Quoted PCR %02d: ", $hpcr);
		if ($retval == 0) {
		    echo $output[2] . $output[3] . '<br>';
		}
		else {
		    printf("pcrread returned: $retval<br>");
		}
	    }
	    else if ($command == 'Verify Quote') {
		echo "Success<br>\n";
	    }
	}
	else {
	    echo $commandStr . "<br>\n";
	    for ($i = 0 ; $i < count($output) ; $i++) {
		echo $output[$i] . "<br>\n";
	    }
	}
    }
    // flush  
    if (strlen($hk) != 0) {
        $commandStr = "/var/www/html/tpm2/flushcontext";
        $commandStr .= " -ha " . $hk;
        //echo 'Command string: ' . $commandStr. "<br>\n";
        unset($output);
        exec ($commandStr, $output, $retval);
        if ($retval != 0) {
            echo $commandStr . "<br>\n";
            for ($i = 0 ; $i < count($output) ; $i++) {
                echo $output[$i] . "<br>\n";
            }
        }
    }
}
?>

<form method="post" action="quote.php">

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
Quote Name <input type="text" name="quotename" value="<?php echo $quotename; ?>">
<br>
     
<h3>Quote</h3>

Key Password <input type="password" name="pwdk" value="<?php echo $pwdk; ?>">
<br>
PCR <input type="text" name="hpcr" value="<?php echo $hpcr; ?>">
<br>
<input type="submit" name="command" value="Quote">

<h3>Verify</h3>
<input type="submit" name="command" value="Verify Quote">

</div>

<?php
require '/var/www/html/tpm2/footer.html';
?>

</body>
</html>

