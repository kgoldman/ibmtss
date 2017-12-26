<!-- $Id: pcr.php 1104 2017-12-06 13:58:03Z kgoldman $ -->

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
<title>TSS 2.0 Demo PCRs
<?php
echo gethostname();
?>
</title>
<link rel="stylesheet" type="text/css" href="demo.css">
</head>
<body>

<div id="header">
<img src="ibm.png" style="float:right;width:200px;height:70px">
<h2>IBM TSS Demo PCRs - 
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
 
    $command = $_POST['command'];
    $ha = $_POST['ha'];
    $ic = $_POST['ic'];

    $retval = 0;
    // parameter checks
    if ($retval == 0) {
	if (strlen($ha) == 0) {
	    echo "PCR Index must be specified<br>";
	    $retval = 1;
	}
	if ($command == 'PCR Extend') {
	    if (strlen($ic) == 0) {
		echo "PCR Extend data must be specified<br>";
		$retval = 1;
	    }
	}
    }
    // construct the command
    if ($retval == 0) {
	switch ($command) {
	  case 'PCR Extend':
	    $commandStr = "/var/www/html/tpm2/pcrextend -halg $halg";
	    $commandStr .= " -ha " . $ha;
	    $commandStr .= " -ic " . $ic;
	    break;
	  case 'PCR Reset':
	    $commandStr = "/var/www/html/tpm2/pcrreset";
	    $commandStr .= " -ha " . $ha;
	    break;
	  default:
	    echo ("Invalid command $command");
	    $retval = 1;
	    break;
	}
    }
    // run the command
    if ($retval == 0) {
	//echo 'Command string: ' . $commandStr. "<br>"; $retval = 0;
	unset($output);
	exec ($commandStr, $output, $retval);
	if ($retval == 0) {
	    ;
	}
	else {
	    echo "<br>" . $commandStr . "<br>";
	    for ($i = 0 ; $i < count($output) ; $i++) {
		echo $output[$i] . "<br>";
	    }
	}
    }
}
     
echo "<h3>PCRs</h3>";
echo "<kbd>\n";

for ($i = '0' ; $i < '24' ; $i++) {
    
    $commandStr = "/var/www/html/tpm2/pcrread -ha $i -halg $halg";
    //echo 'Command string: ' . $commandStr. "<br>";
    unset($output);
    exec ($commandStr, $output, $retval);
    printf("PCR %02d: ", $i);
    if ($retval == 0) {
	echo $output[2] . $output[3] . "<br>\n";
    }
    else {
	printf("pcrread returned: $retval<br>\n");
    }
} 

echo "</kbd>";

?>

<form method="post" action="pcr.php">

<h3>PCR Extend and Reset</h3>

PCR Index <input type="text" name="ha" value="<?php
     if (strlen($ha) != 0) {
        echo $ha;
     }
     else {
        echo "16";
     }
?>">
<br>

PCR Extend Data <input type="text" name="ic" value="<?php
     if (strlen($ic) != 0) {
        echo $ic;
     }
     else {
        echo "aaa";
     }
?>">
<br>

<input type="submit" name="command" value="PCR Extend">
<br>
<input type="submit" name="command" value="PCR Reset">
<br>

</div>

<?php
require '/var/www/html/tpm2/footer.html';
?>

</body>
</html>
