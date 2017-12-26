<!-- $Id: handles.php 1104 2017-12-06 13:58:03Z kgoldman $ -->

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
<title>TSS 2.0 Demo Handles
<?php
echo gethostname();
?>
</title>
<link rel="stylesheet" type="text/css" href="demo.css">
</head>
<body>

<form method="post" action="handles.php">

<div id="header">
<img src="ibm.png" style="float:right;width:200px;height:70px">
<h2>IBM TSS Demo Handles - 
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
    $retval = 0;

    //echo "Post parameters<br>\n";
    //print_r($_POST);
    //echo "<br>\n";

    // construct the flush command
    $handles = array_keys($_POST);
    foreach ($handles as $handle) {
	// echo "Handle: " . $handle . "<br>\n";
	// echo "1 " . hexdec($handle) . "<br>\n";
	// echo "1 " . (hexdec($handle) & 0xff000000) . "<br>\n";
	switch (hexdec($handle) & 0xff000000) { 
	    // NV index
	  case 0x01000000:
	    $commandStr = "/var/www/html/tpm2/nvundefinespace -hi o -ha " . $handle;
	    break;	
	    // loaded sessions, saved sessions, transient objects
	  case 0x02000000:
	  case 0x03000000:
	  case 0x80000000:
	    $commandStr = "/var/www/html/tpm2/flushcontext -ha " . $handle;
	    break;	
	  case 0x81000000:
	    $commandStr = "/var/www/html/tpm2/evictcontrol -hi p -ho " . $handle . " -hp " . $handle;
	    break;	
	  default:
	    echo "Unknown handle type: " . $handle . "<br>\n";
	    continue 2;
	}
	// run the command
	//echo 'Command string: ' . $commandStr. "<br>";
	unset($output);
	exec ($commandStr, $output, $retval);

	if ($retval == 0) {
	    ;
	}
	else {
	    // get the TSS error code
	    $value = $output[0];
	    $values = explode (" ", trim($value));
	    //echo "TPM rc: " . $values[3] . "<br>\n";
	    // do not print the missing file error, because demo may be in different data directory
	    if (strcmp($values[3], "000b0016") != 0) {
		echo 'Error executing ' . $commandStr . '<br>';
		for ($i = 0 ; $i < count($output) ; $i++) {
		    echo $output[$i] . '<br>';
		}
	    }
	}
    }
}
     
echo "<h3>NV Indexes</h3>\n";
unset($output);
exec ('/var/www/html/tpm2/getcapability -cap 1 -pr 01000000', $output, $retval);
sscanf($output[0], '%d', $count);
for ($i = 0 ; $i < $count ; $i++) {
    printf("<input type=\"checkbox\" name=\"%s\">", trim($output[1 + $i]));
    printf("%s<br>\n", trim($output[1 + $i]));
}

echo "<h3>Loaded Sessions</h3>\n";
unset($output);
exec ("/var/www/html/tpm2/getcapability -cap 1 -pr 02000000", $output, $retval);
sscanf($output[0], "%d", $count);
for ($i = 0 ; $i < $count ; $i++) {
    printf("<input type=\"checkbox\" name=\"%s\">", trim($output[1 + $i]));
    printf("%s<br>\n", trim($output[1 + $i]));
}

echo "<h3>Saved Sessions</h3>\n";
unset($output);
exec ("/var/www/html/tpm2/getcapability -cap 1 -pr 03000000", $output, $retval);
sscanf($output[0], "%d", $count);
for ($i = 0 ; $i < $count ; $i++) {
    printf("<input type=\"checkbox\" name=\"%s\">", trim($output[1 + $i]));
    printf("%s<br>\n", trim($output[1 + $i]));
}

echo "<h3>Transient Objects</h3>\n";
unset($output);
exec ("/var/www/html/tpm2/getcapability -cap 1 -pr 80000000", $output, $retval);
sscanf($output[0], "%d", $count);
for ($i = 0 ; $i < $count ; $i++) {
    printf("<input type=\"checkbox\" name=\"%s\">", trim($output[1 + $i]));
    printf("%s<br>\n", trim($output[1 + $i]));
}

echo "<h3>Persistent Objects</h3>\n";
unset($output);
exec ("/var/www/html/tpm2/getcapability -cap 1 -pr 81000000", $output, $retval);
sscanf($output[0], "%d", $count);
for ($i = 0 ; $i < $count ;1 +  $i++) {
    printf("<input type=\"checkbox\" name=\"%s\">", trim($output[1 + $i]));
    printf("%s<br>\n", trim($output[1 + $i]));
}

?>

<br>   
<input type="submit" value="Flush Handles">

</div>

<?php
require '/var/www/html/tpm2/footer.html';
?>

</body>
</html>
