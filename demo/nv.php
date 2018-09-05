<!-- $Id: nv.php 1329 2018-09-05 15:16:18Z kgoldman $ -->

<?php
/* (c) Copyright IBM Corporation 2016, 2018					*/
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
	<title>TSS 2.0 Demo NV Properties
	    <?php
	    echo gethostname();
	    ?>
	</title>
	<link rel="stylesheet" type="text/css" href="demo.css">
    </head>
    <body>

	<div id="header">
	    <img src="ibm.png" style="float:right;width:200px;height:70px">
	    <h2>IBM TSS Demo NV Properties - 
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
	    unset($capoutput);
	    exec ("/var/www/html/tpm2/getcapability -cap 1 -pr 01000000", $capoutput, $retval);
	    sscanf($capoutput[0], "%d", $count);
	    for ($index = 0 ; $index < $count ; $index++) {

		$retval = 0;
		$handle = $capoutput[1 + $index];
		printf("<h3>Handle: %s</h3>", $handle);

		unset($output);
		exec ("/var/www/html/tpm2/nvreadpublic -ha $handle", $output, $retval);
		if ($retval == 0) {
		    //print_r($output);

		    // first line is name algorithm
		    $exp = explode(" ", $output[0]);
		    switch ($exp[3]) {
			case '000b':
			    printf("Name Algorithm: SHA-256\n<br>");
			    break;
			case '000c':
			    printf("Name Algorithm: SHA-384\n<br>");
			    break;
			case '0004':
			    printf("Name Algorithm: SHA-1\n<br>");
			    break;
			default:
			    printf("Name Algorithm: %04x unknown\n<br>", $exp[3]);
		    }
		    // second line is size
		    $exp = explode(" ", $output[1]);
		    printf("Data size: %u\n<br>", $exp[3]);
		    // third line are attributes
		    $exp = explode(" ", $output[2]);
		    $attr = hexdec($exp[2]);
		    printf("Attributes: %08x\n<br>", $attr);
		    switch ($attr & 0x000000f0) {
			case 0x00000000:
			    printf("Type: Ordinary\n");
			    break;
			case 0x00000010:
			    printf("Type: Counter\n");
			    break;
			case 0x00000020:
			    printf("Type: Bits\n");
			    break;
			case 0x00000040:
			    printf("Type: Extend\n");
			    break;
			case 0x00000080:
			    printf("Type: Pin Fail\n");
			    break;
			case 0x00000090:
			    printf("Type: Pin Pass\n");
			    break;
			default:
			    printf("Type: %08x unknown\n", $attr);
		    }
		    echo "<blockquote>\n";
		    if ($attr & 0x00000001) {		// bit 0
			printf("\tPlatform Authorization write<br>\n");
		    }
		    if ($attr & 0x00000002) {
			printf("\tOwner Authorization write<br>\n");
		    }
		    if ($attr & 0x00000004) {
			printf("\tIndex Authorization write<br>\n");
		    }
		    if ($attr & 0x00000008) {
			printf("\tPolicy Authorization write<br>\n");
		    }
		    if ($attr & 0x00000400) {
			printf("\tPolicy Authorization delete<br>\n");
		    }
		    if ($attr & 0x00000800) {
			printf("\tWrite locked<br>\n");
		    }
		    if ($attr & 0x00001000) {		// bit 12
			printf("\tWrite all<br>\n");
		    }
		    if ($attr & 0x00002000) {
			printf("\tWrite lockable (write define)<br>\n");
		    }
		    if ($attr & 0x00004000) {
			printf("\tWrite lockable until ST Clear<br>\n");
		    }
		    if ($attr & 0x00008000) {
			printf("\tGlobal lockable<br>\n");
		    }
		    if ($attr & 0x00010000) {		// bit 16
			printf("\tPlatform Authorization read<br>\n");
		    }
		    if ($attr & 0x00020000) {
			printf("\tOwner Authorization read<br>\n");
		    }
		    if ($attr & 0x00040000) {
			printf("\tIndex Authorization read<br>\n");
		    }
		    if ($attr & 0x00080000) {
			printf("\tPolicy Authorization read<br>\n");
		    }
		    if ($attr & 0x02000000) {		// bit 25
			printf("\tNo DA protection<br>\n");
		    }
		    if ($attr & 0x04000000) {
			printf("\tOrderly (hybrid) index<br>\n");
		    }
		    if ($attr & 0x08000000) {
			printf("\tWritten cleared on ST Clear<br>\n");
		    }
		    if ($attr & 0x10000000) {		// bit 28
			printf("\tRead locked<br>\n");
		    }
		    if ($attr & 0x20000000) {
			printf("\tWritten<br>\n");
		    }
		    if ($attr & 0x40000000) {
			printf("\tPlatform created<br>\n");
		    }
		    if ($attr & 0x80000000) {
			printf("\tRead lockable until ST Clear<br>\n");
		    }
		    echo "\n</blockquote>\n";

		    // search for policy
		    for ($i = 0 ; $i < count($output) ; $i++) {
			$found = strpos($output[$i], "policy");
			if ($found) {
			    $exp = explode(" ", $output[$i]);
			    echo "Policy length: " . $exp[4] . "\n<br>\n";
			    if ($exp[4] != 0) {
				echo "Policy:\n<br>";
				echo "\n<kbd>\n";
				echo "\t" . $output[$i + 1] . "\n<br>\n";
				echo "\t" . $output[$i + 2] . "\n<br>\n";
				if ($exp[4] > 32) {
				    echo "\t" . $output[$i + 3] . "\n<br>\n";
				}
				echo "</kbd>\n";
			    }
			}
		    }
		}
		else {
		    echo $commandStr . "<br>\n";
		    for ($i = 0 ; $i < count($output) ; $i++) {
			echo $output[$i] . "<br>\n";
		    }
		}
	    }
	    ?>

	</div>

	<?php
	require '/var/www/html/tpm2/footer.html';
	?>

    </body>
</html>
