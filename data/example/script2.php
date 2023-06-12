<?php
function encrypt3n($data, $offset, $length, $des_key1, $des_key2, $des_key3, $xor_seed)
{
	$key = $xor_seed;

	for($i=0; $i<$length; $i=$i+8)
	{
		$dat = substr($data, $offset+$i, 8);
		
		for($t=0; $t<8; $t++)
		{
			$dat[$t] = $dat[$t] ^ $key[$t];
		}

		$enc = substr(base64_decode(openssl_encrypt($dat, "des-ecb", $des_key1)), 0, 8);
		$enc = openssl_decrypt($enc, "des-ecb", $des_key2, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING);
		$enc = substr(base64_decode(openssl_encrypt($enc, "des-ecb", $des_key3)), 0, 8);

		for($t=0; $t<8; $t++) {
			$data[$offset+$i+$t] = $enc[$t];
		}
		
		$key = $enc;
	}

	return($data);
}

function decrypt3n($data, $offset, $length, $des_key1, $des_key2, $des_key3, $xor_seed)
{
	$key = $xor_seed;

	for($i=0; $i<$length; $i=$i+8)
	{
		$dat = substr($data, $offset+$i, 8);

		$dec = openssl_decrypt($dat, "des-ecb", $des_key3, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING);
		$dec = substr(base64_decode(openssl_encrypt($dec, "des-ecb", $des_key2)), 0, 8);
		$dec = openssl_decrypt($dec, "des-ecb", $des_key1, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING);

		for($t=0; $t<8; $t++)
		{
			$data[$offset+$i+$t] = $dec[$t] ^ $key[$t];
		}
		
		$key = $dat;
	}
	
	return($data);
}

function encrypt1n($data, $offset, $length, $des_key, $xor_seed)
{
	$key = $xor_seed;

	for($i=0; $i<$length; $i=$i+8)
	{
		$dat = substr($data, $offset+$i, 8);
		
		for($t=0; $t<8; $t++)
		{
			$dat[$t] = $dat[$t] ^ $key[$t];
		}

		$enc = substr(base64_decode(openssl_encrypt($dat, "des-ecb", $des_key)), 0, 8);

		for($t=0; $t<8; $t++)
		{
			$data[$offset+$i+$t] = $enc[$t];
		}
		
		$key = $enc;
	}

	return($data);
}

function decrypt1n($data, $offset, $length, $des_key, $xor_seed)
{
	$key = $xor_seed;

	for($i=0; $i<$length; $i=$i+8)
	{
		$dat = substr($data, $offset+$i, 8);
		$dec = openssl_decrypt($dat, "des-ecb", $des_key, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING);

		for($t=0; $t<8; $t++)
		{
			$data[$offset+$i+$t] = $dec[$t] ^ $key[$t];
		}
		
		$key = $dat;
	}

	return($data);
}

function encrypt2n($data, $offset, $length, $des_key)
{
	for($i=0; $i<$length; $i=$i+8)
	{
		$dat = substr($data, $offset+$i, 8);
		$enc = substr(base64_decode(openssl_encrypt($dat, "des-ecb", $des_key)), 0, 8);

		for($t=0; $t<8; $t++)
		{
			$data[$offset+$i+$t] = $enc[$t];
		}
	}

	return($data);
}

function decrypt2n($data, $offset, $length, $des_key)
{
	for($i=0; $i<$length; $i=$i+8)
	{
		$dat = substr($data, $offset+$i, 8);
		$dec = openssl_decrypt($dat, "des-ecb", $des_key, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING);

		for($t=0; $t<8; $t++)
		{
			$data[$offset+$i+$t] = $dec[$t];
		}
	}

	return($data);
}

// variables bring their own keyset
function decrypt_var($src, $offset, $length)
{
	$vari = substr($src, $offset, $length);
	$des_key1 = substr($vari,    0, 8);
	$des_key2 = substr($vari, 0x10, 8);
	$des_key3 = substr($vari,    0, 8);
	$xor_key  = substr($vari,    8, 8);
	
	$packet   = decrypt3n($src, $offset + 0x18, $length - 0x18, $des_key1, $des_key2, $des_key3, $xor_key);
	
	return($packet);
}


function swap($a)
{
	echo strlen($a)." length\n";
	$b = "0X";
	
	for($t=0; $t<strlen($a); $t=$t+2)
	{
		$b .= substr($a, strlen($a)-$t, 2);
	}
	
	return ($b);
}

$packet = hex2bin("0108000000000000000000000000000000000000000000000000000000000000000000000000010c00020005df010b5d37f88ceff8ca6d529124c11bce87ac7580112f08ee2348479af8b12462712444d285f7871a2d6afd38b0f3c1db52ac3c6b5705af5530699fc5f5f34eb1b1af7ee01612149e1c28168285d2bf34a6cda5bd1253396575f14e26b58eec07aee7f9efec3d5d2c36b32231650cf5de6b3561eb435af56c592e8ed6d7bfaa30fa062f32d041ebfd735c0fd599d71b6cebdd7e64320aaea03dacd7ca78f5623adc183326ec0a5331fad8e70b2bf68496c726628a114b128f22ee6a7392667eb8917c4903fdf1e7512ca8cb1ebadab802c0845d32d7151552ace25d242265af5b74b43ac70dfae8bb81d6f959ee916fbfc461eea8df136fe1f231eab20fdf38c99ed5804563bfcd");
$packet = hex2bin("0118000000000000000000000000000000000000000000000000000000000000000000000000010C00020005C68FC365F49D1F6908FEA93F06524ED13AF679C89C9A9750869CF6FA640258F84E413666B53C0626A341C2D26B975CD10BE185D138C228B50AA912BF2C4AEE7824FA1A6A89341B1D7EEE362F32DD386B8FD1CC19B0593ABAA58D62115C230AF5294DA0025EA8B0D7A80DDDE7ACB308DB515B0E5F9AC8512CC6755816563950759F3E7F60E30973CFE63FC47E9F5D11119DE4DCB87CBCDE109178D88BC154F40DA02E12267CC5368E71519CB8602135100096C19C859EBA518A62141EA58F567C4AD007EC1A7AEC40DA127665D60757973C67443AB699D4F878237A03962E833C05CF347DE3058149CAC8AEDA36ED4AB025DB2D5DAEFCF3D985C2D7F7F52F9AD0FD4568887E02475B");

// step 0 - create the checksums and keys for the answer packet
$chksum1 = sha1(substr($packet, 0x34, 0x100));
$chksum2 = sha1(substr($packet, 0x48,  0xec));
$fullkey = substr($chksum2, 0, 0x14*2) . substr($chksum1, 0, 0x0c*2);
$des_key1 = pack("H*", substr($fullkey,    0, 0x10));
$des_key2 = pack("H*", substr($fullkey, 0x10, 0x10));
$des_key3 = pack("H*", substr($fullkey, 0x20, 0x10));
$xor_seed = pack("H*", substr($fullkey, 0x30, 0x10));  
echo "Keyset for the answer packet:\n";
echo "des_key1: ".bin2hex($des_key1)."\n";
echo "des_key2: ".bin2hex($des_key2)."\n";
echo "des_key3: ".bin2hex($des_key3)."\n";
echo "xor_seed: ".bin2hex($xor_seed)."\n\n";

// step 1 - decryption of the real keys
$packet = decrypt1n($packet, 284, 24, pack("H*", "95b40e8757ca7fe8"), pack("H*", "524f145b3ac48774"));
$packet = decrypt1n($packet, 284, 16, pack("H*", "3f88f6745655525f"), pack("H*", "54af62f9a22b5d11"));

// step 2 - decryption of the payload
$des_key = substr($packet, 284, 8);
$xor_key = substr($packet, 292, 8);
$packet  = decrypt1n($packet, 52, 232, $des_key, $xor_key);

echo "des_key = " . bin2hex($des_key) . "\n";
echo "xor_key = " . bin2hex($xor_key) . "\n";

// step 3 - decryption of variables
// The packet structure is like this:
// header of 0x28 bytes
// 00020005 indicator for the data
// C68FC365F49D1F69 fixed (always? or game specific???)
// 000	028	value_0_28  1a00130711ddd3c80000000000000000
// 028	038	value_28_38 ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
// 060	028	value_60_28	SLPM65692
// 088	020	value_88_20 0100028888

// 1. decrypt the variables with the static keyset for variables
$des_key1 = pack("H*", "6CD3DE203EF186EA");
$des_key2 = pack("H*", "1DE0914A68110166");
$des_key3 = pack("H*", "23F1122148F25391");
$xor_key  = pack("H*", "3AB493F694975297");

$packet   = decrypt3n($packet, 60, 32, $des_key1, $des_key2, $des_key3, $xor_key);
$packet   = decrypt3n($packet, 100, 48, $des_key1, $des_key2, $des_key3, $xor_key);
$packet   = decrypt3n($packet, 156, 32, $des_key1, $des_key2, $des_key3, $xor_key);
$packet   = decrypt3n($packet, 196, 32, $des_key1, $des_key2, $des_key3, $xor_key);

// 2. decrypt the array with its own keyset
$packet = decrypt_var($packet, 52, 40);
$packet = decrypt_var($packet, 92, 56);
$packet = decrypt_var($packet, 148, 40);
$packet = decrypt_var($packet, 188, 40);

// 3. decrypt the variables with a specific keyset for each
$packet = decrypt3n($packet, 60, 32, pack("H*", "25004DDF203AD806"), pack("H*", "DF9953C6588DE905"), pack("H*", "FB2DFBAFB45D9FCB"), pack("H*", "89E5EA01C2D17428"));
$packet = decrypt3n($packet, 100, 48, pack("H*", "B273057e4B27C318"), pack("H*", "8A9B3F8B8AA6B611"), pack("H*", "F9D2D7E28A2D9378"), pack("H*", "59C56A5B1530CC2B"));
$packet = decrypt3n($packet, 156, 32, pack("H*", "E77F0A21DA2AFDE5"), pack("H*", "B6271F345B47C82F"), pack("H*", "00352FD037940FA9"), pack("H*", "25707753C5F68A7C"));
$packet = decrypt3n($packet, 196, 32, pack("H*", "BD1CD35300AA5EDC"), pack("H*", "7FEB6F068D4DC543"), pack("H*", "555CA8631907C78C"), pack("H*", "3D80DED8DA8142FD"));

// and print it ...
echo "Variables from the query packet:\n";
echo "variable 1: ".bin2hex(substr($packet, 68, 16))."\n";
echo "variable 2: ".bin2hex(substr($packet, 108, 32))."\n";
echo "variable 3: ".bin2hex(substr($packet, 164, 16))."(".substr($packet, 164, 16).")\n";
echo "variable 4: ".bin2hex(substr($packet, 204, 8))."\n";


?>

