<?php
// https://onlinephp.io/mcrypt-encrypt/manual

function encrypt3($data, $offset, $length, $des_key1, $des_key2, $des_key3, $xor_seed)
{
	$key = $xor_seed;

	for($i=0; $i<$length; $i=$i+8) {
		$dat = substr($data, $offset+$i, 8);
		
		for($t=0; $t<8; $t++) 
		{
			$dat[$t] = $dat[$t] ^ $key[$t];
		}

		$enc = mcrypt_encrypt(MCRYPT_DES, $des_key1, $dat, MCRYPT_MODE_ECB);
		$enc = mcrypt_decrypt(MCRYPT_DES, $des_key2, $enc, MCRYPT_MODE_ECB);
		$enc = mcrypt_encrypt(MCRYPT_DES, $des_key3, $enc, MCRYPT_MODE_ECB);

		for($t=0; $t<8; $t++)
		{
			$data[$offset+$i+$t] = $enc[$t];
		}
		
		$key = $enc;
	}

	return($data);
}

// get the body of the initial packet
$packet = hex2bin("0118000000000000000000000000000000000000000000000000000000000000000000000000010c00020005ca0810767e461a4910a05ddd78cc6c0708b9bfd96e525f61c0d2103b3573eab830aa2e55969962c08e3f6d3ffbb737d6f91e29a582e1b3864f9122b588e58a6716d152cf5eeaa953c4527b1f290b126f2da7e51856ea681493379c764074055c77d69aa2d48e5454c2ea435df8a9d6f0725eeba6fdd0bc38f16de65639291da30cd841489cda49fb50dc5995fd32487e1622b540a9ab752368a9e646cb8201480d9658a92350b3adf34543ca32416ac12c5cae15464cc8b38fb8e7ee8c8d88d3cebe25fbef772c1fbed9da5a5a1d5422dafdb2bd2b0785eca76f373c5f3b5d513ff56ca46dda63918d38496876babfa77e554e745a13c0bbe63b63ae246f5417b966f1cdc9123495");

$gameID  = substr($packet, 0x2c, 8);
$qrytype = substr($packet, 0, 4);
$fname   = bin2hex($gameID)."_".bin2hex($qrytype);

// step 0 - create the checksums and keys for the answer packet
$chksum1  = sha1(substr($packet, 0x34, 0x100));
$chksum2  = sha1(substr($packet, 0x48,  0xec));
$fullkey  = substr($chksum2, 0, 0x14*2) . substr($chksum1, 0, 0x0c*2);
$des_key1 = pack("H*", substr($fullkey,    0, 0x10));
$des_key2 = pack("H*", substr($fullkey, 0x10, 0x10));
$des_key3 = pack("H*", substr($fullkey, 0x20, 0x10));
$xor_seed = pack("H*", substr($fullkey, 0x30, 0x10));

// filename package
$packet = hex2bin("01180005010e5c55173816120907e0000033a80000001e000000008cb38e6d076d275ddf00000120d0dc9919f11e42859ae1aa193c0835847dc7573ad3e27a541d750bf6fc5212323a6cdea97e338a6d0493e330db597c914710ec1756bda55287793d990b790346af0f045e471f4f9bddd83372294b42ce065c6e5221dec7a05456aceddf7e4adeb34d0bab5c9e55e8fc1736d6d261baa5b1d5d24a094506318181dbda57e6ccbe8e1a8e013cde2e539d08fb781427b4e9fbd9f1106b75e9c0bf6df9d77f444d55e080764ef5c10c9736d6e3e94c23022f4f09e0b7c614c2409a79a35cd7c4b7b7847af5f3e30414cc813ff67431c1c2cad3a7cf3434b0652f5badb94555d233da4c29cd2f2ee2fcaf21f22353b4e61d888decbdc29d22f1f8d0ab3e267d7100c99bcef9c9b0f578d2e89c259c824225102ee2d2cb04c3c4d56e02fceb74fcb510");

// step 2 - encrypt with keyset from query packet
$packet2 = encrypt3($packet, 0xc8, 0x20, $des_key1, $des_key2, $des_key3, $xor_seed);

// step 3 - encrypt with envelope keyset
$packet3 = encrypt3($packet2, 0x28, 0x120, pack("H*", "eb711416cb0ab016"), pack("H*", "ae190174b5ce6339"), pack("H*", "7b01b91880145e34"), pack("H*", "c510a6400a9b022f"));

echo "fname = " . $fname . "\n";
echo "chksum1 = " . $chksum1 . "\n";
echo "chksum2 = " . $chksum2 . "\n";
echo "fullkey = " . $fullkey . "\n";
echo "des_key1 = " . bin2hex($des_key1) . "\n";
echo "des_key2 = " . bin2hex($des_key2) . "\n";
echo "des_key3 = " . bin2hex($des_key3) . "\n";
echo "xor_seed = " . bin2hex($xor_seed) . "\n";
echo "packet2 = " . bin2hex($packet2) . "\n";
echo "packet3 = " . bin2hex($packet3) . "\n";
echo "packet3 length = " . strlen($packet3) . "\n";

/*
Results:
fname = ca0810767e461a49_01180000
chksum1 = 8bcbc96f59e6ee023ebdcf1307e3f741f4f08680
chksum2 = cff9286b4eab05025057b94b3d7cdd50676b80e4
fullkey = cff9286b4eab05025057b94b3d7cdd50676b80e48bcbc96f59e6ee023ebdcf13
des_key1 = cff9286b4eab0502
des_key2 = 5057b94b3d7cdd50
des_key3 = 676b80e48bcbc96f
xor_seed = 59e6ee023ebdcf13
packet = 01180005010e5c55173816120907e0000033a80000001e000000008cb38e6d076d275ddf000001201f2b6a2a372fe2a3947a234ffc1e0ea0100a171f5c2da5afcf88790c8fb86f2616a011515cb50f75edd982763914d627a328c2820c09e8a0f6266704a674116efa9649a5896dd31f3114b94518f077a1e12ab1695e0cfd457f9accb928df76a69d8e56add877d9a6d42ecff3fa0e011d3972c4e42fd783713bab95112a6d064e66f2a70201312b738b2dae630448eae6834a0a0597e190f7b2bc216ae20bbec018e135f6e32566d371e36f865a934ba5f06b202cffe500e2ed342e5416c9f9310758c8a7c384554bd76384219f56790d1a1b4c875011624c001dd1cf6cbd405d19fc1c35145ffd432b4b908aa6eaf1114d43760b42757d589565a876119d5f807bdda83ee39c86288dc1d29516382253ccd19bfbdfc8c443882d9243fdcd33ba
*/
?>
