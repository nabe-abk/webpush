use strict;
#------------------------------------------------------------------------------
# デフォルトmain
#							(C)2017-2018 nabe@abk
#------------------------------------------------------------------------------
package SatsukiApp::push;
use Crypt::PK::ECC;
use Crypt::AuthEnc::GCM;
use Crypt::Mac::HMAC;
use Crypt::Digest::SHA256;
#------------------------------------------------------------------------------
our $VERSION = '1.10';
my $ECC_NAME  = 'prime256v1';
my $AES128GCM = 1;
my $VAPID     = 0;
###############################################################################
# ■基本処理
###############################################################################
#------------------------------------------------------------------------------
# ●【コンストラクタ】
#------------------------------------------------------------------------------
sub new {
	my ($class, $ROBJ, $self) = @_;
	if (ref($self) ne 'HASH') { $self={}; }
	bless($self, $class);	# $self をこのクラスと関連付ける
	$self->{ROBJ} = $ROBJ;
	return $self;
}
###############################################################################
# ■メイン処理
###############################################################################
sub main {
	my $self = shift;
	my $ROBJ = $self->{ROBJ};

	#-------------------------------------------------------------
	# データファイル読み出し
	#-------------------------------------------------------------
	$self->initalize();

	#-------------------------------------------------------------
	# 初期処理
	#-------------------------------------------------------------
	# $ROBJ->make_csrf_check_key();
	$ROBJ->read_form();

	#-------------------------------------------------------------
	# action処理
	#-------------------------------------------------------------
	my $action = $ROBJ->{Form}->{action};
	if ($ROBJ->{POST} && $action ne '' && $action !~ /\W/) {
		$self->{action_data} = $ROBJ->call( 'action/' . $action );
	}

	#-------------------------------------------------------------
	# コマンドライン？
	#-------------------------------------------------------------
	if ($ARGV[0] eq 'send') {
		my $r = $self->send();
		$ROBJ->output_array($r);
		return;
	}

	#-------------------------------------------------------------
	# スケルトン選択
	#-------------------------------------------------------------
	my $skeleton = 'index';
	if ($ENV{QUERY_STRING} =~ /^(\w+)/) {
		$skeleton = $1;
	}

	$self->output_html($skeleton);
	return 0;
}

#------------------------------------------------------------------------------
# ●HTMLの生成と出力
#------------------------------------------------------------------------------
sub output_html {
	my $self = shift;
	my $ROBJ = $self->{ROBJ};
	my ($skeleton) = @_;

	# スケルトンの確認
	if ($skeleton ne '') {
		my $file = $ROBJ->check_skeleton($skeleton);
		if (! defined $file) {
			$ROBJ->redirect( $ROBJ->{Myself} );
		}
	}

	# スケルトンの実効
	my $out;
	if ($self->{action_is_main}) {	# actionの中身で代用する
		$out = $self->{action_data};
	} else {
		$out = $ROBJ->call($skeleton);
	}

	# フレームあり？
	my $frame_name = $self->{frame_skeleton};
	if ($frame_name ne '') {
		$self->{inframe} = $out;
		$out = $ROBJ->call($frame_name);
	}
	$ROBJ->print_http_headers();
	$ROBJ->output_array($out);	# HTML出力
}

###############################################################################
# ■スケルトン用サブルーチン
###############################################################################
#------------------------------------------------------------------------------
# ●登録
#------------------------------------------------------------------------------
sub regist {
	my $self = shift;
	my $form = shift;
	my $ROBJ = $self->{ROBJ};

	my %h;
	$h{endpoint} = $form->{endpoint};
	$h{cpub} = $form->{key_hex};
	$h{auth} = $form->{auth_hex};

	$self->update_data(\%h);
	return 0;
}

#------------------------------------------------------------------------------
# ●dataファイル保存
#------------------------------------------------------------------------------
sub update_data {
	my $self = shift;
	my $up   = shift || {};
	my $ROBJ = $self->{ROBJ};

	my $h = $self->{dat};
	foreach(keys(%$up)) {
		$h->{$_} = $up->{$_};
	}
	$ROBJ->fwrite_hash($self->{datafile}, $h);
}

###############################################################################
# ■通知送信
###############################################################################
#------------------------------------------------------------------------------
# ●initalize
#------------------------------------------------------------------------------
sub initalize {
	my $self = shift;
	my $ROBJ = $self->{ROBJ};

	my $dat = $self->{dat} = $ROBJ->fread_hash_cached( $self->{datafile} );

	if (!$dat->{spub} || !$dat->{sprv}) {
		my $pk = Crypt::PK::ECC->new();
		$pk->generate_key($ECC_NAME);
		my $pubkey = $pk->export_key_raw('public');
		my $prvkey = $pk->export_key_raw('private');
		$dat->{spub} = unpack('H*', $pubkey );
		$dat->{sprv} = unpack('H*', $prvkey );
		$self->update_data();
	}
}

#------------------------------------------------------------------------------
# ●送信
#------------------------------------------------------------------------------
sub send {
	my @buf;
	my $self = shift;
	my $data = shift || {};
	my $log  = shift || sub { push(@buf, @_, "\n") };

	my $ROBJ = $self->{ROBJ};
	my $dat  = $self->{dat};

	# URL
	my $url  = $dat->{endpoint};

	# ECC keys
	my $spub = pack('H*', $dat->{spub});
	my $sprv = pack('H*', $dat->{sprv});
	my $cpub = pack('H*', $dat->{cpub});

	my $secret;
	{
		my $pk1 = Crypt::PK::ECC->new();
		my $pk2 = Crypt::PK::ECC->new();
		$pk1->import_key_raw($sprv, $ECC_NAME);
		$pk2->import_key_raw($cpub, $ECC_NAME);
		$secret = $pk1->shared_secret($pk2);
	}
	&$log("secret: ", $self->base64urlsafe( $secret ));

	my $salt = $ROBJ->get_rand_string(16);
	my $auth = pack('H*', $dat->{auth});

	&$log("salt: ", $self->base64urlsafe( $salt ));
	&$log("auth: ", $self->base64urlsafe( $auth ));

	#-------------------------------------------------------------------
	# Original message
	#-------------------------------------------------------------------
	my $h = $data;
	$h->{title} ||= 'push test';
	$h->{body}  ||= 'message body';
	$h->{tag}   ||= 'push-' . time();
	my $msg = $self->generate_json($h);

	#-------------------------------------------------------------------
	# Encryption (aes128gcm)
	#-------------------------------------------------------------------
	my $header = {};
	my $body;
	my $jwt;
	my $jwt_sig;

	if ($AES128GCM) {
		# for aes128gcm
		my $ikm   = $self->hkdf($auth, $secret, "WebPush: info\x00$cpub$spub");
		my $cek   = $self->hkdf($salt, $ikm,    "Content-Encoding: aes128gcm\x00", 16);
		my $nonce = $self->hkdf($salt, $ikm,    "Content-Encoding: nonce\x00", 12);

		&$log("ikm   : ", $self->base64urlsafe( $ikm   ) );
		&$log("cek   : ", $self->base64urlsafe( $cek   ) );
		&$log("nonce : ", $self->base64urlsafe( $nonce ) );

		if (length($msg) > 3992) {
			&$log("Message too long! (", length($msg), " bytes)");
			return \@buf;
		}

		$msg	= $salt
			. pack('N', 4096)	# network byte order (big eddian)
			. "\x01$spub"
			. $msg;

		# AES-GCM
		my $ae = Crypt::AuthEnc::GCM->new('AES', $cek);
		$ae->iv_add($nonce);
		$ae->adata_add('');
		$body = $ae->encrypt_add($msg . "\x02\x00")
		      . $ae->encrypt_done();

		$header = {
			'Content-Encoding' => 'aes128gcm',
			TTL => 86400
		}

	#-------------------------------------------------------------------
	# Encryption (aesgcm)
	#-------------------------------------------------------------------
	} else {
		my $context = "P-256\x00"		# context is 140 byte
			. pack('n', length($cpub)) . $cpub
			. pack('n', length($spub)) . $spub;

		my $prk    = $self->hkdf($auth, $secret, "Content-Encoding: auth\x00", 32);
		my $aeskey = $self->hkdf($salt, $prk,    "Content-Encoding: aesgcm\x00$context", 16);
		my $nonce  = $self->hkdf($salt, $prk,    "Content-Encoding: nonce\x00$context",  12);

		&$log("aeskey: ", $self->base64urlsafe( $aeskey ) );
		&$log("nonce : ", $self->base64urlsafe( $nonce )  );

		# JWT

		if ($VAPID) {
			my $jwt_h = '{"typ":"JWT","alg":"ES256"}';
			my $jwt_c = '{';
			if ($url =~ m|^(\w+://[^/]*)|) { $jwt_c .= "\"aud\":\"$1\"," }
			$jwt_c .= "\"sub\":\"mailto:a\@b.c\",";
			$jwt_c .= "\"exp\":" . (time()+86400) . ',';
			chop($jwt_c);
			$jwt_c.='}';

			&$log("JWT Header: $jwt_h");
			&$log("JWT claims: $jwt_c");

			$jwt = $self->base64urlsafe($jwt_h) . '.' . $self->base64urlsafe($jwt_c);
			my $pk3 = Crypt::PK::ECC->new();
			$pk3->import_key_raw($sprv, $ECC_NAME);
			my $sig_der = $pk3->sign_message($jwt, 'SHA256');

			$jwt_sig = $self->parse_ANS1_der( $sig_der );	# ASN.1 DER format to Binary

			&$log("JWT context:   ", $jwt);
			&$log("JWT signature: ", $self->base64urlsafe($jwt_sig));
		}

		# push data
		if (length($msg) > 4078) {
			&$log("Message too long! (", length($msg), " bytes)");	# $msg is 4078 byte MAX
			return \@buf;
		}

		# AES-GCM
		my $ae = Crypt::AuthEnc::GCM->new('AES', $aeskey);
		$ae->iv_add($nonce);
		$ae->adata_add('');
		$body = $ae->encrypt_add("\x00\x00" . $msg)
		      . $ae->encrypt_done();

		$header = {
			'Content-Encoding' => 'aesgcm',
			'Crypto-Key' => 'keyid=p256dh;dh=' . $self->base64urlsafe($spub),
			Encryption => 'keyid=p256dh;salt=' . $self->base64urlsafe($salt),
			TTL => 86400
		}
	}

	#-------------------------------------------------------------------
	# POST
	#-------------------------------------------------------------------
	my $http = $ROBJ->loadpm('Base::HTTP');

	if ($jwt) {
		$header->{'Crypto-Key'} .= ';p256ecdsa=' . $self->base64urlsafe($spub);
		$header->{Authorization} = 'Bearer ' . $jwt . '.' . $self->base64urlsafe($jwt_sig);
		# (new)'WebPush' change from 'Bearer'(old)
	}
	&$log("");
	foreach(sort(keys(%$header))) {
		&$log("\t$_: $header->{$_}");
	}

	my $r = $http->post($url, $header, $body);

	&$log("POST: Status $http->{status}");
	if ($http->{status} != 200) {
		&$log(map {"\t$_\n"} @{$http->{header}});
	}
        &$log(@$r);

	return \@buf;
}

#------------------------------------------------------------------------------
# ●HMAC
#------------------------------------------------------------------------------
sub hkdf {
	my $self = shift;
	my $salt = shift;
	my $ikm  = shift;
	my $info = shift;
	my $len  = shift;

	my $prk = Crypt::Mac::HMAC::hmac('SHA256', $salt, $ikm);
	my $ret = Crypt::Mac::HMAC::hmac('SHA256', $prk,  "$info\x01");
	return $len ? substr($ret, 0, $len) : $ret;
}

#------------------------------------------------------------------------------
# ●URL safe base64
#------------------------------------------------------------------------------
my $base64tableu = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
sub base64urlsafe {
	my $self = shift;
	my $str  = shift;
	my $ret;

	# 2 : 0000_0000 1111_1100
	# 4 : 0000_0011 1111_0000
	# 6 : 0000_1111 1100_0000
	my ($i, $j, $x, $y);
	for($i=$x=0, $j=2; $i<length($str); $i++) {
		$x    = ($x<<8) + ord(substr($str,$i,1));
		$ret .= substr($base64tableu, ($x>>$j) & 0x3f, 1);

		if ($j != 6) { $j+=2; next; }
		# j==6
		$ret .= substr($base64tableu, $x & 0x3f, 1);
		$j    = 2;
	}
	if ($j != 2) { $ret .= substr($base64tableu, ($x<<(8-$j)) & 0x3f, 1); }
	return $ret;
}

#------------------------------------------------------------------------------
# ●URL safe base64
#------------------------------------------------------------------------------
my @base64ary = (
 0, 0, 0, 0,  0, 0, 0, 0,   0, 0, 0, 0,  0, 0, 0, 0,	# 0x00〜0x1f
 0, 0, 0, 0,  0, 0, 0, 0,   0, 0, 0, 0,  0, 0, 0, 0,	# 0x10〜0x1f
 0, 0, 0, 0,  0, 0, 0, 0,   0, 0, 0,62,  0,62, 0,63,	# 0x20〜0x2f
52,53,54,55, 56,57,58,59,  60,61, 0, 0,  0, 0, 0, 0,	# 0x30〜0x3f
 0, 0, 1, 2,  3, 4, 5, 6,   7, 8, 9,10, 11,12,13,14,	# 0x40〜0x4f
15,16,17,18, 19,20,21,22,  23,24,25, 0,  0, 0, 0,63,	# 0x50〜0x5f
 0,26,27,28, 29,30,31,32,  33,34,35,36, 37,38,39,40,	# 0x60〜0x6f
41,42,43,44, 45,46,47,48,  49,50,51, 0,  0, 0, 0, 0	# 0x70〜0x7f
);
sub base64decode {
	my $self = shift;
	my $str  = shift;

	my $ret;
	my $buf;
	my $f;
	$str =~ s/[=\.]+$//;
	for(my $i=0; $i<length($str); $i+=4) {
		$buf  = ($buf<<6) + $base64ary[ ord(substr($str,$i  ,1)) ];
		$buf  = ($buf<<6) + $base64ary[ ord(substr($str,$i+1,1)) ];
		$buf  = ($buf<<6) + $base64ary[ ord(substr($str,$i+2,1)) ];
		$buf  = ($buf<<6) + $base64ary[ ord(substr($str,$i+3,1)) ];
		$ret .= chr(($buf & 0xff0000)>>16) . chr(($buf & 0xff00)>>8) . chr($buf & 0xff);
	}
	my $f = length($str) & 3;	# mod 4
	if ($f >1) { chop($ret); }
	if ($f==2) { chop($ret); }
	return $ret;
}

#------------------------------------------------------------------------------
# ●Parse ASN.1 DER format
#------------------------------------------------------------------------------
#	+00h	30h	SEQUENCE
#	+01h	--	SEQUENCE Length
#	+02h	02h	Tag
#	+03h	x	R Length
#	+04h	--	R
#	x+4	02h	Tag
#	x+5	y	S Length
#	x+6	--	S
sub parse_ANS1_der {
	my $self = shift;
	my $der  = shift;

	my $x = ord(substr($der,   3,1));
	my $y = ord(substr($der,$x+5,1));
	my $r = substr($der,    4, $x);
	my $s = substr($der, $x+6, $y);
	$r =~ s/^\x00+//;
	$s =~ s/^\x00+//;
	return $r . $s;
}

#------------------------------------------------------------------------------
# ●hash/arrayツリーからjsonを生成する
#------------------------------------------------------------------------------
sub generate_json {
	my $self = shift;
	my $data = shift;
	my $cols = shift;	# データカラム
	my $ren  = shift || {};	# カラムのリネーム情報
	my $tab  = shift || '';
	my @ary;
	
	sub encode {
		my $v = shift;
		if ($v =~ /^\d+$/) { return $v; }
		if (ref($v) eq 'SCALAR') { return $$v; }
		# 文字列
		$v =~ s/\\/&#92;/g;
		$v =~ s/\n/\\n/g;
		$v =~ s/\t/\\t/g;
		$v =~ s/"/\\"/g;
		return '"' . $v . '"';
	}

	my $is_ary = ref($data) eq 'ARRAY';
	my $dat = $is_ary ? $data : [$data];
	foreach(@$dat) {
		if (!ref($_)) {
			push(@ary, &encode($_));
			next;
		}
		my @a;
		my @b;
		my $_cols = $cols ? $cols : [ keys(%$_) ];
		foreach my $x (@$_cols) {
			my $k = exists($ren->{$x}) ? $ren->{$x} : $x;
			my $v = $_->{$x};
			if (!ref($v)) {
				push(@a, "\"$k\": " . &encode( $v ));
				next;
			}
			# 入れ子
			my $ch = $self->generate_json( $v, $cols, $ren, "\t$tab" );
			push(@b, "\"$k\": $ch");
		}
		push(@ary, $is_ary
			? "$tab\t{"   . join(", "       , @a, @b) . "}"
			: "{\n$tab\t" . join(",\n$tab\t", @a, @b) . "\n$tab}"
		);
	}
	return $is_ary ? "[\n" . join(",\n", @ary) . "\n$tab]" : $ary[0];
}

#------------------------------------------------------------------------------
# ●write
#------------------------------------------------------------------------------
sub write_file {
	my $self = shift;
	my $file = shift;
	my $data = shift;

	open(my $fh, ">$file");
	syswrite($fh, $data, length($data));
	close($fh);
}

#------------------------------------------------------------------------------
# ●スマホ判別
#------------------------------------------------------------------------------
sub sphone_checker {
	my $ua = $ENV{HTTP_USER_AGENT};
	if (0<index($ua,'iPhone') || 0<index($ua,'iPod') || 0<index($ua,'Android')
	 || 0<index($ua,'BlackBerry') || 0<index($ua,'Windows Phone')) {
		return 1;
	}
	return ;
}


1;
