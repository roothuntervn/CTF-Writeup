<?php

require_once('../sql_connect.php');
require_once('cookie.php');

if(isset($_POST['user']) && isset($_POST['pass'])){
	if(isset($_COOKIE['user_info'])){
		unset($_COOKIE['user_info']);
	}
	$u = $_POST['user'];
	$p = $_POST['pass'];

	if($sql_conn_login->connect_errno){
		die('Could not connect');
	}

	if (!($prepared = $sql_conn_login->prepare("SELECT username, admin FROM pico_ch2.users WHERE username = ? AND password = ?;"))) {
	    die("SQL error");
	}

	$prepared->bind_param('ss', $u, $p);
	
	if (!$prepared->execute()) {
	    die("SQL error");
	}
	
	if (!($result = $prepared->get_result())) {
	    die("SQL error");
	}

	$r = $result->fetch_all();

	if($result->num_rows === 1){
		$perm = new permissions($u, $p);
		setcookie('user_info', urlencode(base64_encode(serialize($perm))), time() + (86400 * 30), "/");
		header('Location: index.php?file=login');
	}
	else{
		$error = '<h6 class="text-center" style="color:red">Invalid Login.</h6>';
	}
	$sql_conn_login->close();
}
else if(isset($perm) && $perm->is_admin()){
	header('Location: index.php?file=admin');
	die();
}
else if(isset($perm)){
	header('Location: index.php?file=regular_user');
	die();
}

?>

	<body>
		<div class="container">
			<div class="row">
				<div class="col-sm-9 col-md-7 col-lg-5 mx-auto">
					<div class="card card-signin my-5">
						<div class="card-body">
							<h5 class="card-title text-center">Sign In</h5>
							<?php if (isset($error)) echo $error;?>
							<form class="form-signin" action="index.php?file=login" method="post">
								<div class="form-label-group">
									<input type="text" id="user" name="user" class="form-control" placeholder="Username" required autofocus>
									<label for="user">Username</label>
								</div>

								<div class="form-label-group">
									<input type="password" id="pass" name="pass" class="form-control" placeholder="Password" required>
									<label for="pass">Password</label>
								</div>

								<button class="btn btn-lg btn-primary btn-block text-uppercase" type="submit">Sign in</button>
							</form>
						</div>
					</div>
				</div>
			</div>
		</div>

	</body>
