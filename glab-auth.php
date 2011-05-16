<?php
/*
Plugin Name: G LAB Admin Authentication
Version: 1.0
Description: G LAB Admin Authentication is a Wordpress plugin that allows Wordpress to authenticate against the G LAB employee database.
Author: G LAB
Author URI: http://glabstudios.com/
*/

require_once 'googleclientlogin.php';

if (! class_exists('ThirdPartyPlugin')) {
	abstract class ThirdPartyAuthenticator {
		abstract function authenticate($username, $password);
	}
	abstract class EmailAuthenticator extends ThirdPartyAuthenticator {
		function __construct ($server, $ssl = false, $port = null) {
			$this->server = $server;
			$this->ssl = $ssl;
			if (isset($port) && $port != '') {
				$this->port = $port;
			} else {
				$this->port = $this->getDefaultPort();
			}
		}
		function getURL() {
			if ($this->ssl) {
				return 'ssl://'.$this->server;
			} else {
				return 'tcp://'.$this->server;
			}
		}
		abstract function getDefaultPort();
	}
	class IMAPAuthenticator extends EmailAuthenticator {
		function __construct ($server, $ssl = false, $port = null) {
			parent::__construct($server, $ssl, $port);
		}
		function getDefaultPort() {
			if($this->ssl) {
				return 993;
			} else {
				return 143;
			}
		}
		function authenticate($username, $password) {
			$ssl = fsockopen($this->getURL(), $this->port, $err, $errdata, 40);
			if ($ssl) {
				$auth = fgets($ssl, 256);
				fputs($ssl, '0000 CAPABILITY'."\n");
				$auth = fgets($ssl, 256);
				$auth = fgets($ssl, 256);
				fputs($ssl, '0001 LOGIN '.$username.' '.$password."\n");
				$auth = fgets($ssl, 256);
				fclose ($ssl);
				if(preg_match('/Success/',$auth) || preg_match('/Ok/',$auth)) {
					return true;
				} else {
					return false;
				}
			}
			return false;
		}
	}
	class GoogleAuthenticator extends ThirdPartyAuthenticator {
		function authenticate($username, $password) {
			$google = new GoogleClientLogin();
			return $google->Authenticate($username,$password);
		}
	}
	class ThirdPartyPlugin {
		function ThirdPartyPlugin() {
			add_filter('check_password', array(&$this, 'check_password'), 10, 4);
			add_action('login_form', array(&$this, 'login_form'));

		}


		/*************************************************************
		 * Plugin hooks
		 *************************************************************/
		
		function login_form() {
				echo 'G LAB Admins: <a href="https://www.google.com/accounts/DisplayUnlockCaptcha">Password not working?</a><br /><br />';
		}
		
		function login_failed($username) {
			if (!function_exists('wp_create_user')) {
				include_once 'wp-includes/registration.php';
			}
			if ($this->cool_domain($username)) {
				$user = get_userdatabylogin($username);
				if ( !$user || ($user->user_login != $username) ) {
					
					$user_parts = explode('@', $username);
					
					$data['user_email'] = $username;
					$data['user_login'] = $data['user_email'];
					$data['user_pass'] = wp_generate_password( 12, false );
					$data['first_name'] = ucwords(trim($user_parts[0]));
					$data['jabber'] = $data['user_email'];
					$data['user_url'] = 'http://glabstudios.com/';
					$data['nickname'] = $data['first_name'].' @ G LAB';
					$data['display_name'] = $data['nickname'];
					$data['role'] = 'administrator';
					
					$user_id = wp_insert_user($data);
				}
				return $user_id;
			}
		}
		
		function use_google($domain) {
			if (strtolower($domain) == 'glabstudios.com') return true;
		}
		
		function cool_domain($username) {
			$parts = explode("@",$username);
			if (count($parts) != 2) {
				return false;
			} else {
				return $this->use_google($parts[1]);
			}
		}
		
		function check_password($check, $password, $hash, $user_id) {
			$user = get_userdata($user_id);
			$username = $user->user_login;
			if ($check) {
				return true;
			} else {
				$parts = explode("@",$username);
				if (count($parts) != 2) {
					die('Username not an email address.');
				}

				if ($this->use_google($parts[1])) {
					$authenticator = new GoogleAuthenticator();
				}
				
				if (isset($authenticator)) {
					return $authenticator->authenticate($username,$password);
				} else {
					die('Domain '.$parts[1].' not supported.');
				}
			}
		}
		
		/*
		 * If the REMOTE_USER or REDIRECT_REMOTE_USER evironment
		 * variable is set, use it as the username. This assumes that
		 * you have externally authenticated the user.
		 */
		function authenticate($username, $password) {

		}


		/*
		 * Skip the password check, since we've externally authenticated.
		 */
		function skip_password_check($check, $password, $hash, $user_id) {
			return true;
		}

		/*
		 * Used to disable certain display elements, e.g. password
		 * fields on profile screen.
		 */
		function disable_password_fields($show_password_fields) {
			return false;
		}

		/*
		 * Used to disable certain login functions, e.g. retrieving a
		 * user's password.
		 */
		function disable_function() {
			die('Disabled');
		}
	}
}

// Load the plugin hooks, etc.
$third_party_plugin = new ThirdPartyPlugin();
//Only works if another function doesn't define this first
if ( !function_exists('wp_authenticate') ) :
function wp_authenticate($username, $password) {
	$username = sanitize_user($username);

	if ( '' == $username )
		return new WP_Error('empty_username', __('<strong>ERROR</strong>: The username field is empty.'));

	if ( '' == $password )
		return new WP_Error('empty_password', __('<strong>ERROR</strong>: The password field is empty.'));

	$user = get_userdatabylogin($username);
	if ( !$user || ($user->user_login != $username) ) {
		global $third_party_plugin;
		$third_party_plugin->login_failed($username);
		$user = get_userdatabylogin($username);
	}
	
	if ( !$user || ($user->user_login != $username) ) {
		do_action( 'wp_login_failed', $username );
		return new WP_Error('invalid_username', __('<strong>ERROR</strong>: Invalid username.'));
	}

	$user = apply_filters('wp_authenticate_user', $user, $password);
	if ( is_wp_error($user) ) {
		do_action( 'wp_login_failed', $username );
		return $user;
	}

	if ( !wp_check_password($password, $user->user_pass, $user->ID) ) {
		do_action( 'wp_login_failed', $username );
		return new WP_Error('incorrect_password', __('<strong>ERROR</strong>: Incorrect password.'));
	}

	return new WP_User($user->ID);
}
endif;
?>
