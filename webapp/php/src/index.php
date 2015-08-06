<?php
require_once 'limonade/lib/limonade.php';

function configure() {
  option('base_uri', '/');
  option('session', 'isu4_qualifier_session');

  $host = getenv('ISU4_DB_HOST') ?: 'localhost';
  $port = getenv('ISU4_DB_PORT') ?: 3306;
  $dbname = getenv('ISU4_DB_NAME') ?: 'isu4_qualifier';
  $username = getenv('ISU4_DB_USER') ?: 'root';
  $password = getenv('ISU4_DB_PASSWORD');
  $db = null;
  try {
    $db = new PDO(
      'mysql:host=' . $host . ';port=' . $port. ';dbname=' . $dbname,
      $username,
      $password,
      [ PDO::ATTR_PERSISTENT => true,
        PDO::MYSQL_ATTR_INIT_COMMAND => 'SET CHARACTER SET `utf8`',
      ]
    );
  } catch (PDOException $e) {
    halt("Connection faild: $e");
  }
  $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

  option('db_conn', $db);

  // redisをつかう
  $redis = new Redis();
  $redis->connect("127.0.0.1",6379);
  option('redis', $redis);

  $config = [
    'user_lock_threshold' => getenv('ISU4_USER_LOCK_THRESHOLD') ?: 3,
    'ip_ban_threshold' => getenv('ISU4_IP_BAN_THRESHOLD') ?: 10
  ];
  option('config', $config);
}

function uri_for($path) {
  $host = $_SERVER['HTTP_X_FORWARDED_HOST'] ?: $_SERVER['HTTP_HOST'];
  return 'http://' . $host . $path;
}

function get($key) {
  return set($key);
}

function before() {
  layout('base.html.php');
}

function calculate_password_hash($password, $salt) {
  return hash('sha256', $password . ':' . $salt);
}

function login_log($succeeded, $login, $user_id=null) {

  $redis = option('redis');

  if ($succeeded) {
    $redis->set('locked_user_'.$user_id, 0);
    $redis->set('ban_ip_'.$_SERVER['REMOTE_ADDR'], 0);
    
    $last_login_time = $redis->get('login_'.$user_id);
    $last_login_ip = $redis->get('login_ip_'.$user_id);

    if (!is_null($last_login_time)){
        $redis->set('last_login_'.$user_id, $last_login_time);
    }
    if (!is_null($last_login_ip)){
        $redis->set('last_login_ip_'.$user_id, $last_login_ip);
    }

    $redis->set('login_'.$user_id, date("Y-m-d H:i:s", time()));
    $redis->set('login_ip_'.$user_id, $_SERVER['REMOTE_ADDR']);
  }
  else {
    if (!is_null($user_id)) {
      $redis->incr('locked_user_'.$user_id);
    }
    $redis->incr('ban_ip_'.$_SERVER['REMOTE_ADDR']);
  }
}

function user_locked($user) {
  if (empty($user)) { return null; }
  // redisをつかう
  $redis = option('redis');
  $value = $redis->get('locked_user_'.$user['id']) ?: 0;

  $config = option('config');
  return $value && $config['user_lock_threshold'] <= $value;
}

# FIXME
function ip_banned() {
  $config = option('config');

  // redisをつかう
  $redis = option('redis');
  $value = $redis->get('ban_ip_'.$_SERVER['REMOTE_ADDR']) ?: 0;

  return $value && $config['ip_ban_threshold'] <= $value;

}

function attempt_login($login, $password) {
  $db = option('db_conn');

  // redisをつかう
  $redis = option('redis');
  
  // mysqlのまま（あとでけす）
  $stmt = $db->prepare('SELECT * FROM users WHERE login = :login');
  $stmt->bindValue(':login', $login);
  $stmt->execute();
  $user = $stmt->fetch(PDO::FETCH_ASSOC);

  if (ip_banned()) {
    login_log(false, $login, isset($user['id']) ? $user['id'] : null);
    return ['error' => 'banned'];
  }

  if (user_locked($user)) {
    login_log(false, $login, $user['id']);
    return ['error' => 'locked'];
  }

  if (!empty($user) && calculate_password_hash($password, $user['salt']) == $user['password_hash']) {
    login_log(true, $login, $user['id']);
    return ['user' => $user];
  }
  elseif (!empty($user)) {
    // 値をセットする
    login_log(false, $login, $user['id']);
    return ['error' => 'wrong_password'];
  }
  else {
    login_log(false, $login);
    return ['error' => 'wrong_login'];
  }
}

function current_user() {
  if (empty($_SESSION['user_id'])) {
    return null;
  }

  $db = option('db_conn');

  $stmt = $db->prepare('SELECT * FROM users WHERE id = :id');
  $stmt->bindValue(':id', $_SESSION['user_id']);
  $stmt->execute();
  $user = $stmt->fetch(PDO::FETCH_ASSOC);

  if (empty($user)) {
    unset($_SESSION['user_id']);
    return null;
  }

  return $user;
}

function last_login() {
  $user = current_user();
  if (empty($user)) {
    return null;
  }

  $redis = option('redis');
  $last_login_time = $redis->get('last_login_'.$user['id']);
  $last_login_ip = $redis->get('last_login_ip_'.$user['id']);

  $ret = array('created_at'=>$last_login_time, 'ip'=>$last_login_ip);

  return $ret; 
}

function banned_ips() {
  $threshold = option('config')['ip_ban_threshold'];
  $ips = [];
  
  $redis = option('redis');


  $ban_ips = $redis->keys('ban*');
  foreach($ban_ips as $ban_ip) {
    if ($redis->get($ban_ip) >= $threshold) {
      array_push($ips, substr($ban_ip, 7));
    }
  }
  return $ips;
}

function locked_users() {
  $threshold = option('config')['user_lock_threshold'];
  $user_ids = [];

  $redis = option('redis');

  $locked_users = $redis->keys('locked*');
  foreach($locked_users as $locked_user) {
    if ($redis->get($locked_user) >= $threshold) {
      array_push($user_ids, substr($locked_user, 12));
    }
  }

  return $user_ids;
}

dispatch_get('/', function() {
  return html('index.html.php');
});

dispatch_post('/login', function() {
  $result = attempt_login($_POST['login'], $_POST['password']);
  if (!empty($result['user'])) {
    session_regenerate_id(true);
    $_SESSION['user_id'] = $result['user']['id'];
    return redirect_to('/mypage');
  }
  else {
    switch($result['error']) {
      case 'locked':
        flash('notice', 'This account is locked.');
        break;
      case 'banned':
        flash('notice', "You're banned.");
        break;
      default:
        flash('notice', 'Wrong username or password');
        break;
    }
    return redirect_to('/');
  }
});

dispatch_get('/mypage', function() {
  $user = current_user();

  if (empty($user)) {
    flash('notice', 'You must be logged in');
    return redirect_to('/');
  }
  else {
    set('user', $user);
    $last_login = last_login();
    set('last_login', $last_login);
    return html('mypage.html.php');
  }
});

dispatch_get('/report', function() {
  return json_encode([
    'banned_ips' => banned_ips(),
    'locked_users' => locked_users()
  ]);
});

run();
