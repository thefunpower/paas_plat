<?php 
/**
* 获取服务域名
*/
function get_service_url($service_name){
  $res = get_service_info($service_name); 
  return $res['domain'];
}
/**
* 获取服务信息
*/
function get_service_info($service_name){
  $client = get_plat_service('service');
  if(!$client){return;}
  $res = $client->get('sso');
  return $res;
}
/**
* 登录基类
*/
class plat_login{
    /**
    * 登录检测
    * 使用token检测登录信息
    * $config['redirect_url'] = '/';
    */
    public function check(){ 
        global $config;
        $token = g('token');
        $redirect_url = g('redirect_url')?:$config['redirect_url'];
        if($token){
            $data = json_decode(aes_decode($token),true);
            if($data && $data['code'] == 0 && $data['data']['user_id']){ 
                $err = $data['time']+10-time() > 0?false:true;
                $this->set_cookie($data['data'],$err); 
                jump($redirect_url);
            } 
        } 
    }
    /**
    * 设置COOKIE登录信息
    * [user] => yiiphp@foxmail.com
    * [type] => email
    * [created_at] => 2023-02-13 17:15:33
    * [user_id] => 2
    */
    protected function set_cookie($data,$err){ 
        $content = "请求异常，请返回原地址重新发起请求";
        if(!$data['user_id'] || !$data['user'] || !$data['type']){
            $err = true;
            $content = '已阻止非法请求，如有疑问请联系管理员';
        }
        if($err){
            $title = "登录异常";
            return view('error',[
                'title'=>$title,
                'content'=>$content
            ]); 
        }
        $time = time()+86400*365*10;
        cookie('sso_user_id',$data['user_id'],$time);
        cookie('sso_user_account',$data['user'],$time);
        cookie('sso_user_type',$data['type'],$time);
    } 


}
/**
* 获取登录后的信息
*/
function get_rpc_logined(){
    if(cookie('sso_user_id')){
        return [
            'user_id'=>cookie('sso_user_id'),
            'user_account'=>cookie('sso_user_account'),
            'user_type'=>cookie('sso_user_type'),
        ];
    }
}
 
/**
* 登录
*/
function get_rpc_login(){
  $url = host().'login/check';
  $rpc = get_plat_service('service');
  $res = $rpc->get('sso'); 
  if(!cookie('sso_user_id')){
    jump($res['domain'].'login?redirect_url='.urlencode($url));
  }
}
/**
* 退出系统
*/
function get_rpc_logout(){
    remove_cookie("sso_user_id");
    remove_cookie("sso_user_account");
    remove_cookie("sso_user_type"); 
}


/**
* 调用服务
*/
function get_api_service($service_slug,$service,$call){
    //服务中心查寻对应的服务服务是否已注册并启用
    $client = get_plat_service('service'); 
    $res = $client->get($service_slug);
    //取到所需服务对应的接口域名，并发起RPC请求
    if($res['code'] == 0 && $res['domain']){ 
        $client = get_plat_service($service,$res['domain'].'api/');  
        return $call($client);
    }else{

    } 
}

/**
* 初始化服务中心
* 需要生成RSA证书
*/ 
function plat_boot_rsa(){
    $privatekey = PATH.'data/privatekey.pem';
    $publickey = PATH.'data/publickey.pem';
    if(!file_exists($privatekey)){
        $rsa = new lib\Rsa;
        $res = $rsa->create(); 
        file_put_contents($privatekey,$res['privatekey']);
        file_put_contents($publickey,$res['publickey']);
    }else{

    } 
}
/**
* 注册服务到PASS平台
*/
function register_to_pass_as_service($app_name,$slug){
    register_to_pass_as_app($app_name,'service',$slug);
}

/**
* 把软件注册到PASS平台
* register_to_pass_as_app('演示');
*/
function register_to_pass_as_app($app_name,$type = 'app',$slug = ''){ 
    $service= get_plat_service('app'); 
    $domain = host();
    $res = $service->register($app_name, $domain,$type,$slug);
    if($res['ak'] && $res['sk']){
        //把返回的ak sk保存起来
        unset($res['ak'],$res['sk']); 
    } 
}


/**
* 通过RSA方法请求RPC服务
* RSA用公钥加密
* 向PASS平台中心请求的
*/
function get_plat_service($api_name,$rpc_url=''){ 
    global $config;
    $rpc_url = $rpc_url?:$config['plat_api_url'];
    $publickey = PATH.'data/publickey.pem';
    if(!file_exists($publickey)){
        json_error(['msg'=>'RSA publickey file not exists']);
    }
    $publickey = file_get_contents($publickey); 
    $rsa = new lib\Rsa;
    $token = base64_encode($rsa->encode(json_encode([
        'time'=>time(),
        'api_name'=>$api_name,
    ]),$publickey)); 
    $ak     = 'anonymous';
    $domain = host();
    $client = new Yar_Client($rpc_url.$api_name);  
    $client->SetOpt(YAR_OPT_HEADER, [
        "TOKEN: ".$token,
        "AK: ".$ak,
        "DOMAIN: ".$domain,
        "YARTPYE: RSA",
    ]);
    $client->SetOpt(YAR_OPT_CONNECT_TIMEOUT, 3000);   
    return $client; 
}



/**
* RPC 基类
*/
class rpc_service{ 
    //请求SERVER信息
    protected $data;
    //解密后数据
    protected $decrypt_data;

    public function __construct(){ 
        $this->data = [
            'type'  => $_SERVER['HTTP_YARTPYE'],
            'domain'=> $_SERVER['HTTP_DOMAIN'],
            'ak'    => $_SERVER['HTTP_AK'],
            'token' => $_SERVER['HTTP_TOKEN'],
        ];
    }
    /**
    * 运行RPC函数时会验证通讯是否允许
    */
    protected function run($call){ 
        $token = $this->data['token'];
        $ak = $this->data['ak'];
        $domain = $this->data['domain'];
        $type = $this->data['type'];
        if(!in_array($type,['RSA','AES'])){
            return [
                'msg' => '服务异常，错误发现在'.now(),
                'label'=> 1000,
                'code'=> 404
            ]; 
        }
        //RAS
        if($type == 'RSA'){
            $privatekey = PATH.'data/privatekey.pem';
            if(!file_exists($privatekey)){
                return [
                    'msg'  => '通讯证书异常，错误发现在'.now(),
                    'label'=> 1001,
                    'code' => 403
                ]; 
            }
            $privatekey = file_get_contents($privatekey);
            $rsa = new lib\Rsa;   
            $b_token = base64_decode($token); 
            $decrypt_data = json_decode(@$rsa->decode($b_token,$privatekey),true);
            $this->decrypt_data = $decrypt_data;
            if(!$decrypt_data){
                return [ 
                    'token'=>$token,
                    'msg'  => '通讯证书异常，错误发现在'.now(),
                    'label'=> 1002,
                    'code' => 403
                ]; 
            }
            if(!$decrypt_data['time']){
                return [  
                    'msg'  => '请求异常，错误发现在'.now(),
                    'label'=> 10020,
                    'code' => 403
                ]; 
            }
            if( $decrypt_data['time']+10 > time()){
                
            }else{
                return [  
                    'msg'  => '请求异常，错误发现在'.now(),
                    'label'=> 10021,
                    'code' => 403
                ]; 
            }

        }
        if(!$token){
            return [
                'msg' => '通讯异常，错误发现在'.now(),
                'label'=> 1003,
                'code'=> 403
            ]; 
        }
        return $call();
    }
}

/**
* 执行
*/
function yar_api_run($name){
    $class = "service\\".$name;
    if(class_exists($class)){ 
        $service = new Yar_Server(new $class());
        $service->handle();
    }else{
        json_error(['msg'=>'serve is not exists']);
    } 
}
