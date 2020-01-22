<?php
declare (strict_types = 1);
namespace think\auth;

use think\facade\Db as Db;
use think\facade\Config;
use think\facade\Session;
use think\facade\Request;

class Auth
{

    protected $request;

    protected static $instance;

    public function __construct()
    {
        $this->request = Request::instance();
    }

    public static function instance($options = [])
    {
        if (is_null(self::$instance)) {
            self::$instance = new static($options);
        }
        return self::$instance;
    }

    public function checkAction($mode = 'url', $relation = 'or')
    {
        $controller = strtolower(request()->controller());
        $action = strtolower(request()->action());
        $name = $controller . '_' . $action;

        $ignore_controller = Config::get('auth.ignore_controller');
        $ignore_action = Config::get('auth.ignore_action');

        if (in_array($controller, array_map('strtolower', $ignore_controller))) {
            return true;
        } else if (in_array($name, array_map('strtolower', $ignore_action))) {
            return true;
        }
        return $this->check($name, $mode, $relation);
    }

    public function checkString($name, $mode = 'url', $relation = 'or')
    {
        $ignore_string = Config::get('auth.ignore_string');
        if (in_array($name, array_map('strtolower', $ignore_string))) {
            return true;
        } else {
            return $this->check($name, $mode, $relation);
        }
    }

    /**
     * 检查权限
     *
     * @param $name string|array
     *            需要验证的规则列表,支持逗号分隔的权限规则或索引数组
     * @param string $mode
     *            执行check的模式
     * @param string $relation
     *            如果为 'or' 表示满足任一条规则即通过验证;如果为 'and'则表示需满足所有规则才能通过验证
     * @return int 通过验证返回true;失败返回false
     */
    private function check($name, $mode = 'url', $relation = 'or')
    {
        $name = strtolower($name);
        if (Session::has('user')) {
            $user = Session::get('user');
        } else {
            return false;
        }
        if (! Config::get('auth.auth_on')) {
            return true;
        }

        // 获取用户需要验证的所有有效规则列表
        $authList = $this->getAuthList($user);
        if (is_string($name)) {
            $name = strtolower($name);
            if (strpos($name, ',') !== false) {
                $name = explode(',', $name);
            } else {
                $name = [
                    $name
                ];
            }
        }
        $list = []; // 保存验证通过的规则名
        if ('url' == $mode) {
            $REQUEST = unserialize(strtolower(serialize($this->request->param())));
        }
        foreach ($authList as $auth) {
            $param = '';
            $query = preg_replace('/^.+\?/U', '', $auth);
            if ('url' == $mode && $query != $auth) {
                parse_str($query, $param); // 解析规则中的param
                $intersect = array_intersect_assoc($REQUEST, $param);
                $auth = preg_replace('/\?.*$/U', '', $auth);
                if (in_array($auth, $name) && $intersect == $param) {
                    // 如果节点相符且url参数满足
                    $list[] = $auth;
                }
            } else {
                if (in_array($auth, $name)) {
                    $list[] = $auth;
                }
            }
        }
        if ('or' == $relation && ! empty($list)) {
            return true;
        }
        $diff = array_diff($name, $list);
        if ('and' == $relation && empty($diff)) {
            return true;
        }
        return false;
    }

    /**
     * 根据用户id获取用户组,返回值为数组
     *
     * @param $uid int
     *            用户id
     * @return array 用户所属的用户组 array(
     *         array('uid'=>'用户id','group_id'=>'用户组id','title'=>'用户组名称','rules'=>'用户组拥有的规则id,多个,号隔开'),
     *         ...)
     */
    public function getGroups($user)
    {
        static $groups = [];
        if (isset($groups[$user->id])) {
            return $groups[$user->id];
        }
        // 转换表名
        $auth_group_access = Config::get('auth.auth_group_access');
        $auth_group = Config::get('auth.auth_group');
        // 执行查询
        $user_groups = Db::view($auth_group_access, 'user_id, role_id')->view($auth_group, 'name,rules', "{$auth_group_access}.role_id={$auth_group}.id", 'LEFT')
            ->where("{$auth_group_access}.user_id='{$user->id}' and {$auth_group}.status='1'")
            ->select()
            ->toArray();
        $groups[$user->id] = $user_groups ?: [];
        return $groups[$user->id];
    }

    /**
     * 获得权限列表
     *
     * @param integer $uid
     *            用户id
     * @param integer $type
     * @return array
     */
    protected function getAuthList($user, $type = 1)
    {
        static $_authList = []; // 保存用户验证通过的权限列表
        $t = implode(',', (array) $type);
        if (isset($_authList[$user->id . $t])) {
            return $_authList[$user->id . $t];
        }
        if (2 == Config::get('auth.auth_type') && Session::has('_auth_list_' . $user->id . $t)) {
            return Session::get('_auth_list_' . $user->id . $t);
        }
        // 读取用户所属用户组
        $groups = $this->getGroups($user);

        $ids = []; // 保存用户所属用户组设置的所有权限规则id
        foreach ($groups as $g) {
            $ids = array_merge($ids, explode(',', trim($g['rules'], ',')));
        }
        $ids = array_unique($ids);
        if (empty($ids)) {
            $_authList[$user->id . $t] = [];
            return [];
        }
        $map = array(
            'condition_status' => $type,
            'status' => 1
        );
        // 读取用户组所有权限规则
        $rules = Db::name(Config::get('auth.auth_rule'))->where($map)
            ->where('id', 'in', $ids)
            ->field('condition, name')
            ->select();

        // 循环规则，判断结果。
        $authList = [];
        foreach ($rules as $rule) {
            if (! empty($rule['condition'])) {
                // 根据condition进行验证
                $condition = false;
                @(eval('$condition=(' . preg_replace('/\{(\w*?)\}/', '$user[\'\\1\']', $rule['condition']) . ')?true:false;'));
                if ($condition) {
                    $authList[] = strtolower($rule['name']);
                }
            } else {
                // 只要存在就记录
                $authList[] = strtolower($rule['name']);
            }
        }
        $_authList[$user->id . $t] = $authList;
        if (2 == Config::get('auth.auth_type')) {
            // 规则列表结果保存到session
            Session::set('_auth_list_' . $user->id . $t, $authList);
        }

        return array_unique($authList);
    }
}
