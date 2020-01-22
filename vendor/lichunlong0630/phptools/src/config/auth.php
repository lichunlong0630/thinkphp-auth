<?php
return [
    'auth_on' => 1, // 权限开关
    'auth_type' => 1, // 认证方式，1为实时认证；2为登录认证。
    'auth_group' => 'auth_role', // 用户组数据表名
    'auth_group_access' => 'auth_role_access', // 用户-用户组关系表
    'auth_rule' => 'auth_rule', // 权限规则表

    // 忽略顺序为ignore_string->ignore_controller->ignore_action
    'ignore_controller' => [ // 忽略的控制器
    ],
    'ignore_action' => [ // 忽略的操作，值为controller_action

    ],
    'ignore_string' => [ // 自定义忽略
    ]
];
