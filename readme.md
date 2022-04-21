- 关注点
   1. 发起操作需要的原始信息：用户，什么情况下，对什么对象（被操作对象属性），做什么操作（操作属性）
      1. 用户：用户属性，包括 uid，自定义属性等
      2. 什么情况下：环境属性，包括时间、IP、客户端 等访问控制
      3. 什么对象：资产 id 、账户 id、自定义资产属性
      4. 做什么操作：执行文件上传命令 等运维控制、命令控制等


- 业务流程
  1. 业务授权规则添加到数据库后，根据数据库数据，组装权限策略数据（对应 casbin policy)，加载到 casbin 校验器中
    1. 见 PermRule 抽象
    2. 每个项目的每条业务授权规则，即是一调 casbin策略，可以控制策略数量，最大化性能
  2. 根据用户 id 查询到用户参与的项目，将多个项目授权策略，组装casbin request 结构体数据，逐一校验。

- casbin 规则文件示例，用于 casbin 加载
```
[request_definition]
r = user, obj, env, act

[policy_definition]
p = user_rule, obj_rule, env_rule, act_rule, eft

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = eval(p.user_rule) && eval(p.obj_rule) && eval(p.env_rule) && eval(p.act_rule)
```

- 策略数据示例，根据数据库配置信息生成的，用于 casbin 加载
```
p, "r.user.ProjectId == 'pid' && (r.user.UId in ('uid1', 'uid2') || r.user.GId in ('gid1', 'gid2'))", "r.obj.AssetId in ('asset1', 'asset2') || r.obj.AssetGId in ('assetgid1', 'assetgid2')", "(r.env.SrcIPNum > 1 && r.env.SrcIPNum < 10) || (r.env.SrcIPNum > 20 && r.env.SrcIPNum < 30) && r.env.LocalClient == 1", "r.act.Action=='op'", allow
```

- 设计重点
  1. 业务权限模型的抽象：见 PermRule 定义
