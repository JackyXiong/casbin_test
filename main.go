package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/casbin/casbin/v2"
)

type User struct { //发起操作主体信息
	ProjectId string //参与的项目 id
	UId       string
	GId       string
	Attr      string //a=1,b=2,c=3
}

type Obj struct { //被操作主机信息
	AssetId   string //资产
	AssetGIds string //项目的资产组 id
	AccountId string //账户id
	Service   string //服务 ssh rdp 等
}

type Env struct { //环境信息
	SrcIPNum     int    // 来源 IP
	LocalClient  int    // 是否使用本地客户端
	RemoteClient int    // 是否使用远程客户端
	Time         string // 验证时间
	// todo  其他字段添加
}

type Action struct {
	Action string // 开始运维、文件传输命令、数据库命令等，可在细分
}

type AttrRule struct {
	Key        string
	Comparator string
	Val        string
}

// 授权规则数据结构， 生成一条casbin授权规则
type PermRule struct {
	ProjectId    string     //规则所属项目 id
	UserIds      []string   // * or uid1,uid2
	UserGIds     []string   // gid1,gid2
	UserAttrRule []AttrRule // 用户属性规则

	AssetIds        []string
	AssetGIds       []string
	AssetAttrRule   []AttrRule
	AccountIds      []string
	AccountAttrRule []AttrRule
	Service         string // * or  ssh,rdp

	SrcIPMode       int      //来源 IP 模式
	IPList          []string //限制 IP 列表
	BanLocalClient  bool     // 是否使用本地客户端
	BanRemoteClient bool     //禁止使用远程客户端
	Time            []string // 1-0,1-1,1-2,7-1
}

func (r PermRule) toCasbinPolicy() string {
	// userP := fmt.Sprintf(`"r.user.ProjectId=='%s' && r.user.Uid in (%s)"`,
	// 	r.ProjectId, strings.Join(r.UserIds, ","))

	userP := `"r.user.ProjectId == 'pid' && (r.user.UId in ('uid1', 'uid2') || r.user.GId in ('gid1', 'gid2'))"`
	objP := `"r.obj.AssetId in ('asset1', 'asset2') || r.obj.AssetGId in ('assetgid1', 'assetgid2')"`
	envP := `"(r.env.SrcIPNum > 1 && r.env.SrcIPNum < 10) || (r.env.SrcIPNum > 20 && r.env.SrcIPNum < 30) && r.env.LocalClient == 1"`
	actionP := `"r.act.Action=='op'"`
	return fmt.Sprintf("p, %s, %s, %s, %s, allow", userP, objP, envP, actionP)

}

func abac() {
	pr := PermRule{}
	policyFile := "./conf/test_policy.csv"
	prStr := pr.toCasbinPolicy()
	fmt.Println(prStr)
	if err := ioutil.WriteFile(policyFile, []byte(prStr), 0644); err != nil {
		log.Fatal(0, err)
	}

	e, err := casbin.NewEnforcer("conf/abac_eval_model.conf", policyFile)
	if err != nil {
		log.Fatal(0, err)
	}
	// e.EnableLog(true)

	a := time.Now().UnixMilli()

	ok, err := e.Enforce(
		User{
			ProjectId: "pid",
			UId:       "uid1",
			GId:       "gid1",
		},
		Obj{
			AssetId: "asset1",
		},
		Env{
			SrcIPNum:    5,
			LocalClient: 1,
		},
		Action{
			Action: "op",
		},
	)

	fmt.Printf("Err: %v, Stauts: %v, CostTime: %d ms \n", err, ok, time.Now().UnixMilli()-a)
}

func main() {
	abac()
}
