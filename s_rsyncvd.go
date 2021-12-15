package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

func GetUserList(id int) []string{
	if id==0 {
		USER_LIST := []string{"user", "Administrator", "rsync", "root", "test"}
		return USER_LIST
	}
	PASS_LIST := []string{"", "password", "123456", "12345678", "qwerty", "admin123", "test123", "123456789"}

	return PASS_LIST
}

//十六进制编码转换
func strhex(str string) []byte{
	hex_s:=hex.EncodeToString([]byte(str+"\n"))

	dst := make([]byte, hex.DecodedLen(len(hex_s)))
	n,err:=hex.Decode(dst,[]byte(hex_s))

	if err != nil {
		log.Fatal(err)
		return nil
	}
	return dst[:n]

}


func _init(ip string) []string{

	s :="@RSYNCD: 30.0"

	conn,err:= net.DialTimeout("tcp",ip,8*time.Second)
	defer conn.Close()
	if err!=nil{
		fmt.Println(err)
	}
	//1.init
	_,err =conn.Write(strhex(s))
	if err!=nil{
		fmt.Println(err)
	}

	//2.接收到版本信息
	var rev = make([]byte, 1024)
	_,err =conn.Read(rev)
	if err!=nil{
		fmt.Println(err)
	}

	if err!=nil{
		fmt.Println(err)
	}
	//3.发送回车"\n"
	s ="\n"
	_,err =conn.Write([]byte(s))

	var res = make([]string,10)
	i:=0
	//4.获取模块名
	for true{
		var rev1 = make([]byte, 1024)
		_,err =conn.Read(rev1)
		if err!=nil{
			fmt.Println(err)
		}

		//fmt.Printf("%v %v",len1,string(rev1))
		modulename :=strings.Split(strings.Replace(string(rev1)," ","",len(rev1)),"\n")
		//fmt.Println(modulename)
		for _,v:=range modulename{
			realname := strings.Split(v,"\t")
			if realname[0] != ""{
	//太慢		res=append(res,realname[0])
				res[i]=realname[0]
				i++
			}
		}
		if modulename[len(modulename)-2] =="@RSYNCD:EXIT"{
			break
		}


	}

	//返回模块名
	return res

}

func weak_pass(ip,user,passwd string,mod string) (int,string,error){
	msg := ""
	status:=0
	s :=strhex("@RSYNCD: 30.0")

	conn,err:= net.DialTimeout("tcp",ip,8*time.Second)
	defer conn.Close()
	if err!=nil{
		return status,msg,err
	}
	//1.发送版本信息
	_,err =conn.Write(s)
	if err!=nil{
		return status,msg,err
	}
	var rev = make([]byte, 1024)
	_,err =conn.Read(rev)
	if err!=nil{
		return status,msg,err
	}

//	fmt.Printf("rev: %s\nres: %s\n",rev,mod)
	module :=mod+"\n"

	_,err =conn.Write([]byte(module))

	var rev2 = make([]byte, 1024)
	_,err =conn.Read(rev2) //@RSYNCD: AUTHREQD IEjBYXRtxkX+xYlx5kGfxQ
	if err!=nil{
		return status,msg,err
	}


	//get challenge code
	challenge := strings.Split(string(rev2)," ")
	c:=challenge[len(challenge)-1]
//	fmt.Printf("challenge: %s\n",c)

	//截取字符串
	c1 := strings.Replace(passwd+c," ","",-1)[:28]

	//md5加密
	md :=md5.New()
	md.Write([]byte(c1))
	//md5校验和获取
	str := md.Sum(nil)

	//base64编码
	auth_send_data := base64.StdEncoding.EncodeToString(str)
	//去除 ==
	a:=strings.Replace(auth_send_data,"==","",len(auth_send_data))
	payload := user+" "+a+"\n"

	_,err=conn.Write([]byte(payload))
	if err!=nil{
		return status,msg,err
	}
	var rev3 = make([]byte, 1024)
	_,err =conn.Read(rev3)
	if err!=nil{
		return status,msg,err
	}
	//判断是否爆破成功
	if strings.Contains(string(rev3),"OK"){
		status=1
		if passwd==""{
			msg = "Module: ["+mod+"],User: "+user+",Passwod:<empty>"
		}else{
			msg = "Module: ["+mod+"],User: "+user+",Passwod: "+passwd
		}
	}
	return status,msg,nil
}





func run(ip string,port string){
	users:=GetUserList(0)
	passwd:=GetUserList(1)
	addr :=ip+":"+port
	res :=_init(addr)
	if len(res)==0{
		fmt.Println("no module available")
		return
	}
	lag :=false
	for _,mod:=range res {
		for _, u := range users {
			for _, p := range passwd {
				status, msg, _ := weak_pass(addr, u, p, mod)
				if (status == 1) {
					lag = true
					fmt.Printf("brute successful!\n %s", msg)
					return
				}
			}
		}
	}
	if lag ==false{
		fmt.Println("rsync weakpass not found (brute failed)")
	}
}

func main(){
	run("127.0.0.1","873")
}