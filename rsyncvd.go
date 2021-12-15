package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
)

func chkError(err error) {
	if err != nil {
		log.Fatal(err);
	}
}

func str2Binary(str string) []byte {
	s :=strings.Replace(strings.Replace(str," ","",0),"\n","",0)
	dst := make([]byte, hex.DecodedLen(len(str)))
	n,err:=hex.Decode(dst,[]byte(s))
	if err != nil {
		log.Fatal(err)
		return nil
	}
	return dst[:n]
}

func rsyncCheck(ip string) bool{
	conn,err := net.ResolveTCPAddr("tcp",ip)
	chkError(err)

	//DialTCP建立一个TCP连接
	tcpconn, err1 := net.DialTCP("tcp", nil,conn);
	chkError(err1)

	helloString := "405253594e43443a2033312e300a"
	//向tcpconn中写入数据
	_,err2 :=tcpconn.Write(str2Binary(helloString))
	chkError(err2)
	//读取tcpconn中的所有数据
	var rev = make([]byte, 1024)
	_,err3:=tcpconn.Read(rev)
	chkError(err3)

	if strings.Contains(string(rev),"@RSYNCD")==true{
		_,err := tcpconn.Write(str2Binary("0a"))
		chkError(err)
		for true{
			var rev = make([]byte, 1024)
			len,err:=tcpconn.Read(rev)
			//readdata,err:=ioutil.ReadAll(tcpconn)
			chkError(err)
			if len == 0{
				return false
			}else{
				if strings.Contains(string(rev),"@RSYNCD: EXIT"){
					fmt.Println("发现漏洞")
					return true
				}
			}
		}
	}
	return false

}

func main(){
	rsyncCheck("127.0.0.1:873")

}
