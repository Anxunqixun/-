import requests
import base64
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import ddddocr
cookies = {
        'JSESSIONID': 'CF95413790C32F2CDE75E6167AE78680',
        'ut': 'CLkKl4dD0R78lX78a6Hm4gLl73Z7gZkxqvMQkyUEiZ4=',
    }
def getPho():

    headers = {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0',
    }

    json_data = {
        'captchaType': 'blockPuzzle',
        'clientUid': 'slider-6ca72150-bf24-45b5-838a-a272b2650484',
        'ts': int(time.time() * 1000),
    }
    response = requests.post('https://www.fgnwct.com/captcha/get', cookies=cookies, headers=headers, json=json_data).json()
    print(response['success'])
    base64_to_image_simple(response['repData']['jigsawImageBase64'], "hk.png")
    base64_to_image_simple(response['repData']['originalImageBase64'], "bg.png")
    return response['repData']['token'],response['repData']['secretKey']
def base64_to_image_simple(base64_data, filename="output.png"):
    """
    将纯Base64数据保存为图片文件

    参数:
    base64_data: 纯Base64编码的图片数据（没有前缀）
    filename: 输出文件名
    """
    try:
        # 直接解码Base64
        image_data = base64.b64decode(base64_data)

        # 写入文件
        with open(filename, 'wb') as f:
            f.write(image_data)

        print(f"图片已保存到: {filename}")
        return True

    except Exception as e:
        print(f"转换失败: {e}")
        return False
def aes_encrypt(d, e):
    """
    完全等效于JavaScript的aesEncrypt函数

    参数:
    d: 要加密的字符串
    e: 密钥字符串

    返回:
    Base64编码的加密结果
    """
    # 等效于 CryptoJS.enc.Utf8.parse(e)
    # 直接将UTF-8字符串转换为字节
    key_bytes = e.encode('utf-8')

    # 等效于 CryptoJS.enc.Utf8.parse(d)
    # 直接将UTF-8字符串转换为字节
    data_bytes = d.encode('utf-8')

    # 在ECB模式下，CryptoJS会自动处理密钥长度
    # 我们需要确保密钥是有效的AES密钥长度（16, 24, 32字节）
    # 如果密钥长度不符合，CryptoJS会使用SHA256哈希派生密钥
    # 但根据原始代码，它直接使用UTF-8解析，所以我们也直接使用

    # 创建AES cipher (ECB模式)
    cipher = AES.new(key_bytes, AES.MODE_ECB)

    # 使用PKCS7填充（在PyCryptodome中pad函数使用PKCS7）
    padded_data = pad(data_bytes, AES.block_size)

    # 加密数据
    encrypted_data = cipher.encrypt(padded_data)

    # 等效于 b.toString() - 返回Base64字符串
    return base64.b64encode(encrypted_data).decode('utf-8')
def get_pointJson():
    token,secretKey=getPho()
    print(token,secretKey)

    det = ddddocr.DdddOcr(det=False,ocr=False,show_ad=False)
    with open('hk.png', 'rb') as f:
        target_bytes = f.read()
    with open('bg.png', 'rb') as f:
        background_bytes = f.read()
    res = det.slide_match(target_bytes, background_bytes, simple_target=True)['target'][0]
#     res=1
    data = f'{{"x":{res},"y":5}}'
    # secretKey="ExAdIYxyy58JpNLh"
    result = aes_encrypt(data, secretKey)
    print(f"加密结果: {result}")
    return token,result,data,secretKey
def check(token,pj):

    headers = {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0',
    }

    json_data = {
        'captchaType': 'blockPuzzle',
        'pointJson': pj,
        'token':token,
        'clientUid': 'slider-6ca72150-bf24-45b5-838a-a272b2650484',
        'ts': int(time.time() * 1000),
    }

    response = requests.post('https://www.fgnwct.com/captcha/check', cookies=cookies, headers=headers, json=json_data).json()
    print(response)
    return response['repData']['token']#其实和原始token一样
def send(captchaVerification):
    headers = {
        'Referer': 'https://www.fgnwct.com/dashboard.html',
        'X-Requested-With': 'XMLHttpRequest',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Content-Type': 'application/json;charset=UTF-8',
    }

    json_data = {
        'captchaVerification':captchaVerification,
    }

    response = requests.post('https://www.fgnwct.com/signIn', headers=headers, json=json_data,cookies=cookies)
    print(response.text)
token,pj,w,sk=get_pointJson()
# print(token,pj)
rtoken=check(token,pj)

print(rtoken)
#获取验证码加密数据
send(aes_encrypt( rtoken+ "---" +w,sk ))
