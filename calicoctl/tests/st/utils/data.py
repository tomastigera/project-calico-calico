# Copyright (c) 2015-2021 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Various test data that may be shared across multiple tests.
# Naming follows the approximate format:
#
# <kind>_name<idx>_rev<revision>_<key attributes>
#
# Incrementing name indexes indicate the order in which they would be listed.
#
# The rev (a-z) indicates that it should be possible to switch between different
# revisions of the same data.
#
# The key attributes provide some useful additional data, for example (a v4 specific
# resource).
import netaddr

from utils import API_VERSION

# Large list of CIDRs for testing truncation of certain fields.
many_nets = []
for i in xrange(10000):
    many_nets.append("10.%s.%s.0/28" % (i >> 8, i % 256))


#
# Calico Enterprise Licenses
#

valid_cnx_license_expires_september_02_2021 = {
    'apiVersion': API_VERSION,
    'kind': 'LicenseKey',
    'metadata': {
        'name': 'default'
    },
    'spec': {
        'certificate': """
-----BEGIN CERTIFICATE-----
MIIFxjCCA66gAwIBAgIQVq3rz5D4nQF1fIgMEh71DzANBgkqhkiG9w0BAQsFADCB
tTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xFDASBgNVBAoTC1RpZ2VyYSwgSW5jMSIwIAYDVQQLDBlTZWN1
cml0eSA8c2lydEB0aWdlcmEuaW8+MT8wPQYDVQQDEzZUaWdlcmEgRW50aXRsZW1l
bnRzIEludGVybWVkaWF0ZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTgwNDA1
MjEzMDI5WhcNMjAxMDA2MjEzMDI5WjCBnjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
CkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xFDASBgNVBAoTC1Rp
Z2VyYSwgSW5jMSIwIAYDVQQLDBlTZWN1cml0eSA8c2lydEB0aWdlcmEuaW8+MSgw
JgYDVQQDEx9UaWdlcmEgRW50aXRsZW1lbnRzIENlcnRpZmljYXRlMIIBojANBgkq
hkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAwg3LkeHTwMi651af/HEXi1tpM4K0LVqb
5oUxX5b5jjgi+LHMPzMI6oU+NoGPHNqirhAQqK/k7W7r0oaMe1APWzaCAZpHiMxE
MlsAXmLVUrKg/g+hgrqeije3JDQutnN9h5oZnsg1IneBArnE/AKIHH8XE79yMG49
LaKpPGhpF8NoG2yoWFp2ekihSohvqKxa3m6pxoBVdwNxN0AfWxb60p2SF0lOi6B3
hgK6+ILy08ZqXefiUs+GC1Af4qI1jRhPkjv3qv+H1aQVrq6BqKFXwWIlXCXF57CR
hvUaTOG3fGtlVyiPE4+wi7QDo0cU/+Gx4mNzvmc6lRjz1c5yKxdYvgwXajSBx2pw
kTP0iJxI64zv7u3BZEEII6ak9mgUU1CeGZ1KR2Xu80JiWHAYNOiUKCBYHNKDCUYl
RBErYcAWz2mBpkKyP6hbH16GjXHTTdq5xENmRDHabpHw5o+21LkWBY25EaxjwcZa
Y3qMIOllTZ2iRrXu7fSP6iDjtFCcE2bFAgMBAAGjZzBlMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUIY7LzqNTzgyTBE5efHb5
kZ71BUEwHwYDVR0jBBgwFoAUxZA5kifzo4NniQfGKb+4wruTIFowDQYJKoZIhvcN
AQELBQADggIBAAK207LaqMrnphF6CFQnkMLbskSpDZsKfqqNB52poRvUrNVUOB1w
3dSEaBUjhFgUU6yzF+xnuH84XVbjD7qlM3YbdiKvJS9jrm71saCKMNc+b9HSeQAU
DGY7GPb7Y/LG0GKYawYJcPpvRCNnDLsSVn5N4J1foWAWnxuQ6k57ymWwcddibYHD
OPakOvO4beAnvax3+K5dqF0bh2Np79YolKdIgUVzf4KSBRN4ZE3AOKlBfiKUvWy6
nRGvu8O/8VaI0vGaOdXvWA5b61H0o5cm50A88tTm2LHxTXynE3AYriHxsWBbRpoM
oFnmDaQtGY67S6xGfQbwxrwCFd1l7rGsyBQ17cuusOvMNZEEWraLY/738yWKw3qX
U7KBxdPWPIPd6iDzVjcZrS8AehUEfNQ5yd26gDgW+rZYJoAFYv0vydMEyoI53xXs
cpY84qV37ZC8wYicugidg9cFtD+1E0nVgOLXPkHnmc7lIDHFiWQKfOieH+KoVCbb
zdFu3rhW31ygphRmgszkHwApllCTBBMOqMaBpS8eHCnetOITvyB4Kiu1/nKvVxhY
exit11KQv8F3kTIUQRm0qw00TSBjuQHKoG83yfimlQ8OazciT+aLpVaY8SOrrNnL
IJ8dHgTpF9WWHxx04DDzqrT7Xq99F9RzDzM7dSizGxIxonoWcBjiF6n5
-----END CERTIFICATE-----
""",
        'token': 'eyJhbGciOiJBMTI4R0NNS1ciLCJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJTZGUtWW1KV0pIcTNWREJ3IiwidGFnIjoiOGF2UVZEVHptME9mRGlVM2hfRlhYQSIsInR5cCI6IkpXVCJ9.nZK7QAqo3Jfa3LjUPtFHmw.Y_QN4NvAH0GmSMO9.bMxJ4AtoIF7uLShaSRXDL6cGXUq4kPVQjsh_dFndWud3fjSn1S7q09HcnTHKNmTupCsmStSB_lV363Ar9ShrV8WRebZeKZYqB4OOMzbj89fiTPPPA0AlqxrlEMnHyQYefyp_Kjy_eymHoaiZBzIiHZgKBDP4Dh6lhrMThUMaer6iKo_iMjtI-zRlAQ0_eMAcxRyiyFFIbUdUcy3uMz1UBQFLlm7YMslRBRzvf8gT__Ptihjll0KsxyGtivzYEwgOZ4lheWr1Af5nmslNQP9mR6MOF4TeSik3_yzq6TP3mgUol5HNCWyNB9-o-uqk9Wn0mQG3uy1ERJCMHNPKoUrvSTA5DiF7QeN8YR2h1C36ehcGLYi9L9jj1nT2JOO-uFagTdJeGH3lRQnF6RYkyfw-kitHuac8Ghte-YZNvXTmRBp7wT_L-X89-FcT4XveW5va0ChVOdl7aKAlkf8GDl3gZEkz22eVtZAnFEp6N-ApSasFA-3clqTulSlsLL4WkQ_Vin3lMEr11cYl2VFnQovLw3F30vrB2XEyjEiGRw86R4PRfxlYkHDgK7FhGgFb1UM4lmZUCycExzSYYpDd3oQBFEDR_fhZ0oq6Fp7SUeA6ypFL_Hph1NB0kf5emGnq4R2vr-T4BuM8YYe9Qa6OuVtf2U3o3ipCqdsAAHII0GhlLJWCs5ovNPOEbS_ky_0mLW8mvzfHnPqGL3HjZA2DZb0pZlqI7qbmwiO8N9iU5uZA0RsHJX_ClDF971m2LoUQAbe2I0rCtrhVhW5ljQPuJSTv0chLSDCPxk0-jEsTpA12dqK3eiyT-hWyTTXb2ZsivBdCIpOpVbZM2z2EvvEMvsN3lLCHGP61i0C0KPlze9DJE6vZVxAW1nzqRqi1IqU5mfZuoX8McbQiAEzBQ096hvypIygBmVTr17N8sXmHwJPNEdiLQ3pTLfyHBGZDyZlpy2Ej-4mG-Iegg8hjTkEm3q7QHzRL8hWTP0ff7MHT1NOXkSbN_bIpLmtjb75-we3Mc2cBPyyV96D89G16UUGkh0lzy0pLMMbz_ejSbKlULFkJJWRGn_58Hkw1ROBeREccg_F5B0wqLKY__jyq1OqrzcIZrxhUPLaWfoDKzSykDw.yeAEkIEd1wSwvuwgHs_6dw'
    }
}

valid_cnx_license_expires_november_01_2020 = {
    'apiVersion': API_VERSION,
    'kind': 'LicenseKey',
    'metadata': {
        'name': 'default'
    },
    'spec': {
        'certificate': """
-----BEGIN CERTIFICATE-----
MIIFxjCCA66gAwIBAgIQVq3rz5D4nQF1fIgMEh71DzANBgkqhkiG9w0BAQsFADCB
tTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xFDASBgNVBAoTC1RpZ2VyYSwgSW5jMSIwIAYDVQQLDBlTZWN1
cml0eSA8c2lydEB0aWdlcmEuaW8+MT8wPQYDVQQDEzZUaWdlcmEgRW50aXRsZW1l
bnRzIEludGVybWVkaWF0ZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTgwNDA1
MjEzMDI5WhcNMjAxMDA2MjEzMDI5WjCBnjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
CkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xFDASBgNVBAoTC1Rp
Z2VyYSwgSW5jMSIwIAYDVQQLDBlTZWN1cml0eSA8c2lydEB0aWdlcmEuaW8+MSgw
JgYDVQQDEx9UaWdlcmEgRW50aXRsZW1lbnRzIENlcnRpZmljYXRlMIIBojANBgkq
hkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAwg3LkeHTwMi651af/HEXi1tpM4K0LVqb
5oUxX5b5jjgi+LHMPzMI6oU+NoGPHNqirhAQqK/k7W7r0oaMe1APWzaCAZpHiMxE
MlsAXmLVUrKg/g+hgrqeije3JDQutnN9h5oZnsg1IneBArnE/AKIHH8XE79yMG49
LaKpPGhpF8NoG2yoWFp2ekihSohvqKxa3m6pxoBVdwNxN0AfWxb60p2SF0lOi6B3
hgK6+ILy08ZqXefiUs+GC1Af4qI1jRhPkjv3qv+H1aQVrq6BqKFXwWIlXCXF57CR
hvUaTOG3fGtlVyiPE4+wi7QDo0cU/+Gx4mNzvmc6lRjz1c5yKxdYvgwXajSBx2pw
kTP0iJxI64zv7u3BZEEII6ak9mgUU1CeGZ1KR2Xu80JiWHAYNOiUKCBYHNKDCUYl
RBErYcAWz2mBpkKyP6hbH16GjXHTTdq5xENmRDHabpHw5o+21LkWBY25EaxjwcZa
Y3qMIOllTZ2iRrXu7fSP6iDjtFCcE2bFAgMBAAGjZzBlMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUIY7LzqNTzgyTBE5efHb5
kZ71BUEwHwYDVR0jBBgwFoAUxZA5kifzo4NniQfGKb+4wruTIFowDQYJKoZIhvcN
AQELBQADggIBAAK207LaqMrnphF6CFQnkMLbskSpDZsKfqqNB52poRvUrNVUOB1w
3dSEaBUjhFgUU6yzF+xnuH84XVbjD7qlM3YbdiKvJS9jrm71saCKMNc+b9HSeQAU
DGY7GPb7Y/LG0GKYawYJcPpvRCNnDLsSVn5N4J1foWAWnxuQ6k57ymWwcddibYHD
OPakOvO4beAnvax3+K5dqF0bh2Np79YolKdIgUVzf4KSBRN4ZE3AOKlBfiKUvWy6
nRGvu8O/8VaI0vGaOdXvWA5b61H0o5cm50A88tTm2LHxTXynE3AYriHxsWBbRpoM
oFnmDaQtGY67S6xGfQbwxrwCFd1l7rGsyBQ17cuusOvMNZEEWraLY/738yWKw3qX
U7KBxdPWPIPd6iDzVjcZrS8AehUEfNQ5yd26gDgW+rZYJoAFYv0vydMEyoI53xXs
cpY84qV37ZC8wYicugidg9cFtD+1E0nVgOLXPkHnmc7lIDHFiWQKfOieH+KoVCbb
zdFu3rhW31ygphRmgszkHwApllCTBBMOqMaBpS8eHCnetOITvyB4Kiu1/nKvVxhY
exit11KQv8F3kTIUQRm0qw00TSBjuQHKoG83yfimlQ8OazciT+aLpVaY8SOrrNnL
IJ8dHgTpF9WWHxx04DDzqrT7Xq99F9RzDzM7dSizGxIxonoWcBjiF6n5
-----END CERTIFICATE-----
""",
        'token': """eyJhbGciOiJBMTI4R0NNS1ciLCJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJ1U0lXUkNJd3dwS1U3ZTlFIiwidGFnIjoiaHNvVDF2VG9KNjk0UktpdTBjTEltdyIsInR5cCI6IkpXVCJ9.f78MAwbJiOvFIPUpmYnVeQ.gu8Lk2C1x550ib32.Q9Qbog_J12XFDOYg_DN4qTzcqz5r7O8j-F6epi0YmlDQUjXH__tmE8ScHB1JiQzCG7NnGx3zLDrN1GKI4iubSZX33MNLET_qr42pz9DqlDGfbIsQexGu1UoC5pRdAgE4Wjht3hO9bUlEKXT-NDUr_urqNNsPWdKYx9FeJEIT4QRr8MBYGoDQi_bTBfku7gfZZ8WKudyBWK6giRclsGhdvcTXgzg8Gmt8fqiWto_qUn0BEoBuzN9_HciQgudYEsUHEX1RgQae5KseqsIECeRT0OQK7TvFHQkhJ82E6bU5_QOffV2O59XmNpRC8fGIIzoGvHvFIiAGq4Zfja1CYi5E3rFhTTML183CcXm2XFbtAJac0td742EUhLxAB-UCk_r0kY9n8pfMKzhxwZ7CMHXhrdUFo4M_0tyYGz5T9pnYq04szzekbIePx8IRDwz54wKUfAD9KfqjZoOZaiYH9Uds8z8Oix8MfSMx-2g4BZGEFxGLLu2ZDD3nHgzAv0AjJudOj63jsUmBrcc3UeQ_Z1r2MM4L--zhDFwqTk8OiZSGt4mtOUuLFvW167IXHpTwoEhxp9_eNrtAdRGNv9S_7wImNaYkmI5jL7-jCxgZIIIESE4k-XC-GE2mfMCNlyxqF0XzLcYBUMjdVxlhQwpOVD7aRoL7FSblpNGdUFJLYr7wQJynVRS3lBtkUlyIzE2Ic9oYdfmawCDmUqP9FsR0aDPkVgvm8UoUhCo62Xxb95Eb1PUqJocpT0C6rCp4sleK-wpU5dmY-9mkwYF_n1HcGs8SjnKTG5lGHIwMn7A-Y6-CfprUHD2egsjFqu6s0ME3V9bZ6KM3YMjZeKVJTU4UZ6LjnKp-Bms8jeEleayRVDdeKCejzxjv7m2lsN1kcFTnjTwvAm7QC-99xrgfK7cbEYjyGZRoecmKzK3YM6mI9SmdJIUvhzKieB2ACk37oaXSgQN5udsSBFoa5SGzbKhxjvaXx46_Sm2FRHPMO5A5cCE6nmjlGG4qbz25UlHdv3ojITOqKFHEj2VMJXgBawIHxGWSGjY8t4PxC8PHy9wcNKhQRZdAtzjQ6IKBSytFpxMYAg.Uw0iQ6VZYMtWjz6K26PbOw""",
    }
}

expired_cnx_license = {
    'apiVersion': API_VERSION,
    'kind': 'LicenseKey',
    'metadata': {
        'name': 'default'
    },
    'spec': {
        'certificate': """"
-----BEGIN CERTIFICATE-----
MIIFxjCCA66gAwIBAgIQVq3rz5D4nQF1fIgMEh71DzANBgkqhkiG9w0BAQsFADCB
tTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xFDASBgNVBAoTC1RpZ2VyYSwgSW5jMSIwIAYDVQQLDBlTZWN1
cml0eSA8c2lydEB0aWdlcmEuaW8+MT8wPQYDVQQDEzZUaWdlcmEgRW50aXRsZW1l
bnRzIEludGVybWVkaWF0ZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTgwNDA1
MjEzMDI5WhcNMjAxMDA2MjEzMDI5WjCBnjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
CkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xFDASBgNVBAoTC1Rp
Z2VyYSwgSW5jMSIwIAYDVQQLDBlTZWN1cml0eSA8c2lydEB0aWdlcmEuaW8+MSgw
JgYDVQQDEx9UaWdlcmEgRW50aXRsZW1lbnRzIENlcnRpZmljYXRlMIIBojANBgkq
hkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAwg3LkeHTwMi651af/HEXi1tpM4K0LVqb
5oUxX5b5jjgi+LHMPzMI6oU+NoGPHNqirhAQqK/k7W7r0oaMe1APWzaCAZpHiMxE
MlsAXmLVUrKg/g+hgrqeije3JDQutnN9h5oZnsg1IneBArnE/AKIHH8XE79yMG49
LaKpPGhpF8NoG2yoWFp2ekihSohvqKxa3m6pxoBVdwNxN0AfWxb60p2SF0lOi6B3
hgK6+ILy08ZqXefiUs+GC1Af4qI1jRhPkjv3qv+H1aQVrq6BqKFXwWIlXCXF57CR
hvUaTOG3fGtlVyiPE4+wi7QDo0cU/+Gx4mNzvmc6lRjz1c5yKxdYvgwXajSBx2pw
kTP0iJxI64zv7u3BZEEII6ak9mgUU1CeGZ1KR2Xu80JiWHAYNOiUKCBYHNKDCUYl
RBErYcAWz2mBpkKyP6hbH16GjXHTTdq5xENmRDHabpHw5o+21LkWBY25EaxjwcZa
Y3qMIOllTZ2iRrXu7fSP6iDjtFCcE2bFAgMBAAGjZzBlMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUIY7LzqNTzgyTBE5efHb5
kZ71BUEwHwYDVR0jBBgwFoAUxZA5kifzo4NniQfGKb+4wruTIFowDQYJKoZIhvcN
AQELBQADggIBAAK207LaqMrnphF6CFQnkMLbskSpDZsKfqqNB52poRvUrNVUOB1w
3dSEaBUjhFgUU6yzF+xnuH84XVbjD7qlM3YbdiKvJS9jrm71saCKMNc+b9HSeQAU
DGY7GPb7Y/LG0GKYawYJcPpvRCNnDLsSVn5N4J1foWAWnxuQ6k57ymWwcddibYHD
OPakOvO4beAnvax3+K5dqF0bh2Np79YolKdIgUVzf4KSBRN4ZE3AOKlBfiKUvWy6
nRGvu8O/8VaI0vGaOdXvWA5b61H0o5cm50A88tTm2LHxTXynE3AYriHxsWBbRpoM
oFnmDaQtGY67S6xGfQbwxrwCFd1l7rGsyBQ17cuusOvMNZEEWraLY/738yWKw3qX
U7KBxdPWPIPd6iDzVjcZrS8AehUEfNQ5yd26gDgW+rZYJoAFYv0vydMEyoI53xXs
cpY84qV37ZC8wYicugidg9cFtD+1E0nVgOLXPkHnmc7lIDHFiWQKfOieH+KoVCbb
zdFu3rhW31ygphRmgszkHwApllCTBBMOqMaBpS8eHCnetOITvyB4Kiu1/nKvVxhY
exit11KQv8F3kTIUQRm0qw00TSBjuQHKoG83yfimlQ8OazciT+aLpVaY8SOrrNnL
IJ8dHgTpF9WWHxx04DDzqrT7Xq99F9RzDzM7dSizGxIxonoWcBjiF6n5
-----END CERTIFICATE-----
""",
        'token': """eyJhbGciOiJBMTI4R0NNS1ciLCJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiI3TEJ4V25la3pxSUpuUG9IIiwidGFnIjoiLWEtckU5WF91XzYxN19lLVBEM3BTQSIsInR5cCI6IkpXVCJ9.eVobQYlAvtmi0Tt1FqR_CA.Z0ciTbMAXOOtQlI7.FxlTyVwYSnCZL6a-RJDv91m7YbCAEBMxiZkhHIuEmSQ2WFi_viZCY6MhL_GigX2-q2z1a8JErTUnpO0FZLrgO-HkA4zvF1egbHc96W2h-HC_4b4SVWjaLVvzrdNHDRDmFyXqxb9UYmFoBchlVgfPJ9IIY6R1LiNVO3H8Kt-OIExSFRWd8KwmeR34IGyTfkXQlMtl4YVGbaqgrpIw-vpeOm7vyj8xzKZbOna9QsAOi0241CkOqoFaL2bK4G6RJ6FhwDGxuUxupFHGPEFs27Nyfh6Fsk-TRcO0CHd0iiuIg9KBNQqew6niAcVFFo52GMlkQsctLzdKu94eIXu7XVsHtanoupkOceOUeGMy7VI_TW4iD684cti3q87jYoCez_fT2tLlINR92OaLbY3eL49Bn5JFnYSsao7trAqp7YKfDKgTI9DcxKTUoGleW9reBHWkaVtz5NEL_PEcPK6LZn6ZgEFcGzdUzWkZcjiq08joqpNhfRFT7H_GofK0_9kR2CIYKt2PsfZPqNs9xEHwmXH5tTgZBx4cez9zZLOTo_8oJsr8ky4ZRGlth_gBi_zovlkOG0DtFPcbOo09OVh1fpxejtZRGvFSUiQs9tUdqfpzQ2xdiC8HXfT-vYCAxvVbH0_a-yjEshX6Leqghr2jUCoXB5pjVlot6NkLGNI6BCRqbga9C3rc8q_v_zX3TYm_gBOIqS_CdNJoz3e5H3dZpPxjatkB7qdO1FWaA0gPIYf4GRw_TyMZ_Z93kQLYN66BBudawOyO1Z1YTCKHcac3vl-LCzo--LlGcSGCle-JM-a-9aZ899sd8sxREd5ocKocDSqzGIO8mOz1l6vJOb79LW-nZ80F8TD5oqvEXwRBKty1QEdHWeFqYd7LaOS-aG5f-ue_u9KvB_eJPeZP0KYt11xCbVbkQyI6DOwu_vy90ckZxdldD_BorKWQNmYayCXBnJDupwjACCJfoO6GoBenORrQ2riDLePym_zLWj-zKx__oaBED0MYDVJFwfK24MpJpYLTv5zjStz4vbBgYssDtjkNyU0tHpf3m9L8jOm65VFqphLtevX9d77VqLftejnhOQGWnGann4Q_L6Ekt2C5Hwg.7Dj__9_b3lccD9TWb1HVPA""",
    }
}

#
# IPPools
#
ippool_name1_rev1_v4 = {
    'apiVersion': API_VERSION,
    'kind': 'IPPool',
    'metadata': {
        'name': 'ippool-name1'
    },
    'spec': {
        'cidr': "10.0.1.0/24",
        'ipipMode': 'Always',
        'vxlanMode': 'Never',
        'blockSize': 27,
        'allowedUses': ["Workload", "Tunnel"],
        'assignmentMode': 'Automatic',
        'nodeSelector': "foo == 'bar'",
    }
}

ippool_name1_rev1_table = (
    "NAME           CIDR          SELECTOR       \n"
    "ippool-name1   10.0.1.0/24   foo == 'bar'"
)

ippool_name1_rev1_wide_table = (
    "NAME           CIDR          NAT     IPIPMODE   VXLANMODE   DISABLED   DISABLEBGPEXPORT   SELECTOR       ASSIGNMENTMODE   \n"
    "ippool-name1   10.0.1.0/24   false   Always     Never       false      false              foo == 'bar'   Automatic"
)

ippool_name1_rev2_v4 = {
    'apiVersion': API_VERSION,
    'kind': 'IPPool',
    'metadata': {
        'name': 'ippool-name1'
    },
    'spec': {
        'cidr': "10.0.1.0/24",
        'ipipMode': 'Never',
        'vxlanMode': 'Always',
        'allowedUses': ["Workload", "Tunnel"],
        'nodeSelector': "all()",
    }
}

ippool_name1_rev3_v4 = {
    'apiVersion': API_VERSION,
    'kind': 'IPPool',
    'metadata': {
        'name': 'ippool-name1'
    },
    'spec': {
        'cidr': "10.0.1.0/24",
        'ipipMode': 'Always',
        'vxlanMode': 'Never',
        'blockSize': 27,
        'allowedUses': ["Workload", "Tunnel"],
        'nodeSelector': "foo == 'bar'",
        'disabled': True,
    }
}

ippool_name1_rev4_v4 = {
    'apiVersion': API_VERSION,
    'kind': 'IPPool',
    'metadata': {
        'name': 'ippool-name1',
        'labels': {'test-label': 'label-1'},
        'annotations': {'test-annotation': 'annotation-1'},
    },
    'spec': {
        'cidr': "10.0.1.0/24",
        'ipipMode': 'Always',
        'vxlanMode': 'Never',
        'blockSize': 27,
        'allowedUses': ["Workload", "Tunnel"],
        'nodeSelector': "foo == 'bar'",
        'disabled': True,
    }
}

ippool_name1_rev1_split1_v4 = {
    'apiVersion': API_VERSION,
    'kind': 'IPPool',
    'metadata': {
        'name': 'split-ippool-name1-0'
    },
    'spec': {
        'cidr': "10.0.1.0/26",
        'ipipMode': 'Always',
        'vxlanMode': 'Never',
        'blockSize': 27,
        'allowedUses': ["Workload", "Tunnel"],
        'assignmentMode': 'Automatic',
        'nodeSelector': "foo == 'bar'",
    }
}

ippool_name1_rev1_split2_v4 = {
    'apiVersion': API_VERSION,
    'kind': 'IPPool',
    'metadata': {
        'name': 'split-ippool-name1-1'
    },
    'spec': {
        'cidr': "10.0.1.64/26",
        'ipipMode': 'Always',
        'vxlanMode': 'Never',
        'blockSize': 27,
        'allowedUses': ["Workload", "Tunnel"],
        'assignmentMode': 'Automatic',
        'nodeSelector': "foo == 'bar'",
    }
}

ippool_name1_rev1_split3_v4 = {
    'apiVersion': API_VERSION,
    'kind': 'IPPool',
    'metadata': {
        'name': 'split-ippool-name1-2'
    },
    'spec': {
        'cidr': "10.0.1.128/26",
        'ipipMode': 'Always',
        'vxlanMode': 'Never',
        'blockSize': 27,
        'allowedUses': ["Workload", "Tunnel"],
        'assignmentMode': 'Automatic',
        'nodeSelector': "foo == 'bar'",
    }
}

ippool_name1_rev1_split4_v4 = {
    'apiVersion': API_VERSION,
    'kind': 'IPPool',
    'metadata': {
        'name': 'split-ippool-name1-3'
    },
    'spec': {
        'cidr': "10.0.1.192/26",
        'ipipMode': 'Always',
        'vxlanMode': 'Never',
        'blockSize': 27,
        'allowedUses': ["Workload", "Tunnel"],
        'assignmentMode': 'Automatic',
        'nodeSelector': "foo == 'bar'",
    }
}

ippool_name2_rev1_v6 = {
    'apiVersion': API_VERSION,
    'kind': 'IPPool',
    'metadata': {
        'name': 'ippool-name2'
    },
    'spec': {
        'cidr': "fed0:8001::/64",
        'ipipMode': 'Never',
        'vxlanMode': 'Never',
        'blockSize': 123,
        'allowedUses': ["Workload", "Tunnel"],
        'assignmentMode': 'Automatic',
        'nodeSelector': "all()",
    }
}

ippool_name2_rev1_table = (
    "NAME           CIDR             SELECTOR   \n"
    "ippool-name2   fed0:8001::/64   all()"
)

#
# IP Reservations
#

ipresv_name1_rev1_v4 = {
    'apiVersion': API_VERSION,
    'kind': 'IPReservation',
    'metadata': {
        'name': 'ipreservation-name1'
    },
    'spec': {
        'reservedCIDRs': ["10.0.1.0/24", "11.0.0.1/32"],
    }
}

ipresv_name1_rev1_v4_long = {
    'apiVersion': API_VERSION,
    'kind': 'IPReservation',
    'metadata': {
        'name': 'ipreservation-name1'
    },
    'spec': {
        'reservedCIDRs': many_nets,
    }
}

#
# BGP filters
#

bgpfilter_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'BGPFilter',
    'metadata': {
        'name': 'bgpfilter-name1'
    },
    'spec': {
        'exportv4': [
            {
                'cidr': '10.0.0.0/16',
                'matchOperator': 'Equal',
                'action': 'Accept',
            },
        ],
    }
}


#
# BGPPeers
#
bgppeer_name1_rev1_v4 = {
    'apiVersion': API_VERSION,
    'kind': 'BGPPeer',
    'metadata': {
        'name': 'bgppeer-name-123abc',
    },
    'spec':  {
        'node': 'node1',
        'peerIP': '192.168.0.250',
        'asNumber': 64514,
    },
}

bgppeer_name1_rev2_v4 = {
    'apiVersion': API_VERSION,
    'kind': 'BGPPeer',
    'metadata': {
        'name': 'bgppeer-name-123abc',
    },
    'spec':  {
        'node': 'node2',
        'peerIP': '192.168.0.251',
        'asNumber': 64515,
    },
}

bgppeer_name2_rev1_v6 = {
    'apiVersion': API_VERSION,
    'kind': 'BGPPeer',
    'metadata': {
        'name': 'bgppeer-name-456def',
    },
    'spec': {
        'node': 'node2',
        'peerIP': 'fd5f::6:ee',
        'asNumber': 64590,
    },
}

bgppeer_invalid = {
    'apiVersion': API_VERSION,
    'kind': 'BGPPeer',
    'metadata': {
        'name': 'bgppeer-name-123abc',
    },
    'spec':  {
        'node': 'node2',
        'peerIP': 'badpeerIP',
        'asNumber': 64515,
    },
}

bgppeer_multiple_invalid = [{
    'apiVersion': API_VERSION,
    'kind': 'BGPPeer',
    'metadata': {
        'name': 'bgppeer-invalid1',
    },
    'spec':  {
        'node': 'node1',
        'peerIP': 'badpeerIP',
        'asNumber': 64515,
    },
}, {
    'apiVersion': API_VERSION,
    'kind': 'BGPPeer',
    'metadata': {
        'name': 'bgppeer-invalid2',
    },
    'spec':  {
        'node': 'node2',
        'peerIP': 'badpeerIP',
        'asNumber': 64515,
    }
}]

#
# Tier1
#

tier_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'Tier',
    'metadata': {
        'name': 'admin',
    },
    'spec': {
        'Order': 10000,
    },
}

tier_name2_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'Tier',
    'metadata': {
        'name': 'before',
    },
    'spec': {
        'Order': 100,
    },
}

#
# Network Policy
#
networkpolicy_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'NetworkPolicy',
    'metadata': {
        'name': 'default.policy-mypolicy1',
        'namespace': 'default'
    },
    'spec': {
        'tier': 'default',
        'order': 100,
        'selector': "type=='database'",
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Allow',
                'source': {
                    'selector': "type=='application'"},
            },
        ],
        'ingress': [
            {
                'ipVersion': 4,
                'action': 'Deny',
                'destination': {
                    'notNets': ['10.3.0.0/16'],
                    'notPorts': ['110:1050'],
                    'notSelector': "type=='apples'",
                    'nets': ['10.2.0.0/16'],
                    'ports': ['100:200'],
                    'selector': "type=='application'",
                },
                'protocol': 'TCP',
                'source': {
                    'notNets': ['10.1.0.0/16'],
                    'notPorts': [1050],
                    'notSelector': "type=='database'",
                    'nets': ['10.0.0.0/16'],
                    'ports': [1234, '10:1024'],
                    'selector': "type=='application'",
                    'namespaceSelector': 'has(role)',
                }
            }
        ],
    }
}

networkpolicy_name1_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'NetworkPolicy',
    'metadata': {
        'name': 'default.policy-mypolicy1',
        'namespace': 'default'
    },
    'spec': {
        'tier': "default",
        'order': 100000,
        'selector': "type=='sql'",
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Deny',
                'protocol': 'TCP',
            },
        ],
        'ingress': [
            {
                'action': 'Allow',
                'protocol': 'UDP',
            },
        ],
    }
}

networkpolicy_name2_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'NetworkPolicy',
    'metadata': {
        'name': 'default.policy-mypolicy2',
        'namespace': 'default',
        'generateName': 'test-policy-',
        'deletionTimestamp': '2006-01-02T15:04:07Z',
        'deletionGracePeriodSeconds': 30,
        'ownerReferences': [{
            'apiVersion': 'extensions/v1beta1',
            'blockOwnerDeletion': True,
            'controller': True,
            'kind': 'DaemonSet',
            'name': 'endpoint1',
            'uid': 'test-uid-change',
        }],
        'labels': {'label1': 'l1', 'label2': 'l2'},
        'annotations': {'key': 'value'},
        'selfLink': 'test-self-link',
        'uid': 'test-uid-change',
        'generation': 3,
        'finalizers': ['finalizer1', 'finalizer2'],
        'creationTimestamp': '2006-01-02T15:04:05Z',
    },
    'spec': {
        'tier': "default",
        'order': 100000,
        'selector': "type=='sql'",
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Deny',
                'protocol': 'TCP',
            },
        ],
        'ingress': [
            {
                'action': 'Allow',
                'protocol': 'UDP',
            },
        ],
    }
}

networkpolicy_tiered_name2_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'NetworkPolicy',
    'metadata': {
        'name': 'admin.mypolicy2',
        'namespace': 'default'
    },
    'spec': {
        'tier': 'admin',
        'order': 100000,
        'selector': "type=='sql'",
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Deny',
                'protocol': 'TCP',
            },
        ],
        'ingress': [
            {
                'action': 'Allow',
                'protocol': 'UDP',
            },
        ],
    }
}

networkpolicy_os_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'NetworkPolicy',
    'metadata': {
        'name': 'os-policy-mypolicy1',
        'namespace': 'default'
    },
    'spec': {
        'order': 100,
        'selector': "type=='database'",
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Allow',
                'source': {
                    'selector': "type=='application'"},
            },
        ],
        'ingress': [
            {
                'ipVersion': 4,
                'action': 'Deny',
                'destination': {
                    'notNets': ['10.3.0.0/16'],
                    'notPorts': ['110:1050'],
                    'notSelector': "type=='apples'",
                    'nets': ['10.2.0.0/16'],
                    'ports': ['100:200'],
                    'selector': "type=='application'",
                },
                'protocol': 'TCP',
                'source': {
                    'notNets': ['10.1.0.0/16'],
                    'notPorts': [1050],
                    'notSelector': "type=='database'",
                    'nets': ['10.0.0.0/16'],
                    'ports': [1234, '10:1024'],
                    'selector': "type=='application'",
                    'namespaceSelector': 'has(role)',
                }
            }
        ],
    }
}

#
# Staged Network Policy
#
stagednetworkpolicy_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'StagedNetworkPolicy',
    'metadata': {
        'name': 'default.policy-mystagedpolicy1',
        'namespace': 'default'
    },
    'spec': {
        'stagedAction': 'Set',
        'tier': 'default',
        'order': 100,
        'selector': "type=='database'",
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Allow',
                'source': {
                    'selector': "type=='application'"},
            },
        ],
        'ingress': [
            {
                'ipVersion': 4,
                'action': 'Deny',
                'destination': {
                    'notNets': ['10.3.0.0/16'],
                    'notPorts': ['110:1050'],
                    'notSelector': "type=='apples'",
                    'nets': ['10.2.0.0/16'],
                    'ports': ['100:200'],
                    'selector': "type=='application'",
                },
                'protocol': 'TCP',
                'source': {
                    'notNets': ['10.1.0.0/16'],
                    'notPorts': [1050],
                    'notSelector': "type=='database'",
                    'nets': ['10.0.0.0/16'],
                    'ports': [1234, '10:1024'],
                    'selector': "type=='application'",
                    'namespaceSelector': 'has(role)',
                }
            }
        ],
    }
}

stagednetworkpolicy_name1_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'StagedNetworkPolicy',
    'metadata': {
        'name': 'default.policy-mystagedpolicy1',
        'namespace': 'default'
    },
    'spec': {
        'stagedAction': 'Set',
        'tier': "default",
        'order': 100000,
        'selector': "type=='sql'",
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Deny',
                'protocol': 'TCP',
            },
        ],
        'ingress': [
            {
                'action': 'Allow',
                'protocol': 'UDP',
            },
        ],
    }
}

stagednetworkpolicy_name2_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'StagedNetworkPolicy',
    'metadata': {
        'name': 'default.policy-mystagedpolicy2',
        'namespace': 'default',
        'generateName': 'test-policy-',
        'deletionTimestamp': '2006-01-02T15:04:07Z',
        'deletionGracePeriodSeconds': 30,
        'ownerReferences': [{
            'apiVersion': 'extensions/v1beta1',
            'blockOwnerDeletion': True,
            'controller': True,
            'kind': 'DaemonSet',
            'name': 'endpoint1',
            'uid': 'test-uid-change',
        }],
        'labels': {'label1': 'l1', 'label2': 'l2'},
        'annotations': {'key': 'value'},
        'selfLink': 'test-self-link',
        'uid': 'test-uid-change',
        'generation': 3,
        'finalizers': ['finalizer1', 'finalizer2'],
        'creationTimestamp': '2006-01-02T15:04:05Z',
    },
    'spec': {
        'stagedAction': 'Set',
        'tier': "default",
        'order': 100000,
        'selector': "type=='sql'",
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Deny',
                'protocol': 'TCP',
            },
        ],
        'ingress': [
            {
                'action': 'Allow',
                'protocol': 'UDP',
            },
        ],
    }
}

stagednetworkpolicy_tiered_name2_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'StagedNetworkPolicy',
    'metadata': {
        'name': 'admin.mystagedpolicy2',
        'namespace': 'default'
    },
    'spec': {
        'stagedAction': 'Set',
        'tier': 'admin',
        'order': 100000,
        'selector': "type=='sql'",
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Deny',
                'protocol': 'TCP',
            },
        ],
        'ingress': [
            {
                'action': 'Allow',
                'protocol': 'UDP',
            },
        ],
    }
}

stagednetworkpolicy_os_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'StagedNetworkPolicy',
    'metadata': {
        'name': 'os-policy-mypolicy1',
        'namespace': 'default'
    },
    'spec': {
        'stagedAction': 'Set',
        'order': 100,
        'selector': "type=='database'",
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Allow',
                'source': {
                    'selector': "type=='application'"},
            },
        ],
        'ingress': [
            {
                'ipVersion': 4,
                'action': 'Deny',
                'destination': {
                    'notNets': ['10.3.0.0/16'],
                    'notPorts': ['110:1050'],
                    'notSelector': "type=='apples'",
                    'nets': ['10.2.0.0/16'],
                    'ports': ['100:200'],
                    'selector': "type=='application'",
                },
                'protocol': 'TCP',
                'source': {
                    'notNets': ['10.1.0.0/16'],
                    'notPorts': [1050],
                    'notSelector': "type=='database'",
                    'nets': ['10.0.0.0/16'],
                    'ports': [1234, '10:1024'],
                    'selector': "type=='application'",
                    'namespaceSelector': 'has(role)',
                }
            }
        ],
    }
}

#
# Staged Kubernetes Network Policy
#
stagedk8snetworkpolicy_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'StagedKubernetesNetworkPolicy',
    'metadata': {
        'name': 'mystagedk8spolicy1',
        'namespace': 'default'
    },
    'spec': {
        'stagedAction': 'Set',
        'podSelector': {
            'matchLabels': {"role": 'db',}
        },
        'ingress': [
            {
                'from': [
                    {
                        'namespaceSelector': {
                            'matchLabels': {"project": 'test',},
                        },
                        'podSelector': {
                            'matchLabels': {"role": 'frontend',},
                        },
                    },
                ],
                'ports': [
                    {
                        'port': 6379,
                        'protocol': 'TCP',
                    },
                ],
            },
        ],
    }
}

stagedk8snetworkpolicy_name1_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'StagedKubernetesNetworkPolicy',
    'metadata': {
        'name': 'mystagedk8spolicy1',
        'namespace': 'default'
    },
    'spec': {
        'stagedAction': 'Set',
        'podSelector': {
            'matchLabels': {"role": 'db',}
        },
        'ingress': [
            {
                'from': [
                    {
                        'namespaceSelector': {
                            'matchLabels': {"project": 'test',},
                        },
                    },
                ],
                'ports': [
                    {
                        'port': 6379,
                        'protocol': 'TCP',
                    },
                ],
            },
        ],
    }
}

#
# Global Network Policy
#
globalnetworkpolicy_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'GlobalNetworkPolicy',
    'metadata': {
        'name': 'default.policy-mypolicy1',
    },
    'spec': {
        'tier': "default",
        'order': 100,
        'selector': "type=='database'",
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Allow',
                'source': {
                    'selector': "type=='application'"},
                'destination': {
                    'domains': ["microsoft.com", "www.microsoft.com"]},
            },
        ],
        'ingress': [
            {
                'ipVersion': 4,
                'action': 'Deny',
                'destination': {
                    'notNets': ['10.3.0.0/16'],
                    'notPorts': ['110:1050'],
                    'notSelector': "type=='apples'",
                    'nets': ['10.2.0.0/16'],
                    'ports': ['100:200'],
                    'selector': "type=='application'",
                },
                'protocol': 'TCP',
                'source': {
                    'notNets': ['10.1.0.0/16'],
                    'notPorts': [1050],
                    'notSelector': "type=='database'",
                    'nets': ['10.0.0.0/16'],
                    'ports': [1234, '10:1024'],
                    'selector': "type=='application'",
                    'namespaceSelector': 'has(role)',
                }
            }
        ],
    }
}

globalnetworkpolicy_name1_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'GlobalNetworkPolicy',
    'metadata': {
        'name': 'default.policy-mypolicy1',
    },
    'spec': {
        'tier': "default",
        'order': 100000,
        'selector': "type=='sql'",
        'doNotTrack': True,
        'applyOnForward': True,
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Deny',
                'protocol': 'TCP',
            },
        ],
        'ingress': [
            {
                'action': 'Allow',
                'protocol': 'UDP',
            },
        ],
    }
}

globalnetworkpolicy_tiered_name2_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'GlobalNetworkPolicy',
    'metadata': {
        'name': 'admin.mypolicy2',
    },
    'spec': {
        'tier': 'admin',
        'order': 100000,
        'selector': "type=='sql'",
        'doNotTrack': True,
        'applyOnForward': True,
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Deny',
                'protocol': 'TCP',
            },
        ],
        'ingress': [
            {
                'action': 'Allow',
                'protocol': 'UDP',
            },
        ],
    }
}

globalnetworkpolicy_os_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'GlobalNetworkPolicy',
    'metadata': {
        'name': 'os-policy-mypolicy1',
    },
    'spec': {
        'order': 100,
        'selector': "type=='database'",
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Allow',
                'source': {
                    'selector': "type=='application'"},
            },
        ],
        'ingress': [
            {
                'ipVersion': 4,
                'action': 'Deny',
                'destination': {
                    'notNets': ['10.3.0.0/16'],
                    'notPorts': ['110:1050'],
                    'notSelector': "type=='apples'",
                    'nets': ['10.2.0.0/16'],
                    'ports': ['100:200'],
                    'selector': "type=='application'",
                },
                'protocol': 'TCP',
                'source': {
                    'notNets': ['10.1.0.0/16'],
                    'notPorts': [1050],
                    'notSelector': "type=='database'",
                    'nets': ['10.0.0.0/16'],
                    'ports': [1234, '10:1024'],
                    'selector': "type=='application'",
                    'namespaceSelector': 'has(role)',
                }
            }
        ],
    }
}

networkpolicy_name3_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'NetworkPolicy',
    'metadata': {
        'name': 'policy-mypolicy3',
        'namespace': 'test',
    },
    'spec': {
        'order': 100,
        'selector': "type=='database'",
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Allow',
                'source': {
                    'selector': "type=='application'"},
            },
        ],
        'ingress': [
            {
                'ipVersion': 4,
                'action': 'Deny',
                'destination': {
                    'notNets': ['10.3.0.0/16'],
                    'notPorts': ['110:1050'],
                    'notSelector': "type=='apples'",
                    'nets': ['10.2.0.0/16'],
                    'ports': ['100:200'],
                    'selector': "type=='application'",
                },
                'protocol': 'TCP',
                'source': {
                    'notNets': ['10.1.0.0/16'],
                    'notPorts': [1050],
                    'notSelector': "type=='database'",
                    'nets': ['10.0.0.0/16'],
                    'ports': [1234, '10:1024'],
                    'selector': "type=='application'",
                    'namespaceSelector': 'has(role)',
                }
            }
        ],
    }
}


#
# Staged Global Network Policy
#
stagedglobalnetworkpolicy_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'StagedGlobalNetworkPolicy',
    'metadata': {
        'name': 'default.policy-mystagedpolicy1',
    },
    'spec': {
        'stagedAction': "Set",
        'tier': "default",
        'order': 100,
        'selector': "type=='database'",
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Allow',
                'source': {
                    'selector': "type=='application'"},
                'destination': {
                    'domains': ["microsoft.com", "www.microsoft.com"]},
            },
        ],
        'ingress': [
            {
                'ipVersion': 4,
                'action': 'Deny',
                'destination': {
                    'notNets': ['10.3.0.0/16'],
                    'notPorts': ['110:1050'],
                    'notSelector': "type=='apples'",
                    'nets': ['10.2.0.0/16'],
                    'ports': ['100:200'],
                    'selector': "type=='application'",
                },
                'protocol': 'TCP',
                'source': {
                    'notNets': ['10.1.0.0/16'],
                    'notPorts': [1050],
                    'notSelector': "type=='database'",
                    'nets': ['10.0.0.0/16'],
                    'ports': [1234, '10:1024'],
                    'selector': "type=='application'",
                    'namespaceSelector': 'has(role)',
                }
            }
        ],
    }
}

stagedglobalnetworkpolicy_name1_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'StagedGlobalNetworkPolicy',
    'metadata': {
        'name': 'default.policy-mystagedpolicy1',
    },
    'spec': {
        'stagedAction': "Set",
        'tier': "default",
        'order': 100000,
        'selector': "type=='sql'",
        'doNotTrack': True,
        'applyOnForward': True,
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Deny',
                'protocol': 'TCP',
            },
        ],
        'ingress': [
            {
                'action': 'Allow',
                'protocol': 'UDP',
            },
        ],
    }
}

stagedglobalnetworkpolicy_tiered_name2_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'StagedGlobalNetworkPolicy',
    'metadata': {
        'name': 'admin.mystagedpolicy2',
    },
    'spec': {
        'stagedAction': "Set",
        'tier': 'admin',
        'order': 100000,
        'selector': "type=='sql'",
        'doNotTrack': True,
        'applyOnForward': True,
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Deny',
                'protocol': 'TCP',
            },
        ],
        'ingress': [
            {
                'action': 'Allow',
                'protocol': 'UDP',
            },
        ],
    }
}

stagedglobalnetworkpolicy_os_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'StagedGlobalNetworkPolicy',
    'metadata': {
        'name': 'os-policy-mystagedpolicy1',
    },
    'spec': {
        'stagedAction': "Set",
        'order': 100,
        'selector': "type=='database'",
        'types': ['Ingress', 'Egress'],
        'egress': [
            {
                'action': 'Allow',
                'source': {
                    'selector': "type=='application'"},
            },
        ],
        'ingress': [
            {
                'ipVersion': 4,
                'action': 'Deny',
                'destination': {
                    'notNets': ['10.3.0.0/16'],
                    'notPorts': ['110:1050'],
                    'notSelector': "type=='apples'",
                    'nets': ['10.2.0.0/16'],
                    'ports': ['100:200'],
                    'selector': "type=='application'",
                },
                'protocol': 'TCP',
                'source': {
                    'notNets': ['10.1.0.0/16'],
                    'notPorts': [1050],
                    'notSelector': "type=='database'",
                    'nets': ['10.0.0.0/16'],
                    'ports': [1234, '10:1024'],
                    'selector': "type=='application'",
                    'namespaceSelector': 'has(role)',
                }
            }
        ],
    }
}


#
# Global network sets
#

globalnetworkset_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'GlobalNetworkSet',
    'metadata': {
        'name': 'net-set1',
    },
    'spec': {
        'nets': [
            "10.0.0.1",
            "11.0.0.0/16",
            "feed:beef::1",
            "dead:beef::96",
        ],
        'allowedEgressDomains': [
            "microsoft.com",
            "www.microsoft.com",
        ],
    }
}

# A network set with a large number of entries.  In prototyping this test, I found that there are
# "upstream" limits that cap how large we can go:
#
# - Kubernetes' gRPC API has a 4MB message size limit.
# - etcdv3 has a 1MB value size limit.
globalnetworkset_name1_rev1_large = {
    'apiVersion': API_VERSION,
    'kind': 'GlobalNetworkSet',
    'metadata': {
        'name': 'net-set1',
    },
    'spec': {
        'nets': many_nets,
    }
}

#
# Network sets
#

networkset_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'NetworkSet',
    'metadata': {
        'name': 'net-set1'
    },
    'spec': {
        'nets': [
            "10.0.0.1",
            "11.0.0.0/16",
            "feed:beef::1",
            "dead:beef::96",
        ]
    }
}

networkset_name2_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'NetworkSet',
    'metadata': {
        'name': 'net-set2',
        'namespace': 'test',
    },
    'spec': {
        'nets': [
            "10.0.0.1",
            "11.0.0.0/16",
            "feed:beef::1",
            "dead:beef::96",
        ]
    }
}

# A network set with a large number of entries.  In prototyping this test, I found that there are
# "upstream" limits that cap how large we can go:
#
# - Kubernetes' gRPC API has a 4MB message size limit.
# - etcdv3 has a 1MB value size limit.
many_nets = []
for i in xrange(10000):
    many_nets.append("10.%s.%s.0/28" % (i >> 8, i % 256))
networkset_name1_rev1_large = {
    'apiVersion': API_VERSION,
    'kind': 'NetworkSet',
    'metadata': {
        'name': 'net-set1',
        'namespace': 'namespace-1'
    },
    'spec': {
        'nets': many_nets,
    }
}

#
# Host Endpoints
#
hostendpoint_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'HostEndpoint',
    'metadata': {
        'name': 'endpoint1',
        'labels': {'type': 'database'},
    },
    'spec': {
        'interfaceName': 'eth0',
        'profiles': ['prof1', 'prof2'],
        'node': 'host1'
    }
}

hostendpoint_name1_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'HostEndpoint',
    'metadata': {
        'name': 'endpoint1',
        'labels': {'type': 'frontend'}
    },
    'spec': {
        'interfaceName': 'cali7',
        'profiles': ['prof1', 'prof2'],
        'node': 'host2'
    }
}

hostendpoint_name1_rev3 = {
    'apiVersion': API_VERSION,
    'kind': 'HostEndpoint',
    'metadata': {
        'name': 'endpoint1',
        'labels': {'type': 'frontend', 'misc': 'version1'},
        'annotations': {'key': 'value'},
        'selfLink': 'test-self-link',
        'uid': 'test-uid-change',
        'generation': 3,
        'finalizers': ['finalizer1', 'finalizer2'],
        'creationTimestamp': '2006-01-02T15:04:05Z',
    },
    'spec': {
        'interfaceName': 'cali7',
        'profiles': ['prof1', 'prof2'],
        'node': 'host2'
    }
}

#
# Profiles
#
profile_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'Profile',
    'metadata': {
        'labels': {'foo': 'bar'},
        'name': 'profile-name1'
    },
    'spec': {
        'egress': [
            {
                'action': 'Allow',
                'source': {
                      'selector': "type=='application'"
                }
            }
        ],
        'ingress': [
            {
                'ipVersion': 4,
                'action': 'Deny',
                'destination': {
                   'notNets': ['10.3.0.0/16'],
                   'notPorts': ['110:1050'],
                   'notSelector': "type=='apples'",
                   'nets': ['10.2.0.0/16'],
                   'ports': ['100:200'],
                   'selector': "type=='application'"},
                'protocol': 'TCP',
                'source': {
                   'notNets': ['10.1.0.0/16'],
                   'notPorts': [1050],
                   'notSelector': "type=='database'",
                   'nets': ['10.0.0.0/16'],
                   'ports': [1234, '10:20'],
                   'selector': "type=='application'",
                }
            }
        ],
    }
}

profile_name1_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'Profile',
    'metadata': {
        'name': 'profile-name1',
    },
    'spec': {
        'egress': [
            {
                'action': 'Allow'
            }
        ],
        'ingress': [
            {
                'ipVersion': 6,
                'action': 'Deny',
            },
        ],
    }
}

#
# Workload Endpoints
#
workloadendpoint_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'WorkloadEndpoint',
    'metadata': {
        'labels': {
            'projectcalico.org/namespace': 'namespace1',
            'projectcalico.org/orchestrator': 'k8s',
            'type': 'database',
        },
        'name': 'node1-k8s-abcd-eth0',
        'namespace': 'namespace1',
    },
    'spec': {
        'node': 'node1',
        'orchestrator': 'k8s',
        'pod': 'abcd',
        'endpoint': 'eth0',
        'containerID': 'container1234',
        'ipNetworks': ['1.2.3.4/32'],
        'interfaceName': 'cali1234',
        'profiles': ['prof1', 'prof2'],
    }
}

workloadendpoint_name2_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'WorkloadEndpoint',
    'metadata': {
        'labels': {
            'projectcalico.org/namespace': 'namespace1',
            'projectcalico.org/orchestrator': 'cni',
            'type': 'database'
        },
        'name': 'node2-cni-container1234-eth0',
        'namespace': 'namespace1',
    },
    'spec': {
        'node': 'node2',
        'orchestrator': 'cni',
        'endpoint': 'eth0',
        'containerID': 'container1234',
        'ipNetworks': ['1.2.3.4/32'],
        'interfaceName': 'cali1234',
        'profiles': ['prof1', 'prof2'],
    }
}


#
# Packet captures
#
packetcapture_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'PacketCapture',
    'metadata': {
        'name': 'packet-capture-1',
        'namespace': 'namespace1',
    },
    'spec': {
        'selector': 'all()',
    }
}

packetcapture_name1_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'PacketCapture',
    'metadata': {
        'name': 'packet-capture-1',
        'namespace': 'namespace1',
    },
    'spec': {
        'selector': 'capture == \"true\"',
    }
}

packetcapture_name2_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'PacketCapture',
    'metadata': {
        'name': 'packet-capture-2',
        'namespace': 'namespace1',
    },
    'spec': {
        'selector': 'all()',
    }
}

#
# UISettingsGroup
#
uisettingsgroup_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'UISettingsGroup',
    'metadata': {
        'name': 'ui-group-1',
    },
    'spec': {
        'description': 'This is a UI Settings Group',
    }
}

#
# Nodes
#
node_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'Node',
    'metadata': {
        'name': 'node1',
    },
    'spec': {
        'bgp': {
            'ipv4Address': '1.2.3.4/24',
            'ipv6Address': 'aa:bb:cc::ff/120',
        }
    }
}

node_name2_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'Node',
    'metadata': {
        'name': 'node2',
    },
    'spec': {
        'bgp': {
            'ipv4Address': '1.2.3.5/24',
            'ipv6Address': 'aa:bb:cc::ee/120',
        }
    }
}

node_name3_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'Node',
    'metadata': {
        'name': 'node3',
    },
    'spec': {
        'bgp': {
            'ipv4Address': '1.2.3.6/24',
            'ipv6Address': 'aa:bb:cc::dd/120',
        }
    }
}

node_name4_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'Node',
    'metadata': {
        'name': 'node4',
    },
    'spec': {
        'bgp': {
            'ipv4Address': '1.2.3.4/24',
            'ipv6Address': 'aa:bb:cc::ff/120',
        },
        'orchRefs': [
            {
                'nodeName': 'node4',
                'orchestrator': 'k8s',
            },
        ],
    }
}

node_name5_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'Node',
    'metadata': {
        'name': 'node5',
    },
    'spec': {
        'bgp': {
            'ipv4Address': '1.2.3.5/24',
            'ipv6Address': 'aa:bb:cc::ff/120',
        },
        'orchRefs': [
            {
                'nodeName': 'node4',
                'orchestrator': 'k8s',
            },
        ],
    }
}

#
# BGPConfigs
#
bgpconfig_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'BGPConfiguration',
    'metadata': {
        'name': 'default',
    },
    'spec': {
        'logSeverityScreen': 'Info',
        'nodeToNodeMeshEnabled': True,
        'asNumber': 6512,
        'serviceLoadBalancerAggregation': 'Enabled',
    }
}

bgpconfig_name1_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'BGPConfiguration',
    'metadata': {
        'name': 'default',
    },
    'spec': {
        'logSeverityScreen': 'Info',
        'nodeToNodeMeshEnabled': False,
        'asNumber': 6511,
        'serviceLoadBalancerAggregation': 'Enabled',
    }
}

bgpconfig_name2_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'BGPConfiguration',
    'metadata': {
        'name': 'bgpconfiguration1',
    },
    'spec': {
        'logSeverityScreen': 'Info',
        'serviceLoadBalancerAggregation': 'Enabled',
    }
}

bgpconfig_name2_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'BGPConfiguration',
    'metadata': {
        'name': 'bgpconfiguration1',
    },
    'spec': {
        'logSeverityScreen': 'Debug',
        'serviceLoadBalancerAggregation': 'Enabled',
    }
}

bgpconfig_name2_rev3 = {
    'apiVersion': API_VERSION,
    'kind': 'BGPConfiguration',
    'metadata': {
        'name': 'bgpconfiguration1',
    },
    'spec': {
        'logSeverityScreen': 'Debug',
        'nodeToNodeMeshEnabled': True,
        'serviceLoadBalancerAggregation': 'Enabled',
    }
}

bgpconfig_name3_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'BGPConfiguration',
    'metadata': {
        'name': 'node.node5',
    },
    'spec': {
        'logSeverityScreen': 'Debug',
        'serviceLoadBalancerAggregation': 'Enabled',
    }
}

bgpconfig_name4_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'BGPConfiguration',
    'metadata': {
        'name': 'node.node4',
    },
    'spec': {
        'logSeverityScreen': 'Debug',
        'serviceLoadBalancerAggregation': 'Enabled',
    }
}

#
# Remote cluster configs
#
rcc_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'RemoteClusterConfiguration',
    'metadata': {
        'name': 'rcc1',
    },
    'spec': {
        'datastoreType': 'kubernetes',
        'kubeconfig' : 'yes- this is a valid path!'
    }
}

rcc_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'RemoteClusterConfiguration',
    'metadata': {
        'name': 'rcc1',
    },
    'spec': {
        'datastoreType': 'kubernetes',
        'kubeconfig' : '/more/normal'
    }
}

rcc_rev3 = {
    'apiVersion': API_VERSION,
    'kind': 'RemoteClusterConfiguration',
    'metadata': {
        'name': 'rcc1',
    },
    'spec': {
        'datastoreType': 'kubernetes',
        'kubeconfig' : '/etc/config/kubeconfig'
    }
}

#
# FelixConfigs
#
felixconfig_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'FelixConfiguration',
    'metadata': {
        'name': 'felixconfiguration1',
    },
    'spec': {
        'chainInsertMode': 'append',
        'defaultEndpointToHostAction': 'Accept',
        'failsafeInboundHostPorts': [
            {'protocol': 'TCP', 'port': 666},
            {'protocol': 'UDP', 'port': 333}, ],
        'failsafeOutboundHostPorts': [
            {'protocol': 'TCP', 'port': 999},
            {'protocol': 'UDP', 'port': 222},
            {'protocol': 'UDP', 'port': 422}, ],
        'interfacePrefix': 'humperdink',
        'ipipMTU': 1521,
        'ipsetsRefreshInterval': '44s',
        'iptablesFilterAllowAction': 'Return',
        'iptablesLockProbeInterval': '500ms',
        'iptablesMangleAllowAction': 'Accept',
        'iptablesMarkMask': 0xff0000,
        'iptablesPostWriteCheckInterval': '12s',
        'iptablesRefreshInterval': '22s',
        'ipv6Support': True,
        'logFilePath': '/var/log/fun.log',
        'logPrefix': 'say-hello-friend',
        'logSeverityScreen': 'Info',
        'maxIpsetSize': 8192,
        'metadataAddr': '127.1.1.1',
        'metadataPort': 8999,
        'netlinkTimeout': '10s',
        'prometheusGoMetricsEnabled': True,
        'prometheusMetricsEnabled': True,
        'prometheusMetricsPort': 11,
        'prometheusProcessMetricsEnabled': True,
        'reportingInterval': '10s',
        'reportingTTL': '99s',
        'routeRefreshInterval': '33s',
        'usageReportingEnabled': False,
    }
}

felixconfig_name1_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'FelixConfiguration',
    'metadata': {
        'name': 'felixconfiguration1',
    },
    'spec': {
        'ipv6Support': False,
        'logSeverityScreen': 'Debug',
        'netlinkTimeout': '11s',
    }
}

# The large values for `netlinkTimeout` and `reportingTTL` will be transformed
# into a different unit type in the format `XhXmXs`.
felixconfig_name1_rev3 = {
    'apiVersion': API_VERSION,
    'kind': 'FelixConfiguration',
    'metadata': {
        'name': 'felixconfiguration1',
    },
    'spec': {
        'ipv6Support': False,
        'logSeverityScreen': 'Debug',
        'netlinkTimeout': '125s',
        'reportingTTL': '9910s',
    }
}

felixconfig_name2_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'FelixConfiguration',
    'metadata': {
        'name': 'node.node5',
    },
    'spec': {
        'chainInsertMode': 'append',
        'defaultEndpointToHostAction': 'Accept',
        'failsafeInboundHostPorts': [
            {'protocol': 'TCP', 'port': 666},
            {'protocol': 'UDP', 'port': 333}, ],
        'failsafeOutboundHostPorts': [
            {'protocol': 'TCP', 'port': 999},
            {'protocol': 'UDP', 'port': 222},
            {'protocol': 'UDP', 'port': 422}, ],
        'interfacePrefix': 'humperdink',
        'ipipMTU': 1521,
        'ipsetsRefreshInterval': '44s',
        'iptablesFilterAllowAction': 'Return',
        'iptablesLockProbeInterval': '500ms',
        'iptablesMangleAllowAction': 'Accept',
        'iptablesMarkMask': 0xff0000,
        'iptablesPostWriteCheckInterval': '12s',
        'iptablesRefreshInterval': '22s',
        'ipv6Support': True,
        'logFilePath': '/var/log/fun.log',
        'logPrefix': 'say-hello-friend',
        'logSeverityScreen': 'Info',
        'maxIpsetSize': 8192,
        'metadataAddr': '127.1.1.1',
        'metadataPort': 8999,
        'netlinkTimeout': '10s',
        'prometheusGoMetricsEnabled': True,
        'prometheusMetricsEnabled': True,
        'prometheusMetricsPort': 11,
        'prometheusProcessMetricsEnabled': True,
        'reportingInterval': '10s',
        'reportingTTL': '99s',
        'routeRefreshInterval': '33s',
        'usageReportingEnabled': False,
    }
}

felixconfig_name3_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'FelixConfiguration',
    'metadata': {
        'name': 'node.node4',
    },
    'spec': {
        'chainInsertMode': 'append',
        'defaultEndpointToHostAction': 'Accept',
        'failsafeInboundHostPorts': [
            {'protocol': 'TCP', 'port': 666},
            {'protocol': 'UDP', 'port': 333}, ],
        'failsafeOutboundHostPorts': [
            {'protocol': 'TCP', 'port': 999},
            {'protocol': 'UDP', 'port': 222},
            {'protocol': 'UDP', 'port': 422}, ],
        'interfacePrefix': 'humperdink',
        'ipipMTU': 1521,
        'ipsetsRefreshInterval': '44s',
        'iptablesFilterAllowAction': 'Return',
        'iptablesLockProbeInterval': '500ms',
        'iptablesMangleAllowAction': 'Accept',
        'iptablesMarkMask': 0xff0000,
        'iptablesPostWriteCheckInterval': '12s',
        'iptablesRefreshInterval': '22s',
        'ipv6Support': True,
        'logFilePath': '/var/log/fun.log',
        'logPrefix': 'say-hello-friend',
        'logSeverityScreen': 'Info',
        'maxIpsetSize': 8192,
        'metadataAddr': '127.1.1.1',
        'metadataPort': 8999,
        'netlinkTimeout': '10s',
        'prometheusGoMetricsEnabled': True,
        'prometheusMetricsEnabled': True,
        'prometheusMetricsPort': 11,
        'prometheusProcessMetricsEnabled': True,
        'reportingInterval': '10s',
        'reportingTTL': '99s',
        'routeRefreshInterval': '33s',
        'usageReportingEnabled': False,
    }
}

#
# ClusterInfo
#
clusterinfo_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'ClusterInformation',
    'metadata': {
        'name': 'default',
    },
    'spec': {
        'clusterGUID': 'cluster-guid1',
        'datastoreReady': True,
    }
}

clusterinfo_name1_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'ClusterInformation',
    'metadata': {
        'name': 'default',
    },
    'spec': {
        'clusterGUID': 'cluster-guid2',
        'clusterType': 'cluster-type2',
        'calicoVersion': 'calico-version2',
    }
}

#
# GlobalThreatFeed
#
globalthreatfeed_name1 = {
    'apiVersion': API_VERSION,
    'kind': 'GlobalThreatFeed',
    'metadata': {
        'name': 'name1'
    },
    'spec': {
        'content': 'IPSet',
        'globalNetworkSet': {
            'labels': {
                'foo': 'bar',
                'fizz': 'buzz',
            }
        },
        'pull': {
            'period': '13.5h',
            'http': {
                'url': 'https://notreal.tigera.io/threatfeed',
                'headers': [
                    {'name': 'Accept', 'value': 'text/plain'},
                    {'name': 'APIKey', 'valueFrom': {
                        'secretKeyRef': {
                            'name': 'globalthreatfeed-name1-my-secret',
                            'key': 'my-key'
                        }
                    }}
                ]
            }
        }
    }
}

globalthreatfeed_name2_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'GlobalThreatFeed',
    'metadata': {
        'name': 'name2'
    },
    'spec': {
        'pull': {
            'http': {
                'url': 'https://notreal.tigera.io/threatfeed2',
            }
        }
    }
}

globalthreatfeed_name2_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'GlobalThreatFeed',
    'metadata': {
        'name': 'name2'
    },
    'spec': {
        'pull': {
            'http': {
                'url': 'https://notreal.tigera.io/threatfeed/rev2',
            }
        }
    }
}

# Note: empty/omitted spec is valid!
globalthreatfeed_name0 = {
    'apiVersion': API_VERSION,
    'kind': 'GlobalThreatFeed',
    'metadata': {
        'name': 'name0'
    },
}

# Note: whitespace matters!  Be careful editing.
globalthreatfeed_get_table_output = (
    'NAME    PERIOD   URL                                         \n'
    'name0                                                        \n'
    'name1   13.5h    https://notreal.tigera.io/threatfeed        \n'
    'name2   24h      https://notreal.tigera.io/threatfeed/rev2'
)

#
# KubeControllersConfiguration
#
kubecontrollersconfig_name1_rev1 = {
    'apiVersion': API_VERSION,
    'kind': 'KubeControllersConfiguration',
    'metadata': {
        'name': 'default',
    },
    'spec': {
        'logSeverityScreen': 'Info',
        'controllers': {
            'node': {
                'syncLabels': 'Enabled',
                'hostEndpoint': {
                    'autoCreate': 'Disabled',
                }
            }
        }
    }
}

kubecontrollersconfig_name1_rev2 = {
    'apiVersion': API_VERSION,
    'kind': 'KubeControllersConfiguration',
    'metadata': {
        'name': 'default',
    },
    'spec': {
        'logSeverityScreen': 'Debug',
        'controllers': {
            'node': {
                'syncLabels': 'Enabled',
                'hostEndpoint': {
                    'autoCreate': 'Disabled',
                }
            },
            'namespace': {},
        }
    },
    'status': {
        'environmentVars': {
            'LOG_LEVEL': 'Info',
        }
    }
}
