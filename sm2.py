import binascii
from math import ceil
from random import choice
import copy
from Cryptodome.Util.asn1 import DerSequence, DerInteger
from binascii import unhexlify

#SM2
# 选择素域，设置椭圆曲线参数
default_ecc_table = {
    'n': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
    'p': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
    'g': '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7'
         'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0',
    'a': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
    'b': '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
}



IV = [
    1937774191, 1226093241, 388252375, 3666478592,
    2842636476, 372324522, 3817729613, 2969243214,
]

T_j = [
    2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
    2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
    2043430169, 2043430169, 2043430169, 2043430169, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042
]

def sm3_ff_j(x, y, z, j):
    if 0 <= j and j < 16:
        ret = x ^ y ^ z
    elif 16 <= j and j < 64:
        ret = (x & y) | (x & z) | (y & z)
    return ret

def sm3_gg_j(x, y, z, j):
    if 0 <= j and j < 16:
        ret = x ^ y ^ z
    elif 16 <= j and j < 64:
        #ret = (X | Y) & ((2 ** 32 - 1 - X) | Z)
        ret = (x & y) | ((~ x) & z)
    return ret

def sm3_p_0(x):
    return x ^ (rotl(x, 9 % 32)) ^ (rotl(x, 17 % 32))

def sm3_p_1(x):
    return x ^ (rotl(x, 15 % 32)) ^ (rotl(x, 23 % 32))

def sm3_cf(v_i, b_i):
    w = []
    for i in range(16):
        weight = 0x1000000
        data = 0
        for k in range(i*4,(i+1)*4):
            data = data + b_i[k]*weight
            weight = int(weight/0x100)
        w.append(data)

    for j in range(16, 68):
        w.append(0)
        w[j] = sm3_p_1(w[j-16] ^ w[j-9] ^ (rotl(w[j-3], 15 % 32))) ^ (rotl(w[j-13], 7 % 32)) ^ w[j-6]
        str1 = "%08x" % w[j]
    w_1 = []
    for j in range(0, 64):
        w_1.append(0)
        w_1[j] = w[j] ^ w[j+4]
        str1 = "%08x" % w_1[j]

    a, b, c, d, e, f, g, h = v_i

    for j in range(0, 64):
        ss_1 = rotl(
            ((rotl(a, 12 % 32)) +
            e +
            (rotl(T_j[j], j % 32))) & 0xffffffff, 7 % 32
        )
        ss_2 = ss_1 ^ (rotl(a, 12 % 32))
        tt_1 = (sm3_ff_j(a, b, c, j) + d + ss_2 + w_1[j]) & 0xffffffff
        tt_2 = (sm3_gg_j(e, f, g, j) + h + ss_1 + w[j]) & 0xffffffff
        d = c
        c = rotl(b, 9 % 32)
        b = a
        a = tt_1
        h = g
        g = rotl(f, 19 % 32)
        f = e
        e = sm3_p_0(tt_2)

        a, b, c, d, e, f, g, h = map(
            lambda x:x & 0xFFFFFFFF ,[a, b, c, d, e, f, g, h])

    v_j = [a, b, c, d, e, f, g, h]
    return [v_j[i] ^ v_i[i] for i in range(8)]

def sm3_hash(msg):
    # print(msg)
    len1 = len(msg)
    reserve1 = len1 % 64
    msg.append(0x80)
    reserve1 = reserve1 + 1
    # 56-64, add 64 byte
    range_end = 56
    if reserve1 > range_end:
        range_end = range_end + 64

    for i in range(reserve1, range_end):
        msg.append(0x00)

    bit_length = (len1) * 8
    bit_length_str = [bit_length % 0x100]
    for i in range(7):
        bit_length = int(bit_length / 0x100)
        bit_length_str.append(bit_length % 0x100)
    for i in range(8):
        msg.append(bit_length_str[7-i])

    group_count = round(len(msg) / 64)

    B = []
    for i in range(0, group_count):
        B.append(msg[i*64:(i+1)*64])

    V = []
    V.append(IV)
    for i in range(0, group_count):
        V.append(sm3_cf(V[i], B[i]))

    y = V[i+1]
    result = ""
    for i in y:
        result = '%s%08x' % (result, i)
    return result

def sm3_kdf(z, klen): # z为16进制表示的比特串（str），klen为密钥长度（单位byte）
    klen = int(klen)
    ct = 0x00000001
    rcnt = ceil(klen/32)
    zin = [i for i in bytes.fromhex(z.decode('utf8'))]
    ha = ""
    for i in range(rcnt):
        msg = zin  + [i for i in binascii.a2b_hex(('%08x' % ct).encode('utf8'))]
        ha = ha + sm3_hash(msg)
        ct += 1
    return ha[0: klen * 2]

# Expanded SM4 box table
SM4_BOXES_TABLE = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c,
    0x05, 0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86,
    0x06, 0x99, 0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed,
    0xcf, 0xac, 0x62, 0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa,
    0x75, 0x8f, 0x3f, 0xa6, 0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c,
    0x19, 0xe6, 0x85, 0x4f, 0xa8, 0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb,
    0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35, 0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25,
    0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87, 0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
    0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e, 0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38,
    0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1, 0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34,
    0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3, 0x1d, 0xf6, 0xe2, 0x2e, 0x82,
    0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f, 0xd5, 0xdb, 0x37, 0x45,
    0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51, 0x8d, 0x1b, 0xaf,
    0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8, 0x0a, 0xc1,
    0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0, 0x89,
    0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39,
    0x48,
]

# System parameter
SM4_FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]

# fixed parameter
SM4_CK = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
]

SM4_ENCRYPT = 0
SM4_DECRYPT = 1

PKCS7 = 0
ZERO = 1


class CryptSM4(object):

    def __init__(self, mode=SM4_ENCRYPT, padding_mode=PKCS7):
        self.sk = [0] * 32
        self.mode = mode
        self.padding_mode = padding_mode
    # Calculating round encryption key.
    # args:    [in] a: a is a 32 bits unsigned value;
    # return: sk[i]: i{0,1,2,3,...31}.

    @classmethod
    def _round_key(cls, ka):
        b = [0, 0, 0, 0]
        a = put_uint32_be(ka)
        b[0] = SM4_BOXES_TABLE[a[0]]
        b[1] = SM4_BOXES_TABLE[a[1]]
        b[2] = SM4_BOXES_TABLE[a[2]]
        b[3] = SM4_BOXES_TABLE[a[3]]
        bb = get_uint32_be(b[0:4])
        rk = bb ^ (rotl(bb, 13)) ^ (rotl(bb, 23))
        return rk

    # Calculating and getting encryption/decryption contents.
    # args:    [in] x0: original contents;
    # args:    [in] x1: original contents;
    # args:    [in] x2: original contents;
    # args:    [in] x3: original contents;
    # args:    [in] rk: encryption/decryption key;
    # return the contents of encryption/decryption contents.
    @classmethod
    def _f(cls, x0, x1, x2, x3, rk):
        # "T algorithm" == "L algorithm" + "t algorithm".
        # args:    [in] a: a is a 32 bits unsigned value;
        # return: c: c is calculated with line algorithm "L" and nonline
        # algorithm "t"
        def _sm4_l_t(ka):
            b = [0, 0, 0, 0]
            a = put_uint32_be(ka)
            b[0] = SM4_BOXES_TABLE[a[0]]
            b[1] = SM4_BOXES_TABLE[a[1]]
            b[2] = SM4_BOXES_TABLE[a[2]]
            b[3] = SM4_BOXES_TABLE[a[3]]
            bb = get_uint32_be(b[0:4])
            c = bb ^ (
                rotl(
                    bb,
                    2)) ^ (
                rotl(
                    bb,
                    10)) ^ (
                rotl(
                    bb,
                    18)) ^ (
                rotl(
                    bb,
                    24))
            return c
        return (x0 ^ _sm4_l_t(x1 ^ x2 ^ x3 ^ rk))

    def set_key(self, key, mode):
        key = bytes_to_list(key)
        MK = [0, 0, 0, 0]
        k = [0] * 36
        MK[0] = get_uint32_be(key[0:4])
        MK[1] = get_uint32_be(key[4:8])
        MK[2] = get_uint32_be(key[8:12])
        MK[3] = get_uint32_be(key[12:16])
        k[0:4] = xor(MK[0:4], SM4_FK[0:4])
        for i in range(32):
            k[i + 4] = k[i] ^ (
                self._round_key(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i]))
            self.sk[i] = k[i + 4]
        self.mode = mode
        if mode == SM4_DECRYPT:
            for idx in range(16):
                t = self.sk[idx]
                self.sk[idx] = self.sk[31 - idx]
                self.sk[31 - idx] = t

    def one_round(self, sk, in_put):
        out_put = []
        ulbuf = [0] * 36
        ulbuf[0] = get_uint32_be(in_put[0:4])
        ulbuf[1] = get_uint32_be(in_put[4:8])
        ulbuf[2] = get_uint32_be(in_put[8:12])
        ulbuf[3] = get_uint32_be(in_put[12:16])
        for idx in range(32):
            ulbuf[idx + 4] = self._f(ulbuf[idx],
                                     ulbuf[idx + 1],
                                     ulbuf[idx + 2],
                                     ulbuf[idx + 3],
                                     sk[idx])

        out_put += put_uint32_be(ulbuf[35])
        out_put += put_uint32_be(ulbuf[34])
        out_put += put_uint32_be(ulbuf[33])
        out_put += put_uint32_be(ulbuf[32])
        return out_put

    def crypt_ecb(self, input_data):
        # SM4-ECB block encryption/decryption
        input_data = bytes_to_list(input_data)
        if self.mode == SM4_ENCRYPT:
            if self.padding_mode == PKCS7:
                input_data = pkcs7_padding(input_data)
            elif self.padding_mode == ZERO:
                input_data = zero_padding(input_data)

        length = len(input_data)
        i = 0
        output_data = []
        while length > 0:
            output_data += self.one_round(self.sk, input_data[i:i + 16])
            i += 16
            length -= 16
        if self.mode == SM4_DECRYPT:
            if self.padding_mode == PKCS7:
                return list_to_bytes(pkcs7_unpadding(output_data))
            elif self.padding_mode == ZERO:
                return list_to_bytes(zero_unpadding(output_data))
        return list_to_bytes(output_data)

    def crypt_cbc(self, iv, input_data):
        # SM4-CBC buffer encryption/decryption
        i = 0
        output_data = []
        tmp_input = [0] * 16
        iv = bytes_to_list(iv)
        if self.mode == SM4_ENCRYPT:
            input_data = pkcs7_padding(bytes_to_list(input_data))
            length = len(input_data)
            while length > 0:
                tmp_input[0:16] = xor(input_data[i:i + 16], iv[0:16])
                output_data += self.one_round(self.sk, tmp_input[0:16])
                iv = copy.deepcopy(output_data[i:i + 16])
                i += 16
                length -= 16
            return list_to_bytes(output_data)
        else:
            length = len(input_data)
            while length > 0:
                output_data += self.one_round(self.sk, input_data[i:i + 16])
                output_data[i:i + 16] = xor(output_data[i:i + 16], iv[0:16])
                iv = copy.deepcopy(input_data[i:i + 16])
                i += 16
                length -= 16
            return list_to_bytes(pkcs7_unpadding(output_data))


xor = lambda a, b:list(map(lambda x, y: x ^ y, a, b))

rotl = lambda x, n:((x << n) & 0xffffffff) | ((x >> (32 - n)) & 0xffffffff)

get_uint32_be = lambda key_data:((key_data[0] << 24) | (key_data[1] << 16) | (key_data[2] << 8) | (key_data[3]))

put_uint32_be = lambda n:[((n>>24)&0xff), ((n>>16)&0xff), ((n>>8)&0xff), ((n)&0xff)]

pkcs7_padding = lambda data, block=16: data + [(16 - len(data) % block)for _ in range(16 - len(data) % block)]

zero_padding = lambda data, block=16: data + [0 for _ in range(16 - len(data) % block)]

pkcs7_unpadding = lambda data: data[:-data[-1]]

zero_unpadding = lambda data,i =1:data[:-i] if data[-i] == 0 else i+1

list_to_bytes = lambda data: b''.join([bytes((i,)) for i in data])

bytes_to_list = lambda data: [i for i in data]

random_hex = lambda x: ''.join([choice('0123456789abcdef') for _ in range(x)])


class CryptSM2(object):

    def __init__(self, private_key, public_key, ecc_table=default_ecc_table, mode=0, asn1=False):
        """
        mode: 0-C1C2C3, 1-C1C3C2 (default is 1)
        """
        self.private_key = private_key
        self.public_key = public_key.lstrip("04") if public_key.startswith("04") else public_key
        self.para_len = len(ecc_table['n'])
        self.ecc_a3 = (
            int(ecc_table['a'], base=16) + 3) % int(ecc_table['p'], base=16)
        self.ecc_table = ecc_table
        assert mode in (0, 1), 'mode must be one of (0, 1)'
        self.mode = mode
        self.asn1 = asn1

    def verify(self, Sign, data):
        # 验签函数，sign签名r||s，E消息hash，public_key公钥
        if self.asn1:
            unhex_sign = unhexlify(Sign.encode())
            seq_der = DerSequence()
            origin_sign = seq_der.decode(unhex_sign)
            r = origin_sign[0]
            s = origin_sign[1]
        else:
            r = int(Sign[0:self.para_len], 16)
            s = int(Sign[self.para_len:2*self.para_len], 16)
        e = int(data.hex(), 16)
        t = (r + s) % int(self.ecc_table['n'], base=16)
        if t == 0:
            return 0

        P1 = _kg(s, self.ecc_table['g'])
        P2 = _kg(t, self.public_key)
        # print(P1)
        # print(P2)
        if P1 == P2:
            P1 = '%s%s' % (P1, 1)
            P1 = _double_point(P1)
        else:
            P1 = '%s%s' % (P1, 1)
            P1 = _add_point(P1, P2)
            P1 = _convert_jacb_to_nor(P1)

        x = int(P1[0:self.para_len], 16)
        return r == ((e + x) % int(self.ecc_table['n'], base=16))

    def sign(self, data, K):
        """
        签名函数, data消息的hash，private_key私钥，K随机数，均为16进制字符串
        :param self:
        :param data: data消息的hash
        :param K: K随机数
        :return:
        """
        E = data.hex()  # 消息转化为16进制字符串
        e = int(E, 16)

        d = int(self.private_key, 16)
        k = int(K, 16)

        P1 = _kg(k, self.ecc_table['g'])

        x = int(P1[0:self.para_len], 16)
        R = ((e + x) % int(self.ecc_table['n'], base=16))
        if R == 0 or R + k == int(self.ecc_table['n'], base=16):
            return None
        d_1 = pow(
            d+1, int(self.ecc_table['n'], base=16) - 2, int(self.ecc_table['n'], base=16))
        S = (d_1*(k + R) - R) % int(self.ecc_table['n'], base=16)
        if S == 0:
            return None
        elif self.asn1:
            return DerSequence([DerInteger(R), DerInteger(S)]).encode().hex()
        else:
            return '%064x%064x' % (R, S)

    def encrypt(self, data):
        # 加密函数，data消息(bytes)
        msg = data.hex()  # 消息转化为16进制字符串
        k = random_hex(self.para_len)
        C1 = _kg(int(k, 16), self.ecc_table['g'])
        xy = _kg(int(k, 16), self.public_key)
        x2 = xy[0:self.para_len]
        y2 = xy[self.para_len:2*self.para_len]
        ml = len(msg)
        t = sm3_kdf(xy.encode('utf8'), ml/2)
        if int(t, 16) == 0:
            return None
        else:
            form = '%%0%dx' % ml
            C2 = form % (int(msg, 16) ^ int(t, 16))
            C3 = sm3_hash([
                i for i in bytes.fromhex('%s%s%s' % (x2, msg, y2))
            ])
            if self.mode:
                return bytes.fromhex('%s%s%s' % (C1, C3, C2))
            else:
                return bytes.fromhex('%s%s%s' % (C1, C2, C3))

    def decrypt(self, data):
        # 解密函数，data密文（bytes）
        data = data.hex()
        len_2 = 2 * self.para_len
        len_3 = len_2 + 64
        C1 = data[0:len_2]

        if self.mode:
            C3 = data[len_2:len_3]
            C2 = data[len_3:]
        else:
            C2 = data[len_2:-64]
            C3 = data[-64:]

        xy = _kg(int(self.private_key, 16), C1)
        # print('xy = %s' % xy)
        x2 = xy[0:self.para_len]
        y2 = xy[self.para_len:len_2]
        cl = len(C2)
        t = sm3_kdf(xy.encode('utf8'), cl/2)
        if int(t, 16) == 0:
            return None
        else:
            form = '%%0%dx' % cl
            M = form % (int(C2, 16) ^ int(t, 16))
            u = sm3_hash([
                i for i in bytes.fromhex('%s%s%s' % (x2, M, y2))
            ])
            return bytes.fromhex(M)

    def _sm3_z(self, data):
        """
        SM3WITHSM2 签名规则:  SM2.sign(SM3(Z+MSG)，PrivateKey)
        其中: z = Hash256(Len(ID) + ID + a + b + xG + yG + xA + yA)
        """
        # sm3withsm2 的 z 值
        z = '0080'+'31323334353637383132333435363738' + \
            self.ecc_table['a'] + self.ecc_table['b'] + self.ecc_table['g'] + \
            self.public_key
        z = binascii.a2b_hex(z)
        Za = sm3_hash(bytes_to_list(z))
        M_ = (Za + data.hex()).encode('utf-8')
        e = sm3_hash(bytes_to_list(binascii.a2b_hex(M_)))
        return e

    def sign_with_sm3(self, data, random_hex_str=None):
        sign_data = binascii.a2b_hex(self._sm3_z(data).encode('utf-8'))
        if random_hex_str is None:
            random_hex_str = random_hex(self.para_len)
        sign = self.sign(sign_data, random_hex_str)  # 16进制
        return sign

    def verify_with_sm3(self, sign, data):
        sign_data = binascii.a2b_hex(self._sm3_z(data).encode('utf-8'))
        return self.verify(sign, sign_data)


def _kg(k, Point):  # kP运算
    Point = '%s%s' % (Point, '1')
    mask_str = '8'
    for i in range(len(default_ecc_table['n']) - 1):
        mask_str += '0'
    mask = int(mask_str, 16)
    Temp = Point
    flag = False
    for n in range(len(default_ecc_table['n']) * 4):
        if (flag):
            Temp = _double_point(Temp)
        if (k & mask) != 0:
            if (flag):
                Temp = _add_point(Temp, Point)
            else:
                flag = True
                Temp = Point
        k = k << 1
    return _convert_jacb_to_nor(Temp)


def _double_point(Point):  # 倍点
    l = len(Point)
    len_2 = 2 * len(default_ecc_table['n'])
    if l < len(default_ecc_table['n']) * 2:
        return None
    else:
        x1 = int(Point[0:len(default_ecc_table['n'])], 16)
        y1 = int(Point[len(default_ecc_table['n']):len_2], 16)
        if l == len_2:
            z1 = 1
        else:
            z1 = int(Point[len_2:], 16)
        ecc_a3 = (int(default_ecc_table['a'], base=16) + 3) % int(default_ecc_table['p'], base=16)
        T6 = (z1 * z1) % int(default_ecc_table['p'], base=16)
        T2 = (y1 * y1) % int(default_ecc_table['p'], base=16)
        T3 = (x1 + T6) % int(default_ecc_table['p'], base=16)
        T4 = (x1 - T6) % int(default_ecc_table['p'], base=16)
        T1 = (T3 * T4) % int(default_ecc_table['p'], base=16)
        T3 = (y1 * z1) % int(default_ecc_table['p'], base=16)
        T4 = (T2 * 8) % int(default_ecc_table['p'], base=16)
        T5 = (x1 * T4) % int(default_ecc_table['p'], base=16)
        T1 = (T1 * 3) % int(default_ecc_table['p'], base=16)
        T6 = (T6 * T6) % int(default_ecc_table['p'], base=16)
        T6 = (ecc_a3 * T6) % int(default_ecc_table['p'], base=16)
        T1 = (T1 + T6) % int(default_ecc_table['p'], base=16)
        z3 = (T3 + T3) % int(default_ecc_table['p'], base=16)
        T3 = (T1 * T1) % int(default_ecc_table['p'], base=16)
        T2 = (T2 * T4) % int(default_ecc_table['p'], base=16)
        x3 = (T3 - T5) % int(default_ecc_table['p'], base=16)

        if (T5 % 2) == 1:
            T4 = (T5 + ((T5 + int(default_ecc_table['p'], base=16)) >> 1) - T3) % int(
                default_ecc_table['p'], base=16)
        else:
            T4 = (T5 + (T5 >> 1) - T3) % int(default_ecc_table['p'], base=16)

        T1 = (T1 * T4) % int(default_ecc_table['p'], base=16)
        y3 = (T1 - T2) % int(default_ecc_table['p'], base=16)

        form = '%%0%dx' % len(default_ecc_table['n'])
        form = form * 3
        return form % (x3, y3, z3)


def _add_point(P1, P2):  # 点加函数，P2点为仿射坐标即z=1，P1为Jacobian加重射影坐标
    len_2 = 2 * len(default_ecc_table['n'])
    l1 = len(P1)
    l2 = len(P2)
    if (l1 < len_2) or (l2 < len_2):
        return None
    else:
        X1 = int(P1[0:len(default_ecc_table['n'])], 16)
        Y1 = int(P1[len(default_ecc_table['n']):len_2], 16)
        if (l1 == len_2):
            Z1 = 1
        else:
            Z1 = int(P1[len_2:], 16)
        x2 = int(P2[0:len(default_ecc_table['n'])], 16)
        y2 = int(P2[len(default_ecc_table['n']):len_2], 16)

        T1 = (Z1 * Z1) % int(default_ecc_table['p'], base=16)
        T2 = (y2 * Z1) % int(default_ecc_table['p'], base=16)
        T3 = (x2 * T1) % int(default_ecc_table['p'], base=16)
        T1 = (T1 * T2) % int(default_ecc_table['p'], base=16)
        T2 = (T3 - X1) % int(default_ecc_table['p'], base=16)
        T3 = (T3 + X1) % int(default_ecc_table['p'], base=16)
        T4 = (T2 * T2) % int(default_ecc_table['p'], base=16)
        T1 = (T1 - Y1) % int(default_ecc_table['p'], base=16)
        Z3 = (Z1 * T2) % int(default_ecc_table['p'], base=16)
        T2 = (T2 * T4) % int(default_ecc_table['p'], base=16)
        T3 = (T3 * T4) % int(default_ecc_table['p'], base=16)
        T5 = (T1 * T1) % int(default_ecc_table['p'], base=16)
        T4 = (X1 * T4) % int(default_ecc_table['p'], base=16)
        X3 = (T5 - T3) % int(default_ecc_table['p'], base=16)
        T2 = (Y1 * T2) % int(default_ecc_table['p'], base=16)
        T3 = (T4 - X3) % int(default_ecc_table['p'], base=16)
        T1 = (T1 * T3) % int(default_ecc_table['p'], base=16)
        Y3 = (T1 - T2) % int(default_ecc_table['p'], base=16)

        form = '%%0%dx' % len(default_ecc_table['n'])
        form = form * 3
        return form % (X3, Y3, Z3)


def _convert_jacb_to_nor(Point):  # Jacobian加重射影坐标转换成仿射坐标
    len_2 = 2 * len(default_ecc_table['n'])
    x = int(Point[0:len(default_ecc_table['n'])], 16)
    y = int(Point[len(default_ecc_table['n']):len_2], 16)
    z = int(Point[len_2:], 16)
    z_inv = pow(
        z, int(default_ecc_table['p'], base=16) - 2, int(default_ecc_table['p'], base=16))
    z_invSquar = (z_inv * z_inv) % int(default_ecc_table['p'], base=16)
    z_invQube = (z_invSquar * z_inv) % int(default_ecc_table['p'], base=16)
    x_new = (x * z_invSquar) % int(default_ecc_table['p'], base=16)
    y_new = (y * z_invQube) % int(default_ecc_table['p'], base=16)
    z_new = (z * z_inv) % int(default_ecc_table['p'], base=16)
    if z_new == 1:
        form = '%%0%dx' % len(default_ecc_table['n'])
        form = form * 2
        return form % (x_new, y_new)
    else:
        return None


class PrivateKey:
    def __init__(self, curve=default_ecc_table):
        self.curve = curve
        self.para_len = len(self.curve['n'])
        self.d = random_hex(len(self.curve['n']))

    def publicKey(self):
        len_2 = 2 * self.para_len
        #print(self.curve['g'])
        Px_Py = _kg(int(self.d,16), self.curve['g'])
        # print('Px_Py = %s' % Px_Py)
        Px = Px_Py[0:self.para_len]
        #print(Px)
        Py = Px_Py[self.para_len:len_2]
        return PublicKey(Px, Py, self.curve)

    def toString(self):
        return "{}".format(str(self.d).zfill(64))


class PublicKey:
    def __init__(self, x, y, curve=default_ecc_table):
        self.x = x
        self.y = y
        self.curve = curve

    def toString(self, compressed=True):
        return {
            True: self.x,
            False: "{}{}".format(self.x.zfill(64), self.y.zfill(64))
        }.get(compressed)

def ecdh(private_key, other_public_key, ecc_table=default_ecc_table):
    """
    使用自己的私钥和对方的公钥生成ECDH共享密钥
    :param private_key: 自己的私钥
    :param other_public_key: 对方的公钥
    :param ecc_table: 椭圆曲线参数
    :return: 共享密钥（作为密钥交换的一部分）
    """
    # 私钥和公钥的点乘运算
    px, py = other_public_key[:64], other_public_key[64:128]
    shared_point = _kg(int(private_key, 16), px + py)
    # 仅使用x坐标作为共享密钥
    return shared_point[:64]  # 返回共享点的X坐标

def create_key_pair():
    priKey = PrivateKey()
    pubKey = priKey.publicKey()
    return priKey.toString(), pubKey.toString(compressed=False)


